// 引入必要的模块
use alloc::collections::VecDeque;
use bit_field::BitField;
use core::fmt::{Debug, Formatter, Result};
use core::{arch::naked_asm, mem::size_of};
use raw_cpuid::CpuId;
use x86::bits64::svm;
use x86::controlregs::{Xcr0, xcr0 as xcr0_read, xcr0_write};
use x86::dtables::{self, DescriptorTablePointer};
use x86::segmentation::SegmentSelector;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr3, Cr4, Cr4Flags, EferFlags};

use axaddrspace::{GuestPhysAddr, GuestVirtAddr, HostPhysAddr, NestedPageFaultInfo};
use axerrno::{AxResult, ax_err, ax_err_type};
use axvcpu::{AccessWidth, AxArchVCpu, AxVCpuExitReason, AxVCpuHal};

// SVM 特定定义
use super::SvmExitReason;
use super::as_axerr;
use super::definitions::SvmExitCode;
use super::structs::{Vmcb,IOPm, MSRPm};
use super::vmcb::{
    self, VmcbControl, VmcbStateSave,
    VmcbCleanBits, VmcbInterruptControls
};
use crate::{ept::GuestPageWalkInfo, msr::Msr, regs::GeneralRegisters};


const QEMU_EXIT_PORT: u16 = 0x604;
const QEMU_EXIT_MAGIC: u64 = 0x2000;
pub struct XState {
    host_xcr0: u64,
    guest_xcr0: u64,
    host_xss: u64,
    guest_xss: u64,

    xsave_available: bool,
    xsaves_available: bool,
}

#[derive(PartialEq, Eq, Debug)]
pub enum VmCpuMode {
    Real,
    Protected,
    Compatibility, // IA-32E mode (CS.L = 0)
    Mode64,        // IA-32E mode (CS.L = 1)
}

impl XState {
    /// Create a new [`XState`] instance with current host state
    fn new() -> Self {
        // Check if XSAVE is available
        let xsave_available = Self::xsave_available();
        // Check if XSAVES and XRSTORS (as well as IA32_XSS) are available
        let xsaves_available = if xsave_available {
            Self::xsaves_available()
        } else {
            false
        };

        // Read XCR0 iff XSAVE is available
        let xcr0 = if xsave_available {
            unsafe { xcr0_read().bits() }
        } else {
            0
        };
        // Read IA32_XSS iff XSAVES is available
        let xss = if xsaves_available {
            Msr::IA32_XSS.read()
        } else {
            0
        };

        Self {
            host_xcr0: xcr0,
            guest_xcr0: xcr0,
            host_xss: xss,
            guest_xss: xss,
            xsave_available,
            xsaves_available,
        }
    }

    /// Enable extended processor state management instructions, including XGETBV and XSAVE.
    pub fn enable_xsave() {
        if Self::xsave_available() {
            unsafe { Cr4::write(Cr4::read() | Cr4Flags::OSXSAVE) };
        }
    }

    /// Check if XSAVE is available on the current CPU.
    pub fn xsave_available() -> bool {
        let cpuid = CpuId::new();
        cpuid
            .get_feature_info()
            .map(|f| f.has_xsave())
            .unwrap_or(false)
    }

    /// Check if XSAVES and XRSTORS (as well as IA32_XSS) are available on the current CPU.
    pub fn xsaves_available() -> bool {
        let cpuid = CpuId::new();
        cpuid
            .get_extended_state_info()
            .map(|f| f.has_xsaves_xrstors())
            .unwrap_or(false)
    }

    /// Save the current host XCR0 and IA32_XSS values and load the guest values.
    pub fn switch_to_guest(&mut self) {
        unsafe {
            if self.xsave_available {
                self.host_xcr0 = xcr0_read().bits();
                xcr0_write(Xcr0::from_bits_unchecked(self.guest_xcr0));

                if self.xsaves_available {
                    self.host_xss = Msr::IA32_XSS.read();
                    Msr::IA32_XSS.write(self.guest_xss);
                }
            }
        }
    }

    /// Save the current guest XCR0 and IA32_XSS values and load the host values.
    pub fn switch_to_host(&mut self) {
        unsafe {
            if self.xsave_available {
                self.guest_xcr0 = xcr0_read().bits();
                xcr0_write(Xcr0::from_bits_unchecked(self.host_xcr0));

                if self.xsaves_available {
                    self.guest_xss = Msr::IA32_XSS.read();
                    Msr::IA32_XSS.write(self.host_xss);
                }
            }
        }
    }
}

pub struct SvmVcpu<H: AxVCpuHal> {
    guest_regs: GeneralRegisters,
    host_stack_top: u64,
    launched: bool,
    vmcb: Vmcb<H>,
    iopm: IOPm<H>,
    msrpm: MSRPm<H>,
    pending_events: VecDeque<(u8, Option<u32>)>,
    xstate: XState,
    entry: Option<GuestPhysAddr>,
    npt_root: Option<HostPhysAddr>,
}
