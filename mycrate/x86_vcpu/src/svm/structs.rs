//! AMD-SVM helper structs
//! https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf

#![allow(dead_code)]
#![allow(clippy::upper_case_acronyms)]

use axaddrspace::HostPhysAddr;
use axerrno::{AxResult, ax_err};
use axvcpu::AxVCpuHal;
use bit_field::BitField;
use memory_addr::PAGE_SIZE_4K as PAGE_SIZE;

use crate::frame::PhysFrame;
use crate::msr::Msr;

/// SVM Host-Save Area (HSAVE)
/// CPU saves a few host registers here on every VM-EXIT.
#[derive(Debug)]
pub struct HSaveArea<H: AxVCpuHal> {
    page: PhysFrame<H>,
}

impl<H: AxVCpuHal> HSaveArea<H> {
    pub const unsafe fn uninit() -> Self {
        Self { page: unsafe { PhysFrame::uninit() } }
    }
    pub fn new() -> AxResult<Self> {
        Ok(Self { page: PhysFrame::alloc_zero()? })
    }

    /// Physical address to be written to MSR_VM_HSAVE_PA
    #[inline(always)]
    pub fn phys_addr(&self) -> HostPhysAddr {
        self.page.start_paddr()
    }
}

/// Virtual-Machine Control Block (VMCB)
/// One 4 KiB page per vCPU: [control-area | save-area].
#[derive(Debug)]
pub struct VmcbFrame<H: AxVCpuHal> {
    page: PhysFrame<H>,
}

impl<H: AxVCpuHal> VmcbFrame<H> {
    pub const unsafe fn uninit() -> Self {
        Self { page: unsafe { PhysFrame::uninit() } }
    }

    /// Allocate a zero-filled VMCB frame.
    pub fn new() -> AxResult<Self> {
        Ok(Self { page: PhysFrame::alloc_zero()? })
    }

    /// Guest-visible physical address (GPPA) for VMRUN.
    #[inline(always)]
    pub fn phys_addr(&self) -> u64 {
        self.page.start_paddr().as_u64()
    }
}

// (AMD64 APM Vol.2, Section 15.10)
// The I/O Permissions Map (IOPM) occupies 12 Kbytes of contiguous physical memory.
// The map is structured as a linear array of 64K+3 bits (two 4-Kbyte pages, and the first three bits of a third 4-Kbyte page) and must be aligned on a 4-Kbyte boundary;
#[derive(Debug)]
pub struct IOPM<H: AxVCpuHal> {
    frame: PhysFrame<H>,              // 8 KiB, but we allocate full 8 KiB page(s)
}

impl<H: AxVCpuHal> IOPM<H> {
    /// All ports **pass-through** (bit = 0).
    pub fn passthrough_all() -> AxResult<Self> {
        Ok(Self { frame: PhysFrame::alloc_zero_size(8192)? })
    }

    /// All ports **intercept** (bit = 1).
    pub fn intercept_all() -> AxResult<Self> {
        let mut frame = PhysFrame::alloc_size(8192)?;
        frame.fill(u8::MAX);
        Ok(Self { frame })
    }

    #[inline(always)]
    pub fn phys_addr(&self) -> u64 {
        self.frame.start_paddr().as_u64()
    }

    /// Change permission of one port (APM §15.24.1).
    /// `intercept = true` ⇒ VMM intercepts.
    pub fn set_port(&mut self, port: u16, intercept: bool) {
        let byte  = (port / 8) as usize;
        let bit   = (port % 8) as u8;
        let map   = unsafe {
            core::slice::from_raw_parts_mut(self.frame.as_mut_ptr(), 8192)
        };
        if intercept {
            map[byte] |= 1 << bit;
        } else {
            map[byte] &= !(1 << bit);
        }
    }
}

/// 15.25  *MSR Permission Map (MSRPM)* – 3 × 2 KiB = 6 KiB
/// Indexing rules: see table 15-37.
#[derive(Debug)]
pub struct MSRPM<H: AxVCpuHal> {
    frame: PhysFrame<H>,              // 6 KiB
}

impl<H: AxVCpuHal> MSRPM<H> {
    pub fn passthrough_all() -> AxResult<Self> {
        Ok(Self { frame: PhysFrame::alloc_zero_size(6144)? })
    }

    pub fn intercept_all() -> AxResult<Self> {
        let mut frame = PhysFrame::alloc_size(6144)?;
        frame.fill(u8::MAX);
        Ok(Self { frame })
    }

    #[inline(always)]
    pub fn phys_addr(&self) -> u64 {
        self.frame.start_paddr().as_u64()
    }

    /// Helper: convert MSR ➜ (byte, bit) inside MSRPM (APM §15.25.1).
    fn msr_slot(msr: u32, write: bool) -> (usize, u8) {
        let (base, idx) = match msr {
            0x0000_0000..=0x0000_1FFF => (0, msr),
            0xC000_0000..=0xC000_1FFF => (2048, msr - 0xC000_0000),
            0xC001_0000..=0xC001_1FFF => (4096, msr - 0xC001_0000),
            _ => panic!("MSR {:#x} not interceptable by MSRPM", msr),
        };
        let bit  = (idx & 0x7) as u8;
        let byte = (idx / 8) as usize + base + if write { 0 } else { 1024 };
        (byte, bit)
    }

    /// `write = false` → read-intercept; `true` → write-intercept.
    pub fn set_msr(&mut self, msr: u32, write: bool, intercept: bool) {
        let (byte, bit) = Self::msr_slot(msr, write);
        let map = unsafe {
            core::slice::from_raw_parts_mut(self.frame.as_mut_ptr(), 6144)
        };
        if intercept {
            map[byte] |= 1 << bit;
        } else {
            map[byte] &= !(1 << bit);
        }
    }
}
