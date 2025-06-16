use core::fmt::{Debug, Formatter, Result};
use core::mem::MaybeUninit;

use super::flags::{VmcbCleanBits, VmcbIntInfo};
use super::{SvmExitCode, SvmIntercept};

#[repr(C, align(1024))]
pub struct VmcbControlArea {
    pub intercept_cr: u32,
    pub intercept_dr: u32,
    pub intercept_exceptions: u32,
    pub intercept_vector3: u32,
    pub intercept_vector4: u32,
    pub intercept_vector5: u32,
    _reserved1: [u32; 9],
    pub pause_filter_thresh: u16,
    pub pause_filter_count: u16,
    pub iopm_base_pa: u64,
    pub msrpm_base_pa: u64,
    pub tsc_offset: u64,
    pub guest_asid: u32,
    pub tlb_control: u8,
    _reserved2: [u8; 3],
    pub int_control: u32,
    pub int_vector: u32,
    pub int_state: u32,
    _reserved3: [u8; 4],
    pub exit_code: u64,
    pub exit_info_1: u64,
    pub exit_info_2: u64,
    pub exit_int_info: u32,
    pub exit_int_info_err: u32,
    pub np_enable: u8,
    _reserved4: [u8; 3],
    pub avic_vapic_bar: u64,
    _reserved5: [u8; 8],
    pub event_inj: u32,
    pub event_inj_err: u32,
    pub nest_cr3: u64,
    pub lbr_control: u64,
    pub clean_bits: VmcbCleanBits,
    _reserved6: u32,
    pub next_rip: u64,
    pub insn_len: u8,
    pub insn_bytes: [u8; 15],
    pub avic_backing_page: u64,
    _reserved7: [u8; 8],
    pub avic_logical_id: u64,
    pub avic_physical_id: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct VmcbSegment {
    pub selector: u16,
    pub attr: u16,
    pub limit: u32,
    pub base: u64,
}

#[repr(C, align(1024))]
pub struct VmcbStateSaveArea {
    pub es: VmcbSegment,
    pub cs: VmcbSegment,
    pub ss: VmcbSegment,
    pub ds: VmcbSegment,
    pub fs: VmcbSegment,
    pub gs: VmcbSegment,
    pub gdtr: VmcbSegment,
    pub ldtr: VmcbSegment,
    pub idtr: VmcbSegment,
    pub tr: VmcbSegment,
    _reserved1: [u8; 43],
    pub cpl: u8,
    _reserved2: [u8; 4],
    pub efer: u64,
    _reserved3: [u8; 112],
    pub cr4: u64,
    pub cr3: u64,
    pub cr0: u64,
    pub dr7: u64,
    pub dr6: u64,
    pub rflags: u64,
    pub rip: u64,
    _reserved4: [u8; 88],
    pub rsp: u64,
    pub s_cet: u64,
    pub ssp: u64,
    pub isst_addr: u64,
    pub rax: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub sfmask: u64,
    pub kernel_gs_base: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub cr2: u64,
    _reserved5: [u8; 32],
    pub g_pat: u64,
    pub dbgctl: u64,
    pub br_from: u64,
    pub br_to: u64,
    pub last_excp_from: u64,
    pub last_excp_to: u64,
}

#[derive(Debug)]
#[repr(C, align(4096))]
pub struct Vmcb {
    pub control: VmcbControlArea,
    pub save: VmcbStateSaveArea,
}

impl Vmcb {
    pub fn set_intercept(&mut self, which: SvmIntercept) {
        let val = which as u8;
        match val {
            0x60..=0x7F => self.control.intercept_vector3 |= 1 << (val - 0x60),
            0x80..=0x8F => self.control.intercept_vector4 |= 1 << (val - 0x80),
            0xA0..=0xA4 => self.control.intercept_vector5 |= 1 << (val - 0xA0),
            _ => {}
        }
    }

    pub fn inject_event(&mut self, info: VmcbIntInfo, error_code: u32) {
        self.control.event_inj = info.bits();
        self.control.event_inj_err = error_code;
    }
}

#[derive(Debug)]
pub struct VmExitInfo {
    pub exit_code: core::result::Result<SvmExitCode, u64>,
    pub exit_info_1: u64,
    pub exit_info_2: u64,
    pub guest_rip: u64,
    pub guest_next_rip: u64,
}

impl VmExitInfo {
    pub fn new(vmcb: &Vmcb) -> Self {
        Self {
            exit_code: vmcb.control.exit_code.try_into(),
            exit_info_1: vmcb.control.exit_info_1,
            exit_info_2: vmcb.control.exit_info_2,
            guest_rip: vmcb.save.rip,
            guest_next_rip: vmcb.control.next_rip,
        }
    }
}

impl Default for Vmcb {
    fn default() -> Self {
        unsafe { MaybeUninit::zeroed().assume_init() }
    }
}

impl Debug for VmcbControlArea {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("VmcbControlArea")
            .field("intercept_cr", &self.intercept_cr)
            .field("intercept_dr", &self.intercept_dr)
            .field("intercept_exceptions", &self.intercept_exceptions)
            .field("intercept_vector3", &self.intercept_vector3)
            .field("intercept_vector4", &self.intercept_vector4)
            .field("intercept_vector5", &self.intercept_vector5)
            .field("pause_filter_thresh", &self.pause_filter_thresh)
            .field("pause_filter_count", &self.pause_filter_count)
            .field("iopm_base_pa", &self.iopm_base_pa)
            .field("msrpm_base_pa", &self.msrpm_base_pa)
            .field("tsc_offset", &self.tsc_offset)
            .field("guest_asid", &self.guest_asid)
            .field("tlb_control", &self.tlb_control)
            .field("int_control", &self.int_control)
            .field("int_vector", &self.int_vector)
            .field("int_state", &self.int_state)
            .field("exit_code", &self.exit_code)
            .field("exit_info_1", &self.exit_info_1)
            .field("exit_info_2", &self.exit_info_2)
            .field("exit_int_info", &self.exit_int_info)
            .field("exit_int_info_err", &self.exit_int_info_err)
            .field("np_enable", &self.np_enable)
            .field("avic_vapic_bar", &self.avic_vapic_bar)
            .field("event_inj", &self.event_inj)
            .field("event_inj_err", &self.event_inj_err)
            .field("nest_cr3", &self.nest_cr3)
            .field("lbr_control", &self.lbr_control)
            .field("clean_bits", &self.clean_bits)
            .field("next_rip", &self.next_rip)
            .field("insn_len", &self.insn_len)
            .field("insn_bytes", &self.insn_bytes)
            .field("avic_backing_page", &self.avic_backing_page)
            .field("avic_logical_id", &self.avic_logical_id)
            .field("avic_physical_id", &self.avic_physical_id)
            .finish()
    }
}

impl Debug for VmcbStateSaveArea {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.debug_struct("VmcbStateSaveArea")
            .field("es", &self.es)
            .field("cs", &self.cs)
            .field("ss", &self.ss)
            .field("ds", &self.ds)
            .field("fs", &self.fs)
            .field("gs", &self.gs)
            .field("gdtr", &self.gdtr)
            .field("ldtr", &self.ldtr)
            .field("idtr", &self.idtr)
            .field("tr", &self.tr)
            .field("cpl", &self.cpl)
            .field("efer", &self.efer)
            .field("cr4", &self.cr4)
            .field("cr3", &self.cr3)
            .field("cr0", &self.cr0)
            .field("dr7", &self.dr7)
            .field("dr6", &self.dr6)
            .field("rflags", &self.rflags)
            .field("rip", &self.rip)
            .field("rsp", &self.rsp)
            .field("s_cet", &self.s_cet)
            .field("ssp", &self.ssp)
            .field("isst_addr", &self.isst_addr)
            .field("rax", &self.rax)
            .field("star", &self.star)
            .field("lstar", &self.lstar)
            .field("cstar", &self.cstar)
            .field("sfmask", &self.sfmask)
            .field("kernel_gs_base", &self.kernel_gs_base)
            .field("sysenter_cs", &self.sysenter_cs)
            .field("sysenter_esp", &self.sysenter_esp)
            .field("sysenter_eip", &self.sysenter_eip)
            .field("cr2", &self.cr2)
            .field("g_pat", &self.g_pat)
            .field("dbgctl", &self.dbgctl)
            .field("br_from", &self.br_from)
            .field("br_to", &self.br_to)
            .field("last_excp_from", &self.last_excp_from)
            .field("last_excp_to", &self.last_excp_to)
            .finish()
    }
}