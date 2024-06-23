use core::fmt;

// allowing these deprecated items for the time being, not yet breaking yaxpeax-x86 apis
#[allow(deprecated)]
use yaxpeax_arch::{Colorize, ShowContextual, NoColors, YaxColors};

use crate::MEM_SIZE_STRINGS;
use crate::protected_mode::{RegSpec, Opcode, Operand, MergeMode, InstDecoder, Instruction, Segment, PrefixVex, OperandSpec};

use yaxpeax_arch::display::DisplaySink;
use yaxpeax_arch::safer_unchecked::GetSaferUnchecked as _;

trait DisplaySinkExt {
    // `write_opcode` depends on all mnemonics being less than 32 bytes long. check that here, at
    // compile time. referenced later to force evaluation of this const.
    const MNEMONIC_LT_32: () = {
        let mut i = 0;
        while i < MNEMONICS.len() {
            let name = &MNEMONICS[i];
            if name.len() >= 32 {
                panic!("mnemonic too long");
            }
            i += 1;
        }
    };

    // `write_reg` depends on all register names being less than 8 bytes long. check that here, at
    // compile time. referenced later to force evaluation of this const.
    const REG_LABEL_LT_8: () = {
        let mut i = 0;
        while i < REG_NAMES.len() {
            let name = &REG_NAMES[i];
            if name.len() >= 8 {
                panic!("register name too long");
            }
            i += 1;
        }
    };

    // `write_mem_size_label` depends on all memory size labels being less than 8 bytes long. check
    // that here, at compile time. referenced later to force evaluation of this const.
    const MEM_SIZE_LABEL_LT_8: () = {
        let mut i = 0;
        while i < crate::MEM_SIZE_STRINGS.len() {
            let name = &MEM_SIZE_STRINGS[i];
            if name.len() >= 8 {
                panic!("memory label name too long");
            }
            i += 1;
        }
    };

    // `write_sae_mode` depends on all sae mode labels being less than 16 bytes long. check that
    // here, at compile time. referenced later to force evaluation of this const.
    const SAE_LABEL_LT_16: () = {
        let mut i = 0;
        while i < super::SAE_MODES.len() {
            let mode = &super::SAE_MODES[i];
            if mode.label().len() >= 16 {
                panic!("sae mode label too long");
            }
            i += 1;
        }
    };

    fn write_opcode(&mut self, opcode: super::Opcode) -> Result<(), core::fmt::Error>;
    fn write_reg(&mut self, reg: RegSpec) -> Result<(), core::fmt::Error>;
    fn write_mem_size_label(&mut self, mem_size: u8) -> Result<(), core::fmt::Error>;
    fn write_sae_mode(&mut self, sae: super::SaeMode) -> Result<(), core::fmt::Error>;
}

impl<T: DisplaySink> DisplaySinkExt for T {
    #[inline(always)]
    fn write_opcode(&mut self, opcode: super::Opcode) -> Result<(), core::fmt::Error> {
        let name = opcode.name();

        let _ = Self::MNEMONIC_LT_32;
        // Safety: all opcode mnemonics are 31 bytes or fewer.
        unsafe { self.write_lt_32(name) }
    }

    #[inline(always)]
    fn write_reg(&mut self, reg: RegSpec) -> Result<(), core::fmt::Error> {
        let label = regspec_label(&reg);

        let _ = Self::REG_LABEL_LT_8;
        // Safety: all register labels are 7 bytes or fewer.
        unsafe { self.write_lt_8(label) }
    }

    #[inline(always)]
    fn write_mem_size_label(&mut self, mem_size: u8) -> Result<(), core::fmt::Error> {
        let label = mem_size_label(mem_size);
        let _ = Self::MEM_SIZE_LABEL_LT_8;
        // Safety: all memory size labels are 7 bytes or fewer
        unsafe { self.write_lt_8(label) }
    }

    #[inline(always)]
    fn write_sae_mode(&mut self, sae_mode: super::SaeMode) -> Result<(), core::fmt::Error> {
        let label = sae_mode.label();

        let _ = Self::SAE_LABEL_LT_16;
        // Safety: all sae labels are 15 bytes or fewer.
        unsafe { self.write_lt_16(label) }
    }
}

impl fmt::Display for InstDecoder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self == &InstDecoder::default() {
            return write!(f, "<all features>");
        } else if self == &InstDecoder::minimal() {
            return write!(f, "<no features>");
        }
        if self.sse3() { write!(f, "sse3 ")? }
        if self.ssse3() { write!(f, "ssse3 ")? }
        if self.monitor() { write!(f, "monitor ")? }
        if self.vmx() { write!(f, "vmx ")? }
        if self.fma3() { write!(f, "fma3 ")? }
        if self.cmpxchg16b() { write!(f, "cmpxchg16b ")? }
        if self.sse4_1() { write!(f, "sse4_1 ")? }
        if self.sse4_2() { write!(f, "sse4_2 ")? }
        if self.movbe() { write!(f, "movbe ")? }
        if self.popcnt() { write!(f, "popcnt ")? }
        if self.aesni() { write!(f, "aesni ")? }
        if self.xsave() { write!(f, "xsave ")? }
        if self.rdrand() { write!(f, "rdrand ")? }
        if self.sgx() { write!(f, "sgx ")? }
        if self.bmi1() { write!(f, "bmi1 ")? }
        if self.avx2() { write!(f, "avx2 ")? }
        if self.bmi2() { write!(f, "bmi2 ")? }
        if self.invpcid() { write!(f, "invpcid ")? }
        if self.mpx() { write!(f, "mpx ")? }
        if self.avx512_f() { write!(f, "avx512_f ")? }
        if self.avx512_dq() { write!(f, "avx512_dq ")? }
        if self.rdseed() { write!(f, "rdseed ")? }
        if self.adx() { write!(f, "adx ")? }
        if self.avx512_fma() { write!(f, "avx512_fma ")? }
        if self.pcommit() { write!(f, "pcommit ")? }
        if self.clflushopt() { write!(f, "clflushopt ")? }
        if self.clwb() { write!(f, "clwb ")? }
        if self.avx512_pf() { write!(f, "avx512_pf ")? }
        if self.avx512_er() { write!(f, "avx512_er ")? }
        if self.avx512_cd() { write!(f, "avx512_cd ")? }
        if self.sha() { write!(f, "sha ")? }
        if self.avx512_bw() { write!(f, "avx512_bw ")? }
        if self.avx512_vl() { write!(f, "avx512_vl ")? }
        if self.prefetchwt1() { write!(f, "prefetchwt1 ")? }
        if self.avx512_vbmi() { write!(f, "avx512_vbmi ")? }
        if self.avx512_vbmi2() { write!(f, "avx512_vbmi2 ")? }
        if self.gfni() { write!(f, "gfni ")? }
        if self.vaes() { write!(f, "vaes ")? }
        if self.pclmulqdq() { write!(f, "pclmulqdq ")? }
        if self.avx_vnni() { write!(f, "avx_vnni ")? }
        if self.avx512_bitalg() { write!(f, "avx512_bitalg ")? }
        if self.avx512_vpopcntdq() { write!(f, "avx512_vpopcntdq ")? }
        if self.avx512_4vnniw() { write!(f, "avx512_4vnniw ")? }
        if self.avx512_4fmaps() { write!(f, "avx512_4fmaps ")? }
        if self.cx8() { write!(f, "cx8 ")? }
        if self.syscall() { write!(f, "syscall ")? }
        if self.rdtscp() { write!(f, "rdtscp ")? }
        if self.abm() { write!(f, "abm ")? }
        if self.sse4a() { write!(f, "sse4a ")? }
        if self._3dnowprefetch() { write!(f, "_3dnowprefetch ")? }
        if self.xop() { write!(f, "xop ")? }
        if self.skinit() { write!(f, "skinit ")? }
        if self.tbm() { write!(f, "tbm ")? }
        if self.intel_quirks() { write!(f, "intel_quirks ")? }
        if self.amd_quirks() { write!(f, "amd_quirks ")? }
        if self.avx() { write!(f, "avx ")? }
        Ok(())
    }
}

impl fmt::Display for PrefixVex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.present() {
            write!(f, "vex:{}{}{}{}",
                if self.w() { "w" } else { "-" },
                if self.r() { "r" } else { "-" },
                if self.x() { "x" } else { "-" },
                if self.b() { "b" } else { "-" },
            )
        } else {
            write!(f, "vex:none")
        }
    }
}

impl Segment {
    fn name(&self) -> &'static [u8; 2] {
        match self {
            Segment::CS => b"cs",
            Segment::DS => b"ds",
            Segment::ES => b"es",
            Segment::FS => b"fs",
            Segment::GS => b"gs",
            Segment::SS => b"ss",
        }
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Segment::CS => write!(f, "cs"),
            Segment::DS => write!(f, "ds"),
            Segment::ES => write!(f, "es"),
            Segment::FS => write!(f, "fs"),
            Segment::GS => write!(f, "gs"),
            Segment::SS => write!(f, "ss"),
        }
    }
}

// register names are grouped by indices scaled by 16.
// xmm, ymm, zmm all get two indices.
const REG_NAMES: &[&'static str] = &[
    "BUG", "BUG", "BUG", "BUG", "BUG", "BUG", "BUG", "BUG",
    "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
    "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
    "BUG", "BUG", "BUG", "BUG", "BUG", "BUG", "BUG", "BUG",
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7",
    "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7",
    "es", "cs", "ss", "ds", "fs", "gs", "", "",
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    "xmm16", "xmm17", "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23", "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31",
    "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15",
    "ymm16", "ymm17", "ymm18", "ymm19", "ymm20", "ymm21", "ymm22", "ymm23", "ymm24", "ymm25", "ymm26", "ymm27", "ymm28", "ymm29", "ymm30", "ymm31",
    "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23", "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31",
    "st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)",
    "mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7",
    "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7",
    "eip", "BUG", "BUG", "BUG", "BUG", "BUG", "BUG", "BUG",
    "eflags", "BUG", "BUG", "BUG", "BUG", "BUG", "BUG", "BUG",
];

pub(crate) fn regspec_label(spec: &RegSpec) -> &'static str {
    unsafe { REG_NAMES.get_kinda_unchecked((spec.num as u16 + ((spec.bank as u16) << 3)) as usize) }
}

pub(crate) fn mem_size_label(size: u8) -> &'static str {
    unsafe { MEM_SIZE_STRINGS.get_kinda_unchecked(size as usize) }
}

impl fmt::Display for RegSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(regspec_label(self))
    }
}

impl fmt::Display for Operand {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        // to reuse one implementation, call the deprecated function for now.
        #[allow(deprecated)]
        self.colorize(&NoColors, fmt)
    }
}

// allowing these deprecated items for the time being, not yet breaking yaxpeax-x86 apis
#[allow(deprecated)]
impl <T: fmt::Write, Y: YaxColors> Colorize<T, Y> for Operand {
    fn colorize(&self, _colors: &Y, f: &mut T) -> fmt::Result {
        let mut f = yaxpeax_arch::display::FmtSink::new(f);
        let mut visitor = DisplayingOperandVisitor {
            f: &mut f
        };
        self.visit(&mut visitor)
    }
}

struct DisplayingOperandVisitor<'a, T> {
    f: &'a mut T,
}

impl <T: DisplaySink> super::OperandVisitor for DisplayingOperandVisitor<'_, T> {
    type Ok = ();
    type Error = core::fmt::Error;

    #[cfg_attr(feature="profiling", inline(never))]
    fn visit_u8(&mut self, imm: u8) -> Result<Self::Ok, Self::Error> {
        self.f.span_start_immediate();
        self.f.write_fixed_size("0x")?;
        self.f.write_u8(imm)?;
        self.f.span_end_immediate();
        Ok(())
    }
    #[cfg_attr(feature="profiling", inline(never))]
    fn visit_i8(&mut self, imm: i8) -> Result<Self::Ok, Self::Error> {
        self.f.span_start_immediate();
        let mut v = imm as u8;
        if imm < 0 {
            self.f.write_char('-')?;
            v = imm.unsigned_abs();
        }
        self.f.write_fixed_size("0x")?;
        self.f.write_u8(v)?;
        self.f.span_end_immediate();
        Ok(())
    }
    #[cfg_attr(feature="profiling", inline(never))]
    fn visit_u16(&mut self, imm: u16) -> Result<Self::Ok, Self::Error> {
        self.f.span_start_immediate();
        self.f.write_fixed_size("0x")?;
        self.f.write_u16(imm)?;
        self.f.span_end_immediate();
        Ok(())
    }
    #[cfg_attr(feature="profiling", inline(never))]
    fn visit_i16(&mut self, imm: i16) -> Result<Self::Ok, Self::Error> {
        self.f.span_start_immediate();
        let mut v = imm as u16;
        if imm < 0 {
            self.f.write_char('-')?;
            v = imm.unsigned_abs();
        }
        self.f.write_fixed_size("0x")?;
        self.f.write_u16(v)?;
        self.f.span_end_immediate();
        Ok(())
    }
    #[cfg_attr(feature="profiling", inline(never))]
    fn visit_u32(&mut self, imm: u32) -> Result<Self::Ok, Self::Error> {
        self.f.span_start_immediate();
        self.f.write_fixed_size("0x")?;
        self.f.write_u32(imm)?;
        self.f.span_end_immediate();
        Ok(())
    }
    fn visit_i32(&mut self, imm: i32) -> Result<Self::Ok, Self::Error> {
        self.f.span_start_immediate();
        let mut v = imm as u32;
        if imm < 0 {
            self.f.write_char('-')?;
            v = imm.unsigned_abs();
        }
        self.f.write_fixed_size("0x")?;
        self.f.write_u32(v)?;
        self.f.span_end_immediate();
        Ok(())
    }
    #[cfg_attr(feature="profiling", inline(never))]
    fn visit_reg(&mut self, reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        self.f.span_start_register();
        self.f.write_reg(reg)?;
        self.f.span_end_register();
        Ok(())
    }
    fn visit_reg_mask_merge(&mut self, spec: RegSpec, mask: RegSpec, merge_mode: MergeMode) -> Result<Self::Ok, Self::Error> {
        self.f.span_start_register();
        self.f.write_reg(spec)?;
        self.f.span_end_register();
        if mask.num != 0 {
            self.f.write_fixed_size("{")?;
            self.f.span_start_register();
            self.f.write_reg(mask)?;
            self.f.span_end_register();
            self.f.write_fixed_size("}")?;
        }
        if let MergeMode::Zero = merge_mode {
            self.f.write_fixed_size("{z}")?;
        }
        Ok(())
    }
    fn visit_reg_mask_merge_sae(&mut self, spec: RegSpec, mask: RegSpec, merge_mode: MergeMode, sae_mode: super::SaeMode) -> Result<Self::Ok, Self::Error> {
        self.f.write_reg(spec)?;
        if mask.num != 0 {
            self.f.write_fixed_size("{")?;
            self.f.write_reg(mask)?;
            self.f.write_fixed_size("}")?;
        }
        if let MergeMode::Zero = merge_mode {
            self.f.write_fixed_size("{z}")?;
        }
        self.f.write_sae_mode(sae_mode)?;
        Ok(())
    }
    fn visit_reg_mask_merge_sae_noround(&mut self, spec: RegSpec, mask: RegSpec, merge_mode: MergeMode) -> Result<Self::Ok, Self::Error> {
        self.f.write_reg(spec)?;
        if mask.num != 0 {
            self.f.write_fixed_size("{")?;
            self.f.write_reg(mask)?;
            self.f.write_fixed_size("}")?;
        }
        if let MergeMode::Zero = merge_mode {
            self.f.write_fixed_size("{z}")?;
        }
        self.f.write_fixed_size("{sae}")?;
        Ok(())
    }
    fn visit_abs_u16(&mut self, imm: u16) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_fixed_size("0x")?;
        self.f.write_u16(imm)?;
        self.f.write_fixed_size("]")?;
        Ok(())
    }
    fn visit_abs_u32(&mut self, imm: u32) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_fixed_size("0x")?;
        self.f.write_u32(imm)?;
        self.f.write_fixed_size("]")?;
        Ok(())
    }
    #[cfg_attr(not(feature="profiling"), inline(always))]
    #[cfg_attr(feature="profiling", inline(never))]
    fn visit_disp(&mut self, reg: RegSpec, disp: i32) -> Result<Self::Ok, Self::Error> {
        self.f.write_char('[')?;
        self.f.write_reg(reg)?;
        self.f.write_fixed_size(" ")?;

        {
            let mut v = disp as u32;
            if disp < 0 {
                self.f.write_fixed_size("- 0x")?;
                v = disp.unsigned_abs();
            } else {
                self.f.write_fixed_size("+ 0x")?;
            }
            self.f.write_u32(v)?;
        }
        self.f.write_fixed_size("]")
    }
    fn visit_deref(&mut self, reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_reg(reg)?;
        self.f.write_fixed_size("]")
    }
    fn visit_reg_scale(&mut self, reg: RegSpec, scale: u8) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_reg(reg)?;
        self.f.write_fixed_size(" * ")?;
        self.f.write_char((0x30 + scale) as char)?; // translate scale=1 to '1', scale=2 to '2', etc
        self.f.write_fixed_size("]")?;

        Ok(())
    }
    fn visit_reg_scale_disp(&mut self, reg: RegSpec, scale: u8, disp: i32) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_reg(reg)?;
        self.f.write_fixed_size(" * ")?;
        self.f.write_char((0x30 + scale) as char)?; // translate scale=1 to '1', scale=2 to '2', etc
        self.f.write_fixed_size(" ")?;

        {
            let mut v = disp as u32;
            if disp < 0 {
                self.f.write_fixed_size("- 0x")?;
                v = disp.unsigned_abs();
            } else {
                self.f.write_fixed_size("+ 0x")?;
            }
            self.f.write_u32(v)?;
        }
        self.f.write_char(']')
    }
    fn visit_index_base_scale(&mut self, base: RegSpec, index: RegSpec, scale: u8) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_reg(base)?;
        self.f.write_fixed_size(" + ")?;
        self.f.write_reg(index)?;
        self.f.write_fixed_size(" * ")?;
        self.f.write_char((0x30 + scale) as char)?; // translate scale=1 to '1', scale=2 to '2', etc
        self.f.write_fixed_size("]")
    }
    fn visit_index_base_scale_disp(&mut self, base: RegSpec, index: RegSpec, scale: u8, disp: i32) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_reg(base)?;
        self.f.write_fixed_size(" + ")?;
        self.f.write_reg(index)?;
        self.f.write_fixed_size(" * ")?;
        self.f.write_char((0x30 + scale) as char)?; // translate scale=1 to '1', scale=2 to '2', etc
        self.f.write_fixed_size(" ")?;

        {
            let mut v = disp as u32;
            if disp < 0 {
                self.f.write_fixed_size("- 0x")?;
                v = disp.unsigned_abs();
            } else {
                self.f.write_fixed_size("+ 0x")?;
            }
            self.f.write_u32(v)?;
        }
        self.f.write_fixed_size("]")
    }
    fn visit_reg_disp_masked(&mut self, spec: RegSpec, disp: i32, mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        self.f.write_char('[')?;
        self.f.write_reg(spec)?;
        self.f.write_char(' ')?;
        let mut v = disp as u32;
        if disp < 0 {
            self.f.write_fixed_size("- 0x")?;
            v = disp.unsigned_abs();
        } else {
            self.f.write_fixed_size("+ 0x")?;
        }
        self.f.write_u32(v)?;
        self.f.write_char(']')?;
        self.f.write_char('{')?;
        self.f.write_reg(mask_reg)?;
        self.f.write_char('}')?;
        Ok(())
    }
    fn visit_reg_deref_masked(&mut self, spec: RegSpec, mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_reg(spec)?;
        self.f.write_fixed_size("]")?;
        self.f.write_char('{')?;
        self.f.write_reg(mask_reg)?;
        self.f.write_char('}')?;
        Ok(())
    }
    fn visit_reg_scale_masked(&mut self, spec: RegSpec, scale: u8, mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_reg(spec)?;
        self.f.write_fixed_size(" * ")?;
        self.f.write_char((0x30 + scale) as char)?; // translate scale=1 to '1', scale=2 to '2', etc
        self.f.write_fixed_size("]")?;
        self.f.write_char('{')?;
        self.f.write_reg(mask_reg)?;
        self.f.write_char('}')?;
        Ok(())
    }
    fn visit_reg_scale_disp_masked(&mut self, spec: RegSpec, scale: u8, disp: i32, mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_reg(spec)?;
        self.f.write_fixed_size(" * ")?;
        self.f.write_char((0x30 + scale) as char)?; // translate scale=1 to '1', scale=2 to '2', etc
        self.f.write_fixed_size(" ")?;
        let mut v = disp as u32;
        if disp < 0 {
            self.f.write_fixed_size("- 0x")?;
            v = disp.unsigned_abs();
        } else {
            self.f.write_fixed_size("+ 0x")?;
        }
        self.f.write_u32(v)?;
        self.f.write_char(']')?;
        self.f.write_char('{')?;
        self.f.write_reg(mask_reg)?;
        self.f.write_char('}')?;
        Ok(())
    }
    fn visit_index_base_masked(&mut self, base: RegSpec, index: RegSpec, mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_reg(base)?;
        self.f.write_fixed_size(" + ")?;
        self.f.write_reg(index)?;
        self.f.write_fixed_size("]")?;
        self.f.write_char('{')?;
        self.f.write_reg(mask_reg)?;
        self.f.write_char('}')?;
        Ok(())
    }
    fn visit_index_base_disp_masked(&mut self, base: RegSpec, index: RegSpec, disp: i32, mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_reg(base)?;
        self.f.write_fixed_size(" + ")?;
        self.f.write_reg(index)?;
        self.f.write_fixed_size(" ")?;
        let mut v = disp as u32;
        if disp < 0 {
            self.f.write_fixed_size("- 0x")?;
            v = disp.unsigned_abs();
        } else {
            self.f.write_fixed_size("+ 0x")?;
        }
        self.f.write_u32(v)?;
        self.f.write_char(']')?;
        self.f.write_char('{')?;
        self.f.write_reg(mask_reg)?;
        self.f.write_char('}')?;
        Ok(())
    }
    fn visit_index_base_scale_masked(&mut self, base: RegSpec, index: RegSpec, scale: u8, mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_reg(base)?;
        self.f.write_fixed_size(" + ")?;
        self.f.write_reg(index)?;
        self.f.write_fixed_size(" * ")?;
        self.f.write_char((0x30 + scale) as char)?; // translate scale=1 to '1', scale=2 to '2', etc
        self.f.write_fixed_size("]")?;
        self.f.write_char('{')?;
        self.f.write_reg(mask_reg)?;
        self.f.write_char('}')?;
        Ok(())
    }
    fn visit_index_base_scale_disp_masked(&mut self, base: RegSpec, index: RegSpec, scale: u8, disp: i32, mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        self.f.write_fixed_size("[")?;
        self.f.write_reg(base)?;
        self.f.write_fixed_size(" + ")?;
        self.f.write_reg(index)?;
        self.f.write_fixed_size(" * ")?;
        self.f.write_char((0x30 + scale) as char)?; // translate scale=1 to '1', scale=2 to '2', etc
        self.f.write_char(' ')?;
        let mut v = disp as u32;
        if disp < 0 {
            self.f.write_fixed_size("- 0x")?;
            v = disp.unsigned_abs();
        } else {
            self.f.write_fixed_size("+ 0x")?;
        }
        self.f.write_u32(v)?;
        self.f.write_char(']')?;
        self.f.write_char('{')?;
        self.f.write_reg(mask_reg)?;
        self.f.write_char('}')?;
        Ok(())
    }
    fn visit_absolute_far_address(&mut self, segment: u16, address: u32) -> Result<Self::Ok, Self::Error> {
        self.f.write_prefixed_u16(segment)?;
        self.f.write_fixed_size(":")?;
        self.f.write_prefixed_u32(address)?;
        Ok(())
    }


    fn visit_other(&mut self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name())
    }
}

const MNEMONICS: &[&'static str] = &[
    "add",
    "or",
    "adc",
    "sbb",
    "and",
    "sub",
    "xor",
    "cmp",
    "rol",
    "ror",
    "rcl",
    "rcr",
    "shl",
    "shr",
    "sal",
    "sar",
    "btc",
    "btr",
    "bts",
    "cmpxchg",
    "cmpxchg8b",
    "cmpxchg16b",
    "dec",
    "inc",
    "neg",
    "not",
    "xadd",
    "xchg",
    "cmps",
    "scas",
    "movs",
    "lods",
    "stos",
    "ins",
    "outs",
    "invalid",
    "bt",
    "bsf",
    "bsr",
    "tzcnt",
    "movss",
    "addss",
    "subss",
    "mulss",
    "divss",
    "minss",
    "maxss",
    "sqrtss",
    "movsd",
    "sqrtsd",
    "addsd",
    "subsd",
    "mulsd",
    "divsd",
    "minsd",
    "maxsd",
    "movsldup",
    "movshdup",
    "movddup",
    "haddps",
    "hsubps",
    "addsubpd",
    "addsubps",
    "cvtsi2ss",
    "cvtsi2sd",
    "cvttsd2si",
    "cvttps2dq",
    "cvtpd2dq",
    "cvtpd2ps",
    "cvtps2dq",
    "cvtsd2si",
    "cvtsd2ss",
    "cvttss2si",
    "cvtss2si",
    "cvtss2sd",
    "cvtdq2pd",
    "lddqu",
    "movzx",
    "movsx",
    "movsxd",
    "shrd",
//  " inc",
//  " dec",
    "hlt",
    "call",
    "callf",
    "jmp",
    "jmpf",
    "push",
    "pop",
    "lea",
    "nop",
    "prefetchnta",
    "prefetch0",
    "prefetch1",
    "prefetch2",
//  " xchg",
    "popf",
    "int",
    "into",
    "iret",
    "iretd",
    "iretq",
    "retf",
    "enter",
    "leave",
    "mov",
    "ret",
    "pushf",
    "wait",
    "cbw",
    "cwde",
    "cdqe",
    "cwd",
    "cdq",
    "cqo",
    "lahf",
    "sahf",
    "test",
    "in",
    "out",
    "imul",
    "jo",
    "jno",
    "jb",
    "jnb",
    "jz",
    "jnz",
    "ja",
    "jna",
    "js",
    "jns",
    "jp",
    "jnp",
    "jl",
    "jge",
    "jle",
    "jg",
    "cmova",
    "cmovb",
    "cmovg",
    "cmovge",
    "cmovl",
    "cmovle",
    "cmovna",
    "cmovnb",
    "cmovno",
    "cmovnp",
    "cmovns",
    "cmovnz",
    "cmovo",
    "cmovp",
    "cmovs",
    "cmovz",
    "div",
    "idiv",
    "mul",
//  " neg",
//  " not",
//  " cmpxchg",
    "seto",
    "setno",
    "setb",
    "setae",
    "setz",
    "setnz",
    "setbe",
    "seta",
    "sets",
    "setns",
    "setp",
    "setnp",
    "setl",
    "setge",
    "setle",
    "setg",
    "cpuid",
    "ud0",
    "ud1",
    "ud2",
    "wbinvd",
    "invd",
    "sysret",
    "clts",
    "syscall",
    "lsl",
    "lar",
    "les",
    "lds",
    "sgdt",
    "sidt",
    "lgdt",
    "lidt",
    "smsw",
    "lmsw",
    "swapgs",
    "rdtscp",
    "invlpg",
    "fxsave",
    "fxrstor",
    "ldmxcsr",
    "stmxcsr",
    "xsave",
    "xrstor",
    "xsaveopt",
    "lfence",
    "mfence",
    "sfence",
    "clflush",
    "clflushopt",
    "clwb",
    "wrmsr",
    "rdtsc",
    "rdmsr",
    "rdpmc",
    "sldt",
    "str",
    "lldt",
    "ltr",
    "verr",
    "verw",
    "cmc",
    "clc",
    "stc",
    "cli",
    "sti",
    "cld",
    "std",
    "jmpe",
    "popcnt",
    "movdqu",
    "movdqa",
    "movq",
    "cmpss",
    "cmpsd",
    "unpcklps",
    "unpcklpd",
    "unpckhps",
    "unpckhpd",
    "pshufhw",
    "pshuflw",
    "movups",
    "movq2dq",
    "movdq2q",
    "rsqrtss",
    "rcpss",

   "andn",
    "bextr",
    "blsi",
    "blsmsk",
    "blsr",
    "vmclear",
    "vmxon",
    "vmcall",
    "vmlaunch",
    "vmresume",
    "vmxoff",
    "pconfig",
    "monitor",
    "mwait",
    "monitorx",
    "mwaitx",
    "clac",
    "stac",
    "encls",
    "enclv",
    "xgetbv",
    "xsetbv",
    "vmfunc",
    "xabort",
    "xbegin",
    "xend",
    "xtest",
    "enclu",
    "rdpkru",
    "wrpkru",

   "rdpru",
    "clzero",

   "rdseed",
    "rdrand",

   "addps",
    "addpd",
    "andnps",
    "andnpd",
    "andps",
    "andpd",
    "bswap",
    "cmppd",
    "cmpps",
    "comisd",
    "comiss",
    "cvtdq2ps",
    "cvtpi2ps",
    "cvtpi2pd",
    "cvtps2pd",
    "cvtps2pi",
    "cvtpd2pi",
    "cvttps2pi",
    "cvttpd2pi",
    "cvttpd2dq",
    "divps",
    "divpd",
    "emms",
    "getsec",
    "lfs",
    "lgs",
    "lss",
    "maskmovq",
    "maskmovdqu",
    "maxps",
    "maxpd",
    "minps",
    "minpd",
    "movaps",
    "movapd",
    "movd",
    "movlps",
    "movlpd",
    "movhps",
    "movhpd",
    "movlhps",
    "movhlps",
    "movupd",
    "movmskps",
    "movmskpd",
    "movnti",
    "movntps",
    "movntpd",
    "extrq",
    "insertq",
    "movntss",
    "movntsd",
    "movntq",
    "movntdq",
    "mulps",
    "mulpd",
    "orps",
    "orpd",
    "packssdw",
    "packsswb",
    "packuswb",
    "paddb",
    "paddd",
    "paddq",
    "paddsb",
    "paddsw",
    "paddusb",
    "paddusw",
    "paddw",
    "pand",
    "pandn",
    "pavgb",
    "pavgw",
    "pcmpeqb",
    "pcmpeqd",
    "pcmpeqw",
    "pcmpgtb",
    "pcmpgtd",
    "pcmpgtw",
    "pinsrw",
    "pmaddwd",
    "pmaxsw",
    "pmaxub",
    "pminsw",
    "pminub",
    "pmovmskb",
    "pmulhuw",
    "pmulhw",
    "pmullw",
    "pmuludq",
    "por",
    "psadbw",
    "pshufw",
    "pshufd",
    "pslld",
    "pslldq",
    "psllq",
    "psllw",
    "psrad",
    "psraw",
    "psrld",
    "psrldq",
    "psrlq",
    "psrlw",
    "psubb",
    "psubd",
    "psubq",
    "psubsb",
    "psubsw",
    "psubusb",
    "psubusw",
    "psubw",
    "punpckhbw",
    "punpckhdq",
    "punpckhwd",
    "punpcklbw",
    "punpckldq",
    "punpcklwd",
    "punpcklqdq",
    "punpckhqdq",
    "pxor",
    "rcpps",
    "rsm",
    "rsqrtps",
    "shld",
    "shufpd",
    "shufps",
    "slhd",
    "sqrtps",
    "sqrtpd",
    "subps",
    "subpd",
    "sysenter",
    "sysexit",
    "ucomisd",
    "ucomiss",
    "vmread",
    "vmwrite",
    "xorps",
    "xorpd",

    "vmovddup",
    "vpshuflw",
    "vpshufhw",
    "vhaddps",
    "vhsubps",
    "vaddsubps",
    "vcvtpd2dq",
    "vlddqu",

    "vcomisd",
    "vcomiss",
    "vucomisd",
    "vucomiss",
    "vaddpd",
    "vaddps",
    "vaddsd",
    "vaddss",
    "vaddsubpd",
    "vaesdec",
    "vaesdeclast",
    "vaesenc",
    "vaesenclast",
    "vaesimc",
    "vaeskeygenassist",
    "vblendpd",
    "vblendps",
    "vblendvpd",
    "vblendvps",
    "vbroadcastf128",
    "vbroadcasti128",
    "vbroadcastsd",
    "vbroadcastss",
    "vcmpsd",
    "vcmpss",
    "vcmppd",
    "vcmpps",
    "vcvtdq2pd",
    "vcvtdq2ps",
    "vcvtpd2ps",
    "vcvtph2ps",
    "vcvtps2dq",
    "vcvtps2pd",
    "vcvtss2sd",
    "vcvtsi2ss",
    "vcvtsi2sd",
    "vcvtsd2si",
    "vcvtsd2ss",
    "vcvtps2ph",
    "vcvtss2si",
    "vcvttpd2dq",
    "vcvttps2dq",
    "vcvttss2si",
    "vcvttsd2si",
    "vdivpd",
    "vdivps",
    "vdivsd",
    "vdivss",
    "vdppd",
    "vdpps",
    "vextractf128",
    "vextracti128",
    "vextractps",
    "vfmadd132pd",
    "vfmadd132ps",
    "vfmadd132sd",
    "vfmadd132ss",
    "vfmadd213pd",
    "vfmadd213ps",
    "vfmadd213sd",
    "vfmadd213ss",
    "vfmadd231pd",
    "vfmadd231ps",
    "vfmadd231sd",
    "vfmadd231ss",
    "vfmaddsub132pd",
    "vfmaddsub132ps",
    "vfmaddsub213pd",
    "vfmaddsub213ps",
    "vfmaddsub231pd",
    "vfmaddsub231ps",
    "vfmsub132pd",
    "vfmsub132ps",
    "vfmsub132sd",
    "vfmsub132ss",
    "vfmsub213pd",
    "vfmsub213ps",
    "vfmsub213sd",
    "vfmsub213ss",
    "vfmsub231pd",
    "vfmsub231ps",
    "vfmsub231sd",
    "vfmsub231ss",
    "vfmsubadd132pd",
    "vfmsubadd132ps",
    "vfmsubadd213pd",
    "vfmsubadd213ps",
    "vfmsubadd231pd",
    "vfmsubadd231ps",
    "vfnmadd132pd",
    "vfnmadd132ps",
    "vfnmadd132sd",
    "vfnmadd132ss",
    "vfnmadd213pd",
    "vfnmadd213ps",
    "vfnmadd213sd",
    "vfnmadd213ss",
    "vfnmadd231pd",
    "vfnmadd231ps",
    "vfnmadd231sd",
    "vfnmadd231ss",
    "vfnmsub132pd",
    "vfnmsub132ps",
    "vfnmsub132sd",
    "vfnmsub132ss",
    "vfnmsub213pd",
    "vfnmsub213ps",
    "vfnmsub213sd",
    "vfnmsub213ss",
    "vfnmsub231pd",
    "vfnmsub231ps",
    "vfnmsub231sd",
    "vfnmsub231ss",
    "vgatherdpd",
    "vgatherdps",
    "vgatherqpd",
    "vgatherqps",
    "vhaddpd",
    "vhsubpd",
    "vinsertf128",
    "vinserti128",
    "vinsertps",
    "vmaskmovdqu",
    "vmaskmovpd",
    "vmaskmovps",
    "vmaxpd",
    "vmaxps",
    "vmaxsd",
    "vmaxss",
    "vminpd",
    "vminps",
    "vminsd",
    "vminss",
    "vmovapd",
    "vmovaps",
    "vmovd",
    "vmovdqa",
    "vmovdqu",
    "vmovhlps",
    "vmovhpd",
    "vmovhps",
    "vmovlhps",
    "vmovlpd",
    "vmovlps",
    "vmovmskpd",
    "vmovmskps",
    "vmovntdq",
    "vmovntdqa",
    "vmovntpd",
    "vmovntps",
    "vmovq",
    "vmovss",
    "vmovsd",
    "vmovshdup",
    "vmovsldup",
    "vmovupd",
    "vmovups",
    "vmpsadbw",
    "vmulpd",
    "vmulps",
    "vmulsd",
    "vmulss",
    "vpabsb",
    "vpabsd",
    "vpabsw",
    "vpackssdw",
    "vpackusdw",
    "vpacksswb",
    "vpackuswb",
    "vpaddb",
    "vpaddd",
    "vpaddq",
    "vpaddsb",
    "vpaddsw",
    "vpaddusb",
    "vpaddusw",
    "vpaddw",
    "vpalignr",
    "vandpd",
    "vandps",
    "vorpd",
    "vorps",
    "vandnpd",
    "vandnps",
    "vpand",
    "vpandn",
    "vpavgb",
    "vpavgw",
    "vpblendd",
    "vpblendvb",
    "vpblendw",
    "vpbroadcastb",
    "vpbroadcastd",
    "vpbroadcastq",
    "vpbroadcastw",
    "vpclmulqdq",
    "vpcmpeqb",
    "vpcmpeqd",
    "vpcmpeqq",
    "vpcmpeqw",
    "vpcmpgtb",
    "vpcmpgtd",
    "vpcmpgtq",
    "vpcmpgtw",
    "vpcmpestri",
    "vpcmpestrm",
    "vpcmpistri",
    "vpcmpistrm",
    "vperm2f128",
    "vperm2i128",
    "vpermd",
    "vpermilpd",
    "vpermilps",
    "vpermpd",
    "vpermps",
    "vpermq",
    "vpextrb",
    "vpextrd",
    "vpextrq",
    "vpextrw",
    "vpgatherdd",
    "vpgatherdq",
    "vpgatherqd",
    "vpgatherqq",
    "vphaddd",
    "vphaddsw",
    "vphaddw",
    "vpmaddubsw",
    "vphminposuw",
    "vphsubd",
    "vphsubsw",
    "vphsubw",
    "vpinsrb",
    "vpinsrd",
    "vpinsrq",
    "vpinsrw",
    "vpmaddwd",
    "vpmaskmovd",
    "vpmaskmovq",
    "vpmaxsb",
    "vpmaxsd",
    "vpmaxsw",
    "vpmaxub",
    "vpmaxuw",
    "vpmaxud",
    "vpminsb",
    "vpminsw",
    "vpminsd",
    "vpminub",
    "vpminuw",
    "vpminud",
    "vpmovmskb",
    "vpmovsxbd",
    "vpmovsxbq",
    "vpmovsxbw",
    "vpmovsxdq",
    "vpmovsxwd",
    "vpmovsxwq",
    "vpmovzxbd",
    "vpmovzxbq",
    "vpmovzxbw",
    "vpmovzxdq",
    "vpmovzxwd",
    "vpmovzxwq",
    "vpmuldq",
    "vpmulhrsw",
    "vpmulhuw",
    "vpmulhw",
    "vpmullq",
    "vpmulld",
    "vpmullw",
    "vpmuludq",
    "vpor",
    "vpsadbw",
    "vpshufb",
    "vpshufd",
    "vpsignb",
    "vpsignd",
    "vpsignw",
    "vpslld",
    "vpslldq",
    "vpsllq",
    "vpsllvd",
    "vpsllvq",
    "vpsllw",
    "vpsrad",
    "vpsravd",
    "vpsraw",
    "vpsrld",
    "vpsrldq",
    "vpsrlq",
    "vpsrlvd",
    "vpsrlvq",
    "vpsrlw",
    "vpsubb",
    "vpsubd",
    "vpsubq",
    "vpsubsb",
    "vpsubsw",
    "vpsubusb",
    "vpsubusw",
    "vpsubw",
    "vptest",
    "vpunpckhbw",
    "vpunpckhdq",
    "vpunpckhqdq",
    "vpunpckhwd",
    "vpunpcklbw",
    "vpunpckldq",
    "vpunpcklqdq",
    "vpunpcklwd",
    "vpxor",
    "vrcpps",
    "vroundpd",
    "vroundps",
    "vroundsd",
    "vroundss",
    "vrsqrtps",
    "vrsqrtss",
    "vrcpss",
    "vshufpd",
    "vshufps",
    "vsqrtpd",
    "vsqrtps",
    "vsqrtss",
    "vsqrtsd",
    "vsubpd",
    "vsubps",
    "vsubsd",
    "vsubss",
    "vtestpd",
    "vtestps",
    "vunpckhpd",
    "vunpckhps",
    "vunpcklpd",
    "vunpcklps",
    "vxorpd",
    "vxorps",
    "vzeroupper",
    "vzeroall",
    "vldmxcsr",
    "vstmxcsr",

    "pclmulqdq",
    "aeskeygenassist",
    "aesimc",
    "aesenc",
    "aesenclast",
    "aesdec",
    "aesdeclast",
    "pcmpgtq",
    "pcmpistrm",
    "pcmpistri",
    "pcmpestri",
    "packusdw",
    "pcmpestrm",
    "pcmpeqq",
    "ptest",
    "phminposuw",
    "dpps",
    "dppd",
    "mpsadbw",
    "pmovzxdq",
    "pmovsxdq",
    "pmovzxbd",
    "pmovsxbd",
    "pmovzxwq",
    "pmovsxwq",
    "pmovzxbq",
    "pmovsxbq",
    "pmovsxwd",
    "pmovzxwd",
    "pextrq",
    "pextrd",
    "pextrw",
    "pextrb",
    "pmovsxbw",
    "pmovzxbw",
    "pinsrq",
    "pinsrd",
    "pinsrb",
    "extractps",
    "insertps",
    "roundss",
    "roundsd",
    "roundps",
    "roundpd",
    "pmaxsb",
    "pmaxsd",
    "pmaxuw",
    "pmaxud",
    "pminsd",
    "pminsb",
    "pminud",
    "pminuw",
    "blendw",
    "pblendvb",
    "pblendw",
    "blendvps",
    "blendvpd",
    "blendps",
    "blendpd",
    "pmuldq",
    "movntdqa",
    "pmulld",
    "palignr",
    "psignw",
    "psignd",
    "psignb",
    "pshufb",
    "pmulhrsw",
    "pmaddubsw",
    "pabsd",
    "pabsw",
    "pabsb",
    "phsubsw",
    "phsubw",
    "phsubd",
    "phaddd",
    "phaddsw",
    "phaddw",
    "hsubpd",
    "haddpd",

    "sha1rnds4",
    "sha1nexte",
    "sha1msg1",
    "sha1msg2",
    "sha256rnds2",
    "sha256msg1",
    "sha256msg2",

    "lzcnt",
    "clgi",
    "stgi",
    "skinit",
    "vmload",
    "vmmcall",
    "vmsave",
    "vmrun",
    "invlpga",
    "invlpgb",
    "tlbsync",

    "movbe",

    "adcx",
    "adox",

    "prefetchw",

    "rdpid",
//  " cmpxchg8b",
//  " cmpxchg16b",
    "vmptrld",
    "vmptrst",

    "bzhi",
    "mulx",
    "shlx",
    "shrx",
    "sarx",
    "pdep",
    "pext",
    "rorx",
    "xrstors",
    "xrstors64",
    "xsavec",
    "xsavec64",
    "xsaves",
    "xsaves64",

    "rdfsbase",
    "rdgsbase",
    "wrfsbase",
    "wrgsbase",

    "crc32",
    "salc",
    "xlat",

    "f2xm1",
    "fabs",
    "fadd",
    "faddp",
    "fbld",
    "fbstp",
    "fchs",
    "fcmovb",
    "fcmovbe",
    "fcmove",
    "fcmovnb",
    "fcmovnbe",
    "fcmovne",
    "fcmovnu",
    "fcmovu",
    "fcom",
    "fcomi",
    "fcomip",
    "fcomp",
    "fcompp",
    "fcos",
    "fdecstp",
    "fdisi8087_nop",
    "fdiv",
    "fdivp",
    "fdivr",
    "fdivrp",
    "feni8087_nop",
    "ffree",
    "ffreep",
    "fiadd",
    "ficom",
    "ficomp",
    "fidiv",
    "fidivr",
    "fild",
    "fimul",
    "fincstp",
    "fist",
    "fistp",
    "fisttp",
    "fisub",
    "fisubr",
    "fld",
    "fld1",
    "fldcw",
    "fldenv",
    "fldl2e",
    "fldl2t",
    "fldlg2",
    "fldln2",
    "fldpi",
    "fldz",
    "fmul",
    "fmulp",
    "fnclex",
    "fninit",
    "fnop",
    "fnsave",
    "fnstcw",
    "fnstenv",
    "fnstor",
    "fnstsw",
    "fpatan",
    "fprem",
    "fprem1",
    "fptan",
    "frndint",
    "frstor",
    "fscale",
    "fsetpm287_nop",
    "fsin",
    "fsincos",
    "fsqrt",
    "fst",
    "fstp",
    "fstpnce",
    "fsub",
    "fsubp",
    "fsubr",
    "fsubrp",
    "ftst",
    "fucom",
    "fucomi",
    "fucomip",
    "fucomp",
    "fucompp",
    "fxam",
    "fxch",
    "fxtract",
    "fyl2x",
    "fyl2xp1",

    "loopnz",
    "loopz",
    "loop",
    "jecxz",

    "pusha",
    "popa",
    "bound",
    "arpl",
    "aas",
    "aaa",
    "das",
    "daa",
    "aam",
    "aad",

    // started shipping in tremont, 2020 sept 23
    "movdir64b",
    "movdiri",

    // started shipping in tiger lake, 2020 sept 2
    "aesdec128kl",
    "aesdec256kl",
    "aesdecwide128kl",
    "aesdecwide256kl",
    "aesenc128kl",
    "aesenc256kl",
    "aesencwide128kl",
    "aesencwide256kl",
    "encodekey128",
    "encodekey256",
    "loadiwkey",

    // unsure
    "hreset",

    // 3dnow
    "femms",
    "pi2fw",
    "pi2fd",
    "pf2iw",
    "pf2id",
    "pmulhrw",
    "pfcmpge",
    "pfmin",
    "pfrcp",
    "pfrsqrt",
    "pfsub",
    "pfadd",
    "pfcmpgt",
    "pfmax",
    "pfrcpit1",
    "pfrsqit1",
    "pfsubr",
    "pfacc",
    "pfcmpeq",
    "pfmul",
    "pfmulhrw",
    "pfrcpit2",
    "pfnacc",
    "pfpnacc",
    "pswapd",
    "pavgusb",

    // enqcmd
    "enqcmd",
    "enqcmds",

    // invpcid
    "invept",
    "invvpid",
    "invpcid",

    // ptwrite
    "ptwrite",

    // gfni
    "gf2p8affineqb",
    "gf2p8affineinvqb",
    "gf2p8mulb",

    // cet
    "wruss",
    "wrss",
    "incssp",
    "saveprevssp",
    "setssbsy",
    "clrssbsy",
    "rstorssp",
    "endbr64",
    "endbr32",

    // tdx
    "tdcall",
    "seamret",
    "seamops",
    "seamcall",

    // waitpkg
    "tpause",
    "umonitor",
    "umwait",

    // uintr
    "uiret",
    "testui",
    "clui",
    "stui",
    "senduipi",

    // tsxldtrk
    "xsusldtrk",
    "xresldtrk",

    // avx512f
    "valignd",
    "valignq",
    "vblendmpd",
    "vblendmps",
    "vcompresspd",
    "vcompressps",
    "vcvtpd2udq",
    "vcvttpd2udq",
    "vcvtps2udq",
    "vcvttps2udq",
    "vcvtqq2pd",
    "vcvtqq2ps",
    "vcvtsd2usi",
    "vcvttsd2usi",
    "vcvtss2usi",
    "vcvttss2usi",
    "vcvtudq2pd",
    "vcvtudq2ps",
    "vcvtusi2usd",
    "vcvtusi2uss",
    "vexpandpd",
    "vexpandps",
    "vextractf32x4",
    "vextractf64x4",
    "vextracti32x4",
    "vextracti64x4",
    "vfixupimmpd",
    "vfixupimmps",
    "vfixupimmsd",
    "vfixupimmss",
    "vgetexppd",
    "vgetexpps",
    "vgetexpsd",
    "vgetexpss",
    "vgetmantpd",
    "vgetmantps",
    "vgetmantsd",
    "vgetmantss",
    "vinsertf32x4",
    "vinsertf64x4",
    "vinserti64x4",
    "vmovdqa32",
    "vmovdqa64",
    "vmovdqu32",
    "vmovdqu64",
    "vpblendmd",
    "vpblendmq",
    "vpcmpd",
    "vpcmpud",
    "vpcmpq",
    "vpcmpuq",
    "vpcompressq",
    "vpcompressd",
    "vpermi2d",
    "vpermi2q",
    "vpermi2pd",
    "vpermi2ps",
    "vpermt2d",
    "vpermt2q",
    "vpermt2pd",
    "vpermt2ps",
    "vpmaxsq",
    "vpmaxuq",
    "vpminsq",
    "vpminuq",
    "vpmovsqb",
    "vpmovusqb",
    "vpmovsqw",
    "vpmovusqw",
    "vpmovsqd",
    "vpmovusqd",
    "vpmovsdb",
    "vpmovusdb",
    "vpmovsdw",
    "vpmovusdw",
    "vprold",
    "vprolq",
    "vprolvd",
    "vprolvq",
    "vprord",
    "vprorq",
    "vprorrd",
    "vprorrq",
    "vpscatterdd",
    "vpscatterdq",
    "vpscatterqd",
    "vpscatterqq",
    "vpsraq",
    "vpsravq",
    "vptestnmd",
    "vptestnmq",
    "vpternlogd",
    "vpternlogq",
    "vptestmd",
    "vptestmq",
    "vrcp14pd",
    "vrcp14ps",
    "vrcp14sd",
    "vrcp14ss",
    "vrndscalepd",
    "vrndscaleps",
    "vrndscalesd",
    "vrndscaless",
    "vrsqrt14pd",
    "vrsqrt14ps",
    "vrsqrt14sd",
    "vrsqrt14ss",
    "vscaledpd",
    "vscaledps",
    "vscaledsd",
    "vscaledss",
    "vscatterdd",
    "vscatterdq",
    "vscatterqd",
    "vscatterqq",
    "vshuff32x4",
    "vshuff64x2",
    "vshufi32x4",
    "vshufi64x2",

    // avx512dq
    "vcvttpd2qq",
    "vcvtpd2qq",
    "vcvttpd2uqq",
    "vcvtpd2uqq",
    "vcvttps2qq",
    "vcvtps2qq",
    "vcvttps2uqq",
    "vcvtps2uqq",
    "vcvtuqq2pd",
    "vcvtuqq2ps",
    "vextractf64x2",
    "vextracti64x2",
    "vfpclasspd",
    "vfpclassps",
    "vfpclasssd",
    "vfpclassss",
    "vinsertf64x2",
    "vinserti64x2",
    "vpmovm2d",
    "vpmovm2q",
    "vpmovb2d",
    "vpmovq2m",
    "vrangepd",
    "vrangeps",
    "vrangesd",
    "vrangess",
    "vreducepd",
    "vreduceps",
    "vreducesd",
    "vreducess",

    // avx512bw
    "vdbpsadbw",
    "vmovdqu8",
    "vmovdqu16",
    "vpblendmb",
    "vpblendmw",
    "vpcmpb",
    "vpcmpub",
    "vpcmpw",
    "vpcmpuw",
    "vpermw",
    "vpermi2b",
    "vpermi2w",
    "vpmovm2b",
    "vpmovm2w",
    "vpmovb2m",
    "vpmovw2m",
    "vpmovswb",
    "vpmovuswb",
    "vpsllvw",
    "vpsravw",
    "vpsrlvw",
    "vptestnmb",
    "vptestnmw",
    "vptestmb",
    "vptestmw",

    // avx512cd
    "vpbroadcastm",
    "vpconflictd",
    "vpconflictq",
    "vplzcntd",
    "vplzcntq",

    "kunpckbw",
    "kunpckwd",
    "kunpckdq",

    "kaddb",
    "kandb",
    "kandnb",
    "kmovb",
    "knotb",
    "korb",
    "kortestb",
    "kshiftlb",
    "kshiftrb",
    "ktestb",
    "kxnorb",
    "kxorb",
    "kaddw",
    "kandw",
    "kandnw",
    "kmovw",
    "knotw",
    "korw",
    "kortestw",
    "kshiftlw",
    "kshiftrw",
    "ktestw",
    "kxnorw",
    "kxorw",
    "kaddd",
    "kandd",
    "kandnd",
    "kmovd",
    "knotd",
    "kord",
    "kortestd",
    "kshiftld",
    "kshiftrd",
    "ktestd",
    "kxnord",
    "kxord",
    "kaddq",
    "kandq",
    "kandnq",
    "kmovq",
    "knotq",
    "korq",
    "kortestq",
    "kshiftlq",
    "kshiftrq",
    "ktestq",
    "kxnorq",
    "kxorq",

    // avx512er
    "vexp2pd",
    "vexp2ps",
    "vexp2sd",
    "vexp2ss",
    "vrcp28pd",
    "vrcp28ps",
    "vrcp28sd",
    "vrcp28ss",
    "vrsqrt28pd",
    "vrsqrt28ps",
    "vrsqrt28sd",
    "vrsqrt28ss",

    // avx512pf
    "vgatherpf0dpd",
    "vgatherpf0dps",
    "vgatherpf0qpd",
    "vgatherpf0qps",
    "vgatherpf1dpd",
    "vgatherpf1dps",
    "vgatherpf1qpd",
    "vgatherpf1qps",
    "vscatterpf0dpd",
    "vscatterpf0dps",
    "vscatterpf0qpd",
    "vscatterpf0qps",
    "vscatterpf1dpd",
    "vscatterpf1dps",
    "vscatterpf1qpd",
    "vscatterpf1qps",

    // mpx
    "bndmk",
    "bndcl",
    "bndcu",
    "bndcn",
    "bndmov",
    "bndldx",
    "bndstx",

    "vgf2p8affineqb",
    "vgf2p8affineinvqb",
    "vpshrdq",
    "vpshrdd",
    "vpshrdw",
    "vpshldq",
    "vpshldd",
    "vpshldw",
    "vbroadcastf32x8",
    "vbroadcastf64x4",
    "vbroadcastf32x4",
    "vbroadcastf64x2",
    "vbroadcastf32x2",
    "vbroadcasti32x8",
    "vbroadcasti64x4",
    "vbroadcasti32x4",
    "vbroadcasti64x2",
    "vbroadcasti32x2",
    "vextracti32x8",
    "vextractf32x8",
    "vinserti32x8",
    "vinsertf32x8",
    "vinserti32x4",
    "v4fnmaddss",
    "v4fnmaddps",
    "vcvtneps2bf16",
    "v4fmaddss",
    "v4fmaddps",
    "vcvtne2ps2bf16",
    "vp2intersectd",
    "vp2intersectq",
    "vp4dpwssds",
    "vp4dpwssd",
    "vpdpwssds",
    "vpdpwssd",
    "vpdpbusds",
    "vdpbf16ps",
    "vpbroadcastmw2d",
    "vpbroadcastmb2q",
    "vpmovd2m",
    "vpmovqd",
    "vpmovwb",
    "vpmovdb",
    "vpmovdw",
    "vpmovqb",
    "vpmovqw",
    "vgf2p8mulb",
    "vpmadd52huq",
    "vpmadd52luq",
    "vpshufbitqmb",
    "vpermb",
    "vpexpandd",
    "vpexpandq",
    "vpabsq",
    "vprorvd",
    "vprorvq",
    "vpmultishiftqb",
    "vpermt2b",
    "vpermt2w",
    "vpshrdvq",
    "vpshrdvd",
    "vpshrdvw",
    "vpshldvq",
    "vpshldvd",
    "vpshldvw",
    "vpcompressb",
    "vpcompressw",
    "vpexpandb",
    "vpexpandw",
    "vpopcntd",
    "vpopcntq",
    "vpopcntb",
    "vpopcntw",
    "vscalefss",
    "vscalefsd",
    "vscalefps",
    "vscalefpd",
    "vpdpbusd",
    "vcvtusi2sd",
    "vcvtusi2ss",
    "vpxord",
    "vpxorq",
    "vpord",
    "vporq",
    "vpandnd",
    "vpandnq",
    "vpandd",
    "vpandq",

    "psmash",
    "pvalidate",
    "rmpadjust",
    "rmpupdate",
];

impl Opcode {
    fn name(&self) -> &'static str {
        unsafe {
            MNEMONICS.get_kinda_unchecked(*self as usize & 0xfff)
        }
    }
}

// allowing these deprecated items for the time being, not yet breaking yaxpeax-x86 apis
#[allow(deprecated)]
impl <T: fmt::Write, Y: YaxColors> Colorize<T, Y> for Opcode {
    fn colorize(&self, _colors: &Y, out: &mut T) -> fmt::Result {
        // see `impl Colorize for long_mode::Opcode for more about this
        out.write_str(self.name())
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        // to reuse one implementation, call the deprecated function for now.
        #[allow(deprecated)]
        self.display_with(DisplayStyle::Intel).colorize(&NoColors, fmt)
    }
}

impl<'instr> fmt::Display for InstructionDisplayer<'instr> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        // to reuse one implementation, call the deprecated function for now.
        #[allow(deprecated)]
        self.colorize(&NoColors, fmt)
    }
}

/// enum controlling how `Instruction::display_with` renders instructions. `Intel` is more or less
/// intel syntax, though memory operand sizes are elided if they can be inferred from other
/// operands.
#[derive(Copy, Clone)]
pub enum DisplayStyle {
    /// intel-style syntax for instructions, like
    /// `add eax, [edx + ecx * 2 + 0x1234]`
    Intel,
    /// C-style syntax for instructions, like
    /// `eax += [edx + ecx * 2 + 0x1234]`
    C,
    // one might imagine an ATT style here, which is mostly interesting for reversing operand
    // order.
    // well.
    // it also complicates memory operands in an offset-only operand, and is just kind of awful, so
    // it's just not implemented yet.
    // ATT,
}

/// implementation of [`Display`](fmt::Display) that renders instructions using a specified display
/// style.
pub struct InstructionDisplayer<'instr> {
    pub(crate) instr: &'instr Instruction,
    pub(crate) style: DisplayStyle,
}

/*
 * Can't implement this as accepting a formatter because rust
 * doesn't let me build one outside println! or write! or whatever.
 *
 * can't write this as an intermediate struct because i refuse to copy
 * all data into the struct, and having a function producing a struct with
 * some lifetimes gets really hairy if it's from a trait - same GAT kind
 * of nonsense as i saw with ContextRead, because someone could hold onto
 * the dang intermediate struct forever.
 *
 * so write to some Write thing i guess. bite me. i really just want to
 * stop thinking about how to support printing instructions...
 */
// allowing these deprecated items for the time being, not yet breaking yaxpeax-x86 apis
#[allow(deprecated)]
impl <'instr, T: fmt::Write, Y: YaxColors> Colorize<T, Y> for InstructionDisplayer<'instr> {
    fn colorize(&self, colors: &Y, out: &mut T) -> fmt::Result {
        // TODO: I DONT LIKE THIS, there is no address i can give contextualize here,
        // the address operand maybe should be optional..
        self.contextualize(colors, 0, Some(&NoContext), out)
    }
}

/// No per-operand context when contextualizing an instruction!
struct NoContext;

impl Instruction {
    /// format this instruction into `out` as a plain text string.
    #[cfg_attr(feature="profiling", inline(never))]
    pub fn write_to<T: fmt::Write>(&self, out: &mut T) -> fmt::Result {
        let mut out = yaxpeax_arch::display::FmtSink::new(out);
        contextualize_intel(self, &mut out)
    }

    /// format this instruction into `out`, which may perform additional styling based on its
    /// `DisplaySink` implementation.
    #[cfg_attr(feature="profiling", inline(never))]
    pub fn display_into<T: DisplaySink>(&self, out: &mut T) -> fmt::Result {
        contextualize_intel(self, out)
    }
}

pub(crate) fn contextualize_intel<T: DisplaySink>(instr: &Instruction, out: &mut T) -> fmt::Result {
    if instr.xacquire() {
        out.write_fixed_size("xacquire ")?;
    }
    if instr.xrelease() {
        out.write_fixed_size("xrelease ")?;
    }
    if instr.prefixes.lock() {
        out.write_fixed_size("lock ")?;
    }

    if instr.prefixes.rep_any() {
        if instr.opcode.can_rep() {
            if instr.prefixes.rep() {
                out.write_fixed_size("rep ")?;
            } else if instr.prefixes.repnz() {
                out.write_fixed_size("repnz ")?;
            }
        }
    }

    out.write_opcode(instr.opcode)?;

    if instr.operand_count > 0 {
        out.write_fixed_size(" ")?;

        if instr.visit_operand(0, &mut RelativeBranchPrinter {
            inst: instr,
            out,
        })? {
            return Ok(());
        }

        if instr.operands[0 as usize].is_memory() {
            out.write_mem_size_label(instr.mem_size)?;
            if let Some(prefix) = instr.segment_override_for_op(0) {
                let name = prefix.name();
                out.write_char(' ')?;
                out.write_char(name[0] as char)?;
                out.write_char(name[1] as char)?;
                out.write_fixed_size(":")?;
            } else {
                out.write_fixed_size(" ")?;
            }
        }

        let mut displayer = DisplayingOperandVisitor {
            f: out,
        };
        instr.visit_operand(0 as u8, &mut displayer)?;

        for i in 1..instr.operand_count {
            // don't worry about checking for `instr.operands[i] != Nothing`, it would be a bug to
            // reach that while iterating only to `operand_count`..
            out.write_fixed_size(", ")?;
            if i >= 4 {
                unsafe { core::hint::unreachable_unchecked(); }
            }

            if instr.operands[i as usize].is_memory() {
                out.write_mem_size_label(instr.mem_size)?;
                if i >= 4 {
                    unsafe { core::hint::unreachable_unchecked(); }
                }
                if let Some(prefix) = instr.segment_override_for_op(i) {
                    let name = prefix.name();
                    out.write_char(' ')?;
                    out.write_char(name[0] as char)?;
                    out.write_char(name[1] as char)?;
                    out.write_fixed_size(":")?;
                } else {
                    out.write_fixed_size(" ")?;
                }
            }

            let mut displayer = DisplayingOperandVisitor {
                f: out,
            };

            instr.visit_operand(i as u8, &mut displayer)?;
            if let Some(evex) = instr.prefixes.evex() {
                if evex.broadcast() && instr.operands[i as usize].is_memory() {
                    let scale = if instr.opcode == Opcode::VCVTPD2PS || instr.opcode == Opcode::VCVTTPD2UDQ || instr.opcode == Opcode::VCVTPD2UDQ || instr.opcode == Opcode::VCVTUDQ2PD || instr.opcode == Opcode::VCVTPS2PD || instr.opcode == Opcode::VCVTQQ2PS || instr.opcode == Opcode::VCVTDQ2PD || instr.opcode == Opcode::VCVTTPD2DQ || instr.opcode == Opcode::VFPCLASSPS || instr.opcode == Opcode::VFPCLASSPD || instr.opcode == Opcode::VCVTNEPS2BF16 || instr.opcode == Opcode::VCVTUQQ2PS || instr.opcode == Opcode::VCVTPD2DQ || instr.opcode == Opcode::VCVTTPS2UQQ || instr.opcode == Opcode::VCVTPS2UQQ || instr.opcode == Opcode::VCVTTPS2QQ || instr.opcode == Opcode::VCVTPS2QQ {
                        if instr.opcode == Opcode::VFPCLASSPS || instr.opcode ==  Opcode::VCVTNEPS2BF16 {
                            if evex.vex().l() {
                                8
                            } else if evex.lp() {
                                16
                            } else {
                                4
                            }
                        } else if instr.opcode == Opcode::VFPCLASSPD {
                            if evex.vex().l() {
                                4
                            } else if evex.lp() {
                                8
                            } else {
                                2
                            }
                        } else {
                            // vcvtpd2ps is "cool": in broadcast mode, it can read a
                            // double-precision float (qword), resize to single-precision,
                            // then broadcast that to the whole destination register. this
                            // means we need to show `xmm, qword [addr]{1to4}` if vector
                            // size is 256. likewise, scale of 8 for the same truncation
                            // reason if vector size is 512.
                            // vcvtudq2pd is the same story.
                            // vfpclassp{s,d} is a mystery to me.
                            if evex.vex().l() {
                                4
                            } else if evex.lp() {
                                8
                            } else {
                                2
                            }
                        }
                    } else {
                        // this should never be `None` - that would imply two
                        // memory operands for a broadcasted operation.
                        if let Some(width) = Operand::from_spec(instr, instr.operands[i as usize - 1]).width() {
                            width / instr.mem_size
                        } else {
                            0
                        }
                    };
                    out.write_fixed_size("{1to")?;
                    static STRING_LUT: &'static [&'static str] = &[
                        "0", "1", "2", "3", "4", "5", "6", "7", "8",
                        "9", "10", "11", "12", "13", "14", "15", "16",
                    ];
                    unsafe {
                        out.write_lt_16(STRING_LUT.get_kinda_unchecked(scale as usize))?;
                    }
                    out.write_char('}')?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn contextualize_c<T: DisplaySink>(instr: &Instruction, out: &mut T) -> fmt::Result {
    let mut brace_count = 0;

    let mut prefixed = false;

    if instr.xacquire() {
        out.write_str("xacquire ")?;
        prefixed = true;
    }
    if instr.xrelease() {
        out.write_str("xrelease ")?;
        prefixed = true;
    }
    if instr.prefixes.lock() {
        out.write_str("lock ")?;
        prefixed = true;
    }

    if prefixed {
        out.write_str("{ ")?;
        brace_count += 1;
    }

    if instr.prefixes.rep_any() {
        if instr.opcode.can_rep() {
            let word_str = match instr.mem_size {
                1 => "byte",
                2 => "word",
                4 => "dword",
                8 => "qword",
                _ => { unreachable!("invalid word size") }
            };

            // only a few of you actually use the prefix...
            if instr.prefixes.rep() {
                out.write_str("rep ")?;
            } else if instr.prefixes.repnz() {
                out.write_str("repnz ")?;
            } // TODO: other rep kinds?

            out.write_str(word_str)?;
            out.write_str(" { ")?;
            brace_count += 1;
        }
    }

    fn write_jmp_operand<T: fmt::Write>(op: Operand, out: &mut T) -> fmt::Result {
        let mut out = yaxpeax_arch::display::FmtSink::new(out);
        use core::fmt::Write;
        match op {
            Operand::ImmediateI8(rel) => {
                let rel = if rel >= 0 {
                    out.write_str("$+")?;
                    rel as u8
                } else {
                    out.write_str("$-")?;
                    rel.unsigned_abs()
                };
                out.write_prefixed_u8(rel)
            }
            Operand::ImmediateI32(rel) => {
                let rel = if rel >= 0 {
                    out.write_str("$+")?;
                    rel as u32
                } else {
                    out.write_str("$-")?;
                    rel.unsigned_abs()
                };
                out.write_prefixed_u32(rel)
            }
            other => {
                write!(out, "{}", other)
            }
        }
    }

    match instr.opcode {
        Opcode::Invalid => { out.write_str("invalid")?; },
        Opcode::MOVS => {
            out.write_str("es:[edi++] = ds:[esi++]")?;
        },
        Opcode::CMPS => {
            out.write_str("eflags = flags(ds:[esi++] - es:[edi++])")?;
        },
        Opcode::LODS => {
            // TODO: size
            out.write_str("rax = ds:[esi++]")?;
        },
        Opcode::STOS => {
            // TODO: size
            out.write_str("es:[edi++] = rax")?;
        },
        Opcode::INS => {
            // TODO: size
            out.write_str("es:[edi++] = port(dx)")?;
        },
        Opcode::OUTS => {
            // TODO: size
            out.write_str("port(dx) = ds:[esi++]")?;
        }
        Opcode::ADD => {
            write!(out, "{} += {}", instr.operand(0), instr.operand(1))?;
        }
        Opcode::OR => {
            write!(out, "{} |= {}", instr.operand(0), instr.operand(1))?;
        }
        Opcode::ADC => {
            write!(out, "{} += {} + eflags.cf", instr.operand(0), instr.operand(1))?;
        }
        Opcode::ADCX => {
            write!(out, "{} += {} + eflags.cf", instr.operand(0), instr.operand(1))?;
        }
        Opcode::ADOX => {
            write!(out, "{} += {} + eflags.of", instr.operand(0), instr.operand(1))?;
        }
        Opcode::SBB => {
            write!(out, "{} -= {} + eflags.cf", instr.operand(0), instr.operand(1))?;
        }
        Opcode::AND => {
            write!(out, "{} &= {}", instr.operand(0), instr.operand(1))?;
        }
        Opcode::XOR => {
            write!(out, "{} ^= {}", instr.operand(0), instr.operand(1))?;
        }
        Opcode::SUB => {
            write!(out, "{} -= {}", instr.operand(0), instr.operand(1))?;
        }
        Opcode::CMP => {
            write!(out, "eflags = flags({} - {})", instr.operand(0), instr.operand(1))?;
        }
        Opcode::TEST => {
            write!(out, "eflags = flags({} & {})", instr.operand(0), instr.operand(1))?;
        }
        Opcode::XADD => {
            write!(out, "({}, {}) = ({} + {}, {})", instr.operand(0), instr.operand(1), instr.operand(0), instr.operand(1), instr.operand(0))?;
        }
        Opcode::BT => {
            write!(out, "bt")?;
        }
        Opcode::BTS => {
            write!(out, "bts")?;
        }
        Opcode::BTC => {
            write!(out, "btc")?;
        }
        Opcode::BSR => {
            write!(out, "{} = msb({})", instr.operand(0), instr.operand(1))?;
        }
        Opcode::BSF => {
            write!(out, "{} = lsb({}) (x86 bsf)", instr.operand(0), instr.operand(1))?;
        }
        Opcode::TZCNT => {
            write!(out, "{} = lsb({})", instr.operand(0), instr.operand(1))?;
        }
        Opcode::MOV => {
            write!(out, "{} = {}", instr.operand(0), instr.operand(1))?;
        }
        Opcode::SAR => {
            write!(out, "{} = {} >>> {}", instr.operand(0), instr.operand(0), instr.operand(1))?;
        }
        Opcode::SAL => {
            write!(out, "{} = {} <<< {}", instr.operand(0), instr.operand(0), instr.operand(1))?;
        }
        Opcode::SHR => {
            write!(out, "{} = {} >> {}", instr.operand(0), instr.operand(0), instr.operand(1))?;
        }
        Opcode::SHRX => {
            write!(out, "{} = {} >> {} (x86 shrx)", instr.operand(0), instr.operand(1), instr.operand(2))?;
        }
        Opcode::SHL => {
            write!(out, "{} = {} << {}", instr.operand(0), instr.operand(0), instr.operand(1))?;
        }
        Opcode::SHLX => {
            write!(out, "{} = {} << {} (x86 shlx)", instr.operand(0), instr.operand(1), instr.operand(2))?;
        }
        Opcode::ROR => {
            write!(out, "{} = {} ror {}", instr.operand(0), instr.operand(0), instr.operand(1))?;
        }
        Opcode::RORX => {
            write!(out, "{} = {} ror {} (x86 rorx)", instr.operand(0), instr.operand(1), instr.operand(2))?;
        }
        Opcode::ROL => {
            write!(out, "{} = {} rol {}", instr.operand(0), instr.operand(0), instr.operand(1))?;
        }
        Opcode::RCR => {
            write!(out, "{} = {} rcr {}", instr.operand(0), instr.operand(0), instr.operand(1))?;
        }
        Opcode::RCL => {
            write!(out, "{} = {} rcl {}", instr.operand(0), instr.operand(0), instr.operand(1))?;
        }
        Opcode::PUSH => {
            write!(out, "push({})", instr.operand(0))?;
        }
        Opcode::POP => {
            write!(out, "{} = pop()", instr.operand(0))?;
        }
        Opcode::MOVD => {
            write!(out, "{} = movd({})", instr.operand(0), instr.operand(1))?;
        }
        Opcode::MOVQ => {
            write!(out, "{} = movq({})", instr.operand(0), instr.operand(1))?;
        }
        Opcode::MOVNTQ => {
            write!(out, "{} = movntq({})", instr.operand(0), instr.operand(1))?;
        }
        Opcode::INC => {
            if instr.operand(0).is_memory() {
                match instr.mem_size {
                    1 => { write!(out, "byte {}++", instr.operand(0))?; },
                    2 => { write!(out, "word {}++", instr.operand(0))?; },
                    4 => { write!(out, "dword {}++", instr.operand(0))?; },
                    _ => { write!(out, "qword {}++", instr.operand(0))?; }, // sizes that are not 1, 2, or 4, *better* be 8.
                }
            } else {
                write!(out, "{}++", instr.operand(0))?;
            }
        }
        Opcode::DEC => {
            if instr.operand(0).is_memory() {
                match instr.mem_size {
                    1 => { write!(out, "byte {}--", instr.operand(0))?; },
                    2 => { write!(out, "word {}--", instr.operand(0))?; },
                    4 => { write!(out, "dword {}--", instr.operand(0))?; },
                    _ => { write!(out, "qword {}--", instr.operand(0))?; }, // sizes that are not 1, 2, or 4, *better* be 8.
                }
            } else {
                write!(out, "{}--", instr.operand(0))?;
            }
        }
        Opcode::JMP => {
            out.write_str("jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JECXZ => {
            out.write_str("if ecx == 0 then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::LOOP => {
            out.write_str("ecx--; if ecx != 0 then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::LOOPZ => {
            out.write_str("ecx--; if ecx != 0 and zero(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::LOOPNZ => {
            out.write_str("ecx--; if ecx != 0 and !zero(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JO => {
            out.write_str("if _(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JNO => {
            out.write_str("if _(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JB => {
            out.write_str("if /* unsigned */ below(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JNB => {
            out.write_str("if /* unsigned */ above_or_equal(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JZ => {
            out.write_str("if zero(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JNZ => {
            out.write_str("if !zero(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JNA => {
            out.write_str("if /* unsigned */ below_or_equal(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JA => {
            out.write_str("if /* unsigned */ above(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JS => {
            out.write_str("if signed(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JNS => {
            out.write_str("if !signed(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JP => {
            out.write_str("if parity(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JNP => {
            out.write_str("if !parity(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JL => {
            out.write_str("if /* signed */ less(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JGE => {
            out.write_str("if /* signed */ greater_or_equal(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JLE => {
            out.write_str("if /* signed */ less_or_equal(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::JG => {
            out.write_str("if /* signed */ greater(rflags) then jmp ")?;
            write_jmp_operand(instr.operand(0), out)?;
        },
        Opcode::NOP => {
            write!(out, "nop")?;
        }
        _ => {
            if instr.operand_count() == 0 {
                write!(out, "{}()", instr.opcode())?;
            } else {
                write!(out, "{} = {}({}", instr.operand(0), instr.opcode(), instr.operand(0))?;
                let mut comma = true;
                for i in 1..instr.operand_count() {
                    if comma {
                        write!(out, ", ")?;
                    }
                    write!(out, "{}", instr.operand(i))?;
                    comma = true;
                }
                write!(out, ")")?;
            }
        }
    }

    while brace_count > 0 {
        out.write_str(" }")?;
        brace_count -= 1;
    }

    Ok(())
}

// allowing these deprecated items for the time being, not yet breaking yaxpeax-x86 apis
#[allow(deprecated)]
impl <'instr, T: fmt::Write, Y: YaxColors> ShowContextual<u32, NoContext, T, Y> for InstructionDisplayer<'instr> {
    fn contextualize(&self, _colors: &Y, _address: u32, _context: Option<&NoContext>, out: &mut T) -> fmt::Result {
        let InstructionDisplayer {
            instr,
            style,
        } = self;

        let mut out = yaxpeax_arch::display::FmtSink::new(out);

        match style {
            DisplayStyle::Intel => {
                contextualize_intel(instr, &mut out)
            }
            DisplayStyle::C => {
                contextualize_c(instr, &mut out)
            }
        }
    }
}

// allowing these deprecated items for the time being, not yet breaking yaxpeax-x86 apis
#[allow(deprecated)]
#[cfg(feature="std")]
impl <T: fmt::Write, Y: YaxColors> ShowContextual<u64, [Option<alloc::string::String>], T, Y> for Instruction {
    fn contextualize(&self, colors: &Y, _address: u64, context: Option<&[Option<alloc::string::String>]>, out: &mut T) -> fmt::Result {
        if self.prefixes.lock() {
            write!(out, "lock ")?;
        }

        if [Opcode::MOVS, Opcode::CMPS, Opcode::LODS, Opcode::STOS, Opcode::INS, Opcode::OUTS].contains(&self.opcode) {
            // only a few of you actually use the prefix...
            if self.prefixes.rep() {
                write!(out, "rep ")?;
            } else if self.prefixes.repnz() {
                write!(out, "repnz ")?;
            }
        }

        self.opcode.colorize(colors, out)?;

        match context.and_then(|xs| xs[0].as_ref()) {
            Some(s) => { write!(out, " {}", s)?; },
            None => {
                match self.operands[0] {
                    OperandSpec::Nothing => {
                        return Ok(());
                    },
                    _ => {
                        write!(out, " ")?;
                        if let Some(prefix) = self.segment_override_for_op(0) {
                            write!(out, "{}:", prefix)?;
                        }
                    }
                }
                let x = Operand::from_spec(self, self.operands[0]);
                x.colorize(colors, out)?;
            }
        };
        for i in 1..self.operand_count {
            let i = i as usize;
            match context.and_then(|xs| xs[i].as_ref()) {
                Some(s) => { write!(out, ", {}", s)? }
                None => {
                    match &self.operands[i] {
                        &OperandSpec::Nothing => {
                            return Ok(());
                        },
                        _ => {
                            write!(out, ", ")?;
                            if let Some(prefix) = self.segment_override_for_op(1) {
                                write!(out, "{}:", prefix)?;
                            }
                            let x = Operand::from_spec(self, self.operands[i]);
                            x.colorize(colors, out)?
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

static RELATIVE_BRANCHES: [Opcode; 22] = [
    Opcode::JMP, Opcode::CALL, Opcode::JECXZ,
    Opcode::LOOP, Opcode::LOOPZ, Opcode::LOOPNZ,
    Opcode::JO, Opcode::JNO,
    Opcode::JB, Opcode::JNB,
    Opcode::JZ, Opcode::JNZ,
    Opcode::JNA, Opcode::JA,
    Opcode::JS, Opcode::JNS,
    Opcode::JP, Opcode::JNP,
    Opcode::JL, Opcode::JGE,
    Opcode::JLE, Opcode::JG,
];

struct RelativeBranchPrinter<'a, F: DisplaySink> {
    inst: &'a Instruction,
    out: &'a mut F,
}

impl<'a, F: DisplaySink> super::OperandVisitor for RelativeBranchPrinter<'a, F> {
    // return true if we printed a relative branch offset, false otherwise
    type Ok = bool;
    // but errors are errors
    type Error = fmt::Error;

    fn visit_reg(&mut self, _reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_deref(&mut self, _reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_disp(&mut self, _reg: RegSpec, _disp: i32) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    #[cfg_attr(feature="profiling", inline(never))]
    fn visit_i8(&mut self, rel: i8) -> Result<Self::Ok, Self::Error> {
        if RELATIVE_BRANCHES.contains(&self.inst.opcode) {
            self.out.write_char('$')?;
            // danger_anguished_string_write(self.out, "$");
            let mut v = rel as u8;
            if rel < 0 {
                self.out.write_char('-')?;
                //danger_anguished_string_write(&mut self.out, "-");
                v = rel.unsigned_abs();
            } else {
                self.out.write_char('+')?;
                // danger_anguished_string_write(&mut self.out, "+");
            }
            self.out.write_fixed_size("0x")?;
            self.out.write_u8(v)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    #[cfg_attr(feature="profiling", inline(never))]
    fn visit_i32(&mut self, rel: i32) -> Result<Self::Ok, Self::Error> {
        if RELATIVE_BRANCHES.contains(&self.inst.opcode) || self.inst.opcode == Opcode::XBEGIN {
            self.out.write_char('$')?;
            // danger_anguished_string_write(self.out, "$");
            let mut v = rel as u32;
            if rel < 0 {
                self.out.write_char('-')?;
                // danger_anguished_string_write(&mut self.out, "-");
                v = rel.unsigned_abs();
            } else {
                self.out.write_char('+')?;
                // danger_anguished_string_write(&mut self.out, "+");
            }
            self.out.write_fixed_size("0x")?;
            self.out.write_u32(v)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn visit_u8(&mut self, _imm: u8) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_i16(&mut self, _imm: i16) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_u16(&mut self, _imm: u16) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_u32(&mut self, _imm: u32) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_abs_u16(&mut self, _imm: u16) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_abs_u32(&mut self, _imm: u32) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_reg_scale(&mut self, _reg: RegSpec, _scale: u8) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_index_base_scale(&mut self, _base: RegSpec, _index: RegSpec, _scale: u8) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_reg_scale_disp(&mut self, _reg: RegSpec, _scale: u8, _disp: i32) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_index_base_scale_disp(&mut self, _base: RegSpec, _index: RegSpec, _scale: u8, _disp: i32) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_other(&mut self) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_reg_mask_merge(&mut self, _spec: RegSpec, _mask: RegSpec, _merge_mode: MergeMode) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_reg_mask_merge_sae(&mut self, _spec: RegSpec, _mask: RegSpec, _merge_mode: MergeMode, _sae_mode: super::SaeMode) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_reg_mask_merge_sae_noround(&mut self, _spec: RegSpec, _mask: RegSpec, _merge_mode: MergeMode) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_reg_disp_masked(&mut self, _spec: RegSpec, _disp: i32, _mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_reg_deref_masked(&mut self, _spec: RegSpec, _mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_reg_scale_masked(&mut self, _spec: RegSpec, _scale: u8, _mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_reg_scale_disp_masked(&mut self, _spec: RegSpec, _scale: u8, _disp: i32, _mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_index_base_masked(&mut self, _base: RegSpec, _index: RegSpec, _mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_index_base_disp_masked(&mut self, _base: RegSpec, _index: RegSpec, _disp: i32, _mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_index_base_scale_masked(&mut self, _base: RegSpec, _index: RegSpec, _scale: u8, _mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_index_base_scale_disp_masked(&mut self, _base: RegSpec, _index: RegSpec, _scale: u8, _disp: i32, _mask_reg: RegSpec) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
    fn visit_absolute_far_address(&mut self, _segment: u16, _address: u32) -> Result<Self::Ok, Self::Error> {
        Ok(false)
    }
}

#[cfg(feature="alloc")]
mod buffer_sink {
    use core::fmt;
    use super::super::{DisplayStyle, InstructionDisplayer};
    use super::{contextualize_c, contextualize_intel};

    /// helper to format `amd64` instructions with highest throughput and least configuration. this is
    /// functionally a buffer for one x86 instruction's text.
    ///
    /// ### when to use this over `fmt::Display`?
    ///
    /// `fmt::Display` is a fair choice in most cases. in some cases, `InstructionTextBuffer` may
    /// support formatting options that may be difficult to configure for a `Display` impl.
    /// additionally, `InstructionTextBuffer` may be able to specialize more effectively where
    /// `fmt::Display`, writing to a generic `fmt::Write`, may not.
    ///
    /// if your use case for `yaxpeax-x86` involves being bounded on the speed of disassembling and
    /// formatting instructions, [`InstructionTextBuffer::format_inst`] has been measured as up to 11%
    /// faster than an equivalent `write!(buf, "{}", inst)`.
    ///
    /// `InstructionTextBuffer` involves internal allocations; if your use case for `yaxpeax-x86`
    /// requires allocations never occurring, it is not an appropriate tool.
    ///
    /// ### example
    ///
    /// ```
    /// use yaxpeax_x86::long_mode::InstDecoder;
    /// use yaxpeax_x86::long_mode::InstructionTextBuffer;
    /// use yaxpeax_x86::long_mode::DisplayStyle;
    ///
    /// let bytes = &[0x33, 0xc0];
    /// let inst = InstDecoder::default().decode_slice(bytes).expect("can decode");
    /// let mut text_buf = InstructionTextBuffer::new();
    /// assert_eq!(
    ///     text_buf.format_inst(&inst.display_with(DisplayStyle::Intel)).expect("can format"),
    ///     "xor eax, eax"
    /// );
    ///
    /// // or, getting the formatted instruction with `text_str`:
    /// assert_eq!(
    ///     text_buf.text_str(),
    ///     "xor eax, eax"
    /// );
    /// ```
    pub struct InstructionTextBuffer {
        content: alloc::string::String,
    }

    impl InstructionTextBuffer {
        /// create an `InstructionTextBuffer` with default settings. `InstructionTextBuffer`'s default
        /// settings format instructions identically to their corresponding `fmt::Display`.
        pub fn new() -> Self {
            let mut buf = alloc::string::String::new();
            // TODO: move 512 out to a MAX_INSTRUCTION_LEN const and appropriate justification (and
            // fuzzing and ..)
            buf.reserve(512);
            Self {
                content: buf,
            }
        }

        /// format `inst` into this buffer. returns a borrow of that same internal buffer for convenience.
        ///
        /// this clears and reuses an internal buffer; if an instruction had been previously formatted
        /// through this buffer, it will be overwritten.
        pub fn format_inst<'buf, 'instr>(&'buf mut self, display: &InstructionDisplayer<'instr>) -> Result<&'buf str, fmt::Error> {
            // Safety: this sink is used to format exactly one instruction and then dropped. it can
            // never escape `format_inst`.
            let mut handle = unsafe { self.write_handle() };

            match display.style {
                DisplayStyle::Intel => {
                    contextualize_intel(&display.instr, &mut handle)?;
                }
                DisplayStyle::C => {
                    contextualize_c(&display.instr, &mut handle)?;
                }
            }

            Ok(self.text_str())
        }

        /// return a borrow of the internal buffer. if an instruction has been formatted, the
        /// returned `&str` contains that instruction's buffered text.
        pub fn text_str(&self) -> &str {
            self.content.as_str()
        }

        /// do the necessary bookkeeping and provide an `InstructionTextSink` to write an instruction
        /// into.
        ///
        /// SAFETY: callers must print at most one instruction into this handle.
        unsafe fn write_handle(&mut self) -> yaxpeax_arch::display::InstructionTextSink {
            self.content.clear();
            // Safety: `content` was just cleared, so writing begins at the start of the buffer.
            // `content`is large enough to hold a fully-formatted instruction (see
            // `InstructionTextBuffer::new`).
            yaxpeax_arch::display::InstructionTextSink::new(&mut self.content)
        }
    }
}
#[cfg(feature="alloc")]
pub use buffer_sink::InstructionTextBuffer;
