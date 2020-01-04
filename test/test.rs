extern crate yaxpeax_arch;
extern crate yaxpeax_x86;

use std::fmt::Write;

use yaxpeax_arch::Decoder;
use yaxpeax_x86::{Instruction, InstDecoder, decode_one};

fn decode(bytes: &[u8]) -> Option<Instruction> {
    let mut instr = Instruction::invalid();
    match decode_one(&InstDecoder::default(), bytes.iter().map(|x| *x).take(16).collect::<Vec<u8>>(), &mut instr) {
        Ok(()) => Some(instr),
        _ => None
    }
}

fn decode_as(decoder: &InstDecoder, bytes: &[u8]) -> Option<Instruction> {
    let mut instr = Instruction::invalid();
    match decode_one(decoder, bytes.iter().map(|x| *x).take(16).collect::<Vec<u8>>(), &mut instr) {
        Ok(()) => Some(instr),
        _ => None
    }
}

fn test_invalid(data: &[u8]) {
    test_invalid_under(&InstDecoder::default(), data);
}

fn test_invalid_under(decoder: &InstDecoder, data: &[u8]) {
    if let Ok(inst) = decoder.decode(data.into_iter().cloned()) {
        assert_eq!(inst.opcode, yaxpeax_x86::Opcode::Invalid, "decoded {:?} from {:02x?} under decoder {}", inst.opcode, data, decoder);
    } else {
        // this is fine
    }
}

fn test_display(data: &[u8], expected: &'static str) {
    test_display_under(&InstDecoder::default(), data, expected);
}

fn test_display_under(decoder: &InstDecoder, data: &[u8], expected: &'static str) {
    let mut hex = String::new();
    for b in data {
        write!(hex, "{:02x}", b).unwrap();
    }
    match decoder.decode(data.into_iter().map(|x| *x)) {
        Ok(instr) => {
            let text = format!("{}", instr);
            assert!(
                text == expected,
                "display error for {}:\n  decoded: {:?} under decoder {}\n displayed: {}\n expected: {}\n",
                hex,
                instr,
                decoder,
                text,
                expected
            );
        },
        Err(e) => {
            assert!(false, "decode error ({}) for {} under decoder {}:\n  expected: {}\n", e, hex, decoder, expected);
        }
    }
}

#[test]
fn test_mmx() {
    test_display(&[0x4f, 0x0f, 0x7e, 0xcf], "movd r15, mm1");
    test_display(&[0x41, 0x0f, 0x7e, 0xcf], "movd r15d, mm1");
    test_display(&[0x4f, 0x0f, 0x7f, 0xcf], "movq mm7, mm1");
    test_display(&[0x0f, 0xc4, 0xc0, 0x14], "pinsrw mm0, eax, 0x14");
    test_display(&[0x4f, 0x0f, 0xc4, 0xc0, 0x14], "pinsrw mm0, r8d, 0x14");
    test_display(&[0x4f, 0x0f, 0xc4, 0x00, 0x14], "pinsrw mm0, [r8], 0x14");
    test_display(&[0x4f, 0x0f, 0xd1, 0xcf], "psrlw mm1, mm7");
    test_display(&[0x4f, 0x0f, 0xd1, 0x00], "psrlw mm0, [r8]");
    test_invalid(&[0x4f, 0x0f, 0xd7, 0x00]);
    test_display(&[0x4f, 0x0f, 0xd7, 0xcf], "pmovmskb r9d, mm7");
}

#[test]
fn test_cvt() {
    test_display(&[0x0f, 0x2c, 0xcf], "cvttps2pi mm1, xmm7");
    test_display(&[0x48, 0x0f, 0x2c, 0xcf], "cvttps2pi mm1, xmm7");
    test_display(&[0x4f, 0x0f, 0x2c, 0xcf], "cvttps2pi mm1, xmm15");
    test_display(&[0x4f, 0x0f, 0x2a, 0xcf], "cvtpi2ps xmm9, mm7");
    test_display(&[0x4f, 0x0f, 0x2a, 0x00], "cvtpi2ps xmm8, [r8]");
    test_display(&[0x4f, 0x66, 0x0f, 0x2a, 0xcf], "cvtpi2pd xmm1, mm7");
    test_display(&[0x66, 0x4f, 0x0f, 0x2a, 0xcf], "cvtpi2pd xmm9, mm7");
    test_display(&[0x4f, 0xf3, 0x0f, 0x2a, 0xcf], "cvtsi2ss xmm1, edi");
    test_display(&[0xf3, 0x4f, 0x0f, 0x2a, 0xcf], "cvtsi2ss xmm9, r15");
    test_display(&[0x4f, 0xf2, 0x0f, 0x2a, 0xcf], "cvtsi2sd xmm1, edi");
    test_display(&[0xf2, 0x4f, 0x0f, 0x2a, 0xcf], "cvtsi2sd xmm9, r15");
    test_display(&[0x4f, 0xf2, 0x0f, 0x2a, 0x00], "cvtsi2sd xmm0, [rax]");
    test_display(&[0xf2, 0x4f, 0x0f, 0x2a, 0x00], "cvtsi2sd xmm8, [r8]");
    test_display(&[0x4f, 0xf3, 0x0f, 0x2a, 0x00], "cvtsi2ss xmm0, [rax]");
    test_display(&[0xf3, 0x4f, 0x0f, 0x2a, 0x00], "cvtsi2ss xmm8, [r8]");
    test_display(&[0x4f, 0x66, 0x0f, 0x2a, 0x00], "cvtpi2pd xmm0, [rax]");
    test_display(&[0x66, 0x4f, 0x0f, 0x2a, 0x00], "cvtpi2pd xmm8, [r8]");
}

#[test]
fn test_aesni() {
    fn test_instr(bytes: &[u8], text: &'static str) {
        test_display_under(&InstDecoder::minimal().with_aesni(), bytes, text);
        test_display_under(&InstDecoder::default(), bytes, text);
        test_invalid_under(&InstDecoder::minimal(), bytes);
    }

    fn test_instr_invalid(bytes: &[u8]) {
        test_invalid_under(&InstDecoder::minimal().with_aesni(), bytes);
        test_invalid_under(&InstDecoder::default(), bytes);
    }

    test_instr(&[0x66, 0x0f, 0x38, 0xdb, 0x0f], "aesimc xmm1, [rdi]");
    test_instr(&[0x66, 0x4f, 0x0f, 0x38, 0xdb, 0xcf], "aesimc xmm9, xmm15");

    test_instr(&[0x66, 0x0f, 0x38, 0xdc, 0x0f], "aesenc xmm1, [rdi]");
    test_instr(&[0x66, 0x4f, 0x0f, 0x38, 0xdc, 0xcf], "aesenc xmm9, xmm15");

    test_instr(&[0x66, 0x0f, 0x38, 0xdd, 0x0f], "aesenclast xmm1, [rdi]");
    test_instr(&[0x66, 0x4f, 0x0f, 0x38, 0xdd, 0xcf], "aesenclast xmm9, xmm15");

    test_instr(&[0x66, 0x0f, 0x38, 0xde, 0x0f], "aesdec xmm1, [rdi]");
    test_instr(&[0x66, 0x4f, 0x0f, 0x38, 0xde, 0xcf], "aesdec xmm9, xmm15");

    test_instr(&[0x66, 0x0f, 0x38, 0xdf, 0x0f], "aesdeclast xmm1, [rdi]");
    test_instr(&[0x66, 0x4f, 0x0f, 0x38, 0xdf, 0xcf], "aesdeclast xmm9, xmm15");

    test_instr(&[0x66, 0x0f, 0x3a, 0xdf, 0x0f, 0xaa], "aeskeygenassist xmm1, [rdi], 0xaa");
    test_instr(&[0x66, 0x4f, 0x0f, 0x3a, 0xdf, 0xcf, 0xaa], "aeskeygenassist xmm9, xmm15, 0xaa");
}

#[test]
fn test_sse3() {
    fn test_instr(bytes: &[u8], text: &'static str) {
        test_display_under(&InstDecoder::minimal().with_sse3(), bytes, text);
        test_invalid_under(&InstDecoder::minimal(), bytes);
        // avx doesn't imply older instructions are necessarily valid
        test_invalid_under(&InstDecoder::minimal().with_avx(), bytes);
        // sse4 doesn't imply older instructions are necessarily valid
        test_invalid_under(&InstDecoder::minimal().with_sse4_1(), bytes);
        test_invalid_under(&InstDecoder::minimal().with_sse4_2(), bytes);
    }

    fn test_instr_invalid(bytes: &[u8]) {
        test_invalid_under(&InstDecoder::minimal().with_sse3(), bytes);
        test_invalid_under(&InstDecoder::default(), bytes);
    }

    test_instr(&[0xf2, 0x0f, 0xf0, 0x0f], "lddqu xmm1, [rdi]");
    test_instr_invalid(&[0xf2, 0x0f, 0xf0, 0xcf]);
    test_instr(&[0xf2, 0x0f, 0xd0, 0x0f], "addsubps xmm1, [rdi]");
    test_instr(&[0xf2, 0x0f, 0xd0, 0xcf], "addsubps xmm1, xmm7");
    test_instr(&[0xf2, 0x4f, 0x0f, 0xd0, 0xcf], "addsubps xmm9, xmm15");
    test_instr(&[0x66, 0x0f, 0xd0, 0x0f], "addsubpd xmm1, [rdi]");
    test_instr(&[0x66, 0x0f, 0xd0, 0xcf], "addsubpd xmm1, xmm7");
    test_instr(&[0x66, 0x4f, 0x0f, 0xd0, 0xcf], "addsubpd xmm9, xmm15");

    test_instr(&[0xf2, 0x0f, 0x7c, 0x0f], "haddps xmm1, [rdi]");
    test_instr(&[0xf2, 0x0f, 0x7c, 0xcf], "haddps xmm1, xmm7");
    test_instr(&[0xf2, 0x4f, 0x0f, 0x7c, 0xcf], "haddps xmm9, xmm15");
    test_instr(&[0x66, 0x0f, 0x7c, 0x0f], "haddpd xmm1, [rdi]");
    test_instr(&[0x66, 0x0f, 0x7c, 0xcf], "haddpd xmm1, xmm7");
    test_instr(&[0x66, 0x4f, 0x0f, 0x7c, 0xcf], "haddpd xmm9, xmm15");

    test_instr(&[0xf2, 0x0f, 0x7d, 0x0f], "hsubps xmm1, [rdi]");
    test_instr(&[0xf2, 0x0f, 0x7d, 0xcf], "hsubps xmm1, xmm7");
    test_instr(&[0xf2, 0x4f, 0x0f, 0x7d, 0xcf], "hsubps xmm9, xmm15");
    test_instr(&[0x66, 0x0f, 0x7d, 0x0f], "hsubpd xmm1, [rdi]");
    test_instr(&[0x66, 0x0f, 0x7d, 0xcf], "hsubpd xmm1, xmm7");
    test_instr(&[0x66, 0x4f, 0x0f, 0x7d, 0xcf], "hsubpd xmm9, xmm15");

    test_instr(&[0xf3, 0x0f, 0x12, 0x0f], "movsldup xmm1, [rdi]");
    test_instr(&[0xf3, 0x0f, 0x12, 0xcf], "movsldup xmm1, xmm7");
    test_instr(&[0xf3, 0x4f, 0x0f, 0x12, 0xcf], "movsldup xmm9, xmm15");
    test_instr(&[0xf3, 0x0f, 0x16, 0x0f], "movshdup xmm1, [rdi]");
    test_instr(&[0xf3, 0x0f, 0x16, 0xcf], "movshdup xmm1, xmm7");
    test_instr(&[0xf3, 0x4f, 0x0f, 0x16, 0xcf], "movshdup xmm9, xmm15");

    test_instr(&[0xf2, 0x0f, 0x12, 0x0f], "movddup xmm1, [rdi]");
    test_instr(&[0xf2, 0x0f, 0x12, 0xcf], "movddup xmm1, xmm7");
    test_instr(&[0xf2, 0x4f, 0x0f, 0x12, 0xcf], "movddup xmm9, xmm15");

    test_instr(&[0x66, 0x0f, 0x01, 0xc8], "monitor");
    test_instr(&[0xf2, 0x0f, 0x01, 0xc8], "monitor");
    test_instr(&[0xf3, 0x0f, 0x01, 0xc8], "monitor");

    test_instr(&[0x66, 0x0f, 0x01, 0xc9], "mwait");
    test_instr(&[0xf2, 0x0f, 0x01, 0xc9], "mwait");
    test_instr(&[0xf3, 0x0f, 0x01, 0xc9], "mwait");
}

#[test]
fn test_0f01() {
    // drawn heavily from "Table A-6.  Opcode Extensions for One- and Two-byte Opcodes by Group
    // Number"
    test_display(&[0x0f, 0x01, 0x38], "invlpg [rax]");
    test_display(&[0x0f, 0x01, 0x3f], "invlpg [rdi]");
    test_display(&[0x0f, 0x01, 0x40, 0xff], "sgdt [rax - 0x1]");
    test_display(&[0x0f, 0x01, 0x41, 0xff], "sgdt [rcx - 0x1]");
    test_display(&[0x0f, 0x01, 0x49, 0xff], "sidt [rcx - 0x1]");
    test_display(&[0x0f, 0x01, 0x51, 0xff], "lgdt [rcx - 0x1]");
    test_display(&[0x0f, 0x01, 0x59, 0xff], "lidt [rcx - 0x1]");
    test_display(&[0x0f, 0x01, 0x61, 0xff], "smsw [rcx - 0x1]");
    test_display(&[0x0f, 0x01, 0xc0], "enclv");
    test_display(&[0x0f, 0x01, 0xc1], "vmcall");
    test_display(&[0x0f, 0x01, 0xc2], "vmlaunch");
    test_display(&[0x0f, 0x01, 0xc3], "vmresume");
    test_display(&[0x0f, 0x01, 0xc4], "vmxoff");
    test_invalid(&[0x0f, 0x01, 0xc5]);
    test_invalid(&[0x0f, 0x01, 0xc6]);
    test_invalid(&[0x0f, 0x01, 0xc7]);
    test_display(&[0x0f, 0x01, 0xc8], "monitor");
    test_display(&[0x0f, 0x01, 0xc9], "mwait");
    test_display(&[0x0f, 0x01, 0xca], "clac");
    test_display(&[0x0f, 0x01, 0xcb], "stac");
    test_display(&[0x0f, 0x01, 0xcf], "encls");
    test_display(&[0x0f, 0x01, 0xd0], "xgetbv");
    test_display(&[0x0f, 0x01, 0xd1], "xsetbv");
    test_invalid(&[0x0f, 0x01, 0xd2]);
    test_invalid(&[0x0f, 0x01, 0xd3]);
    test_display(&[0x0f, 0x01, 0xd4], "vmfunc");
    test_display(&[0x0f, 0x01, 0xd5], "xend");
    test_display(&[0x0f, 0x01, 0xd6], "xtest");
    test_display(&[0x0f, 0x01, 0xd7], "enclu");
    test_invalid(&[0x0f, 0x01, 0xd8]);
    test_invalid(&[0x0f, 0x01, 0xd9]);
    test_invalid(&[0x0f, 0x01, 0xda]);
    test_invalid(&[0x0f, 0x01, 0xdb]);
    test_invalid(&[0x0f, 0x01, 0xdc]);
    test_invalid(&[0x0f, 0x01, 0xdd]);
    test_invalid(&[0x0f, 0x01, 0xde]);
    test_invalid(&[0x0f, 0x01, 0xdf]);
    test_display(&[0x0f, 0x01, 0xee], "rdpkru");
    test_display(&[0x0f, 0x01, 0xef], "wrpkru");
    test_display(&[0x0f, 0x01, 0xf8], "swapgs");
    test_display(&[0x0f, 0x01, 0xf9], "rdtscp");
}

#[test]
fn test_0fae() {
    let intel = InstDecoder::minimal().with_intel_quirks();
    let amd = InstDecoder::minimal().with_amd_quirks();
    let default = InstDecoder::default();
    let minimal = InstDecoder::minimal();
    // drawn heavily from "Table A-6.  Opcode Extensions for One- and Two-byte Opcodes by Group
    // Number"
    test_display(&[0x0f, 0xae, 0x04, 0x4f], "fxsave [rdi + rcx * 2]");
    test_display(&[0x0f, 0xae, 0x0c, 0x4f], "fxrstor [rdi + rcx * 2]");
    test_display(&[0x0f, 0xae, 0x14, 0x4f], "ldmxcsr [rdi + rcx * 2]");
    test_display(&[0x0f, 0xae, 0x1c, 0x4f], "stmxcsr [rdi + rcx * 2]");
    test_display(&[0x0f, 0xae, 0x24, 0x4f], "xsave [rdi + rcx * 2]");
    test_display(&[0x0f, 0xae, 0x2c, 0x4f], "xrstor [rdi + rcx * 2]");
    test_display(&[0x0f, 0xae, 0x34, 0x4f], "xsaveopt [rdi + rcx * 2]");
    test_display(&[0x0f, 0xae, 0x3c, 0x4f], "clflush [rdi + rcx * 2]");

    for (modrm, text) in &[(0xe8u8, "lfence"), (0xf0u8, "mfence"), (0xf8u8, "sfence")] {
        test_display_under(&intel, &[0x0f, 0xae, *modrm], text);
        test_display_under(&amd, &[0x0f, 0xae, *modrm], text);
        test_display_under(&default, &[0x0f, 0xae, *modrm], text);
        test_display_under(&minimal, &[0x0f, 0xae, *modrm], text);
        // it turns out intel and amd accept m != 0 for {l,m,s}fence:
        // from intel:
        // ```
        // Specification of the instruction's opcode above indicates a ModR/M byte of F0. For this
        // instruction, the processor ignores the r/m field of the ModR/M byte. Thus, MFENCE is encoded
        // by any opcode of the form 0F AE Fx, where x is in the range 0-7.
        // ```
        // whereas amd does not discuss the r/m field at all. at least as of zen, amd also accepts
        // these encodings.
        for m in 1u8..8u8 {
            test_display_under(&intel, &[0x0f, 0xae, modrm | m], text);
            test_display_under(&amd, &[0x0f, 0xae, modrm | m], text);
            test_display_under(&default, &[0x0f, 0xae, modrm | m], text);
            test_invalid_under(&minimal, &[0x0f, 0xae, modrm | m]);
        }
    }
}

#[test]
fn test_system() {
    test_display(&[0x66, 0x4f, 0x0f, 0xb2, 0x00], "lss r8, [r8]");
    test_display(&[0x67, 0x4f, 0x0f, 0xb2, 0x00], "lss r8, [r8d]");
    test_display(&[0x4f, 0x0f, 0xb2, 0x00], "lss r8, [r8]");
    test_display(&[0x45, 0x0f, 0x22, 0xc8], "mov cr9, r8");
    test_display(&[0x45, 0x0f, 0x20, 0xc8], "mov r8, cr9");
    test_display(&[0x40, 0x0f, 0x22, 0xc8], "mov cr1, rax");
    test_display(&[0x0f, 0x22, 0xc8], "mov cr1, rax");
    test_display(&[0x44, 0x0f, 0x22, 0xcf], "mov cr9, rdi");
    test_display(&[0x0f, 0x22, 0xcf], "mov cr1, rdi");
    test_display(&[0x0f, 0x20, 0xc8], "mov rax, cr1");

    test_display(&[0x45, 0x0f, 0x23, 0xc8], "mov dr9, r8");
    test_display(&[0x45, 0x0f, 0x21, 0xc8], "mov r8, dr9");
    test_display(&[0x40, 0x0f, 0x23, 0xc8], "mov dr1, rax");
    test_display(&[0x0f, 0x23, 0xc8], "mov dr1, rax");
    test_display(&[0x0f, 0x21, 0xc8], "mov rax, dr1");
}

#[test]
fn test_arithmetic() {
    test_display(&[0x81, 0xec, 0x10, 0x03, 0x00, 0x00], "sub esp, 0x310");
    test_display(&[0x0f, 0xaf, 0xc2], "imul eax, edx");
    test_display(&[0x4b, 0x69, 0x43, 0x6f, 0x6d, 0x70, 0x6c, 0x65], "imul rax, [r11 + 0x6f], 0x656c706d");
    test_display(&[0x66, 0x0f, 0xaf, 0xd1], "imul dx, cx");
    test_display(&[0x4b, 0x6b, 0x43, 0x6f, 0x6d], "imul al, [r11 + 0x6f], 0x6d");
    test_display(&[0x4f, 0x4e, 0x00, 0xcc], "add spl, r9b");
}

#[test]
#[allow(non_snake_case)]
fn test_E_decode() {
    test_display(&[0xff, 0x75, 0xb8], "push [rbp - 0x48]");
    test_display(&[0xff, 0x75, 0x08], "push [rbp + 0x8]");
}

#[test]
fn test_sse() {
    test_display(&[0x4f, 0x0f, 0x28, 0x00], "movaps xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x29, 0x00], "movaps [r8], xmm8");
    test_display(&[0x4f, 0x0f, 0x2b, 0x00], "movntps [r8], xmm8");
    test_display(&[0x4f, 0x0f, 0x2e, 0x00], "ucomiss xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x2f, 0x00], "comiss xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x50, 0xc0], "movmskps r8d, xmm8");
    test_display(&[0x0f, 0x28, 0xd0], "movaps xmm2, xmm0");
    test_display(&[0x66, 0x0f, 0x28, 0xd0], "movapd xmm2, xmm0");
    test_display(&[0x66, 0x0f, 0x28, 0x00], "movapd xmm0, [rax]");
    test_invalid(&[0x4f, 0x0f, 0x50, 0x00]);
    test_display(&[0x4f, 0x0f, 0x50, 0xc0], "movmskps r8d, xmm8");
    test_display(&[0x4f, 0x0f, 0x51, 0x00], "sqrtps xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x52, 0x00], "rsqrtps xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x53, 0x00], "rcpps xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x54, 0x00], "andps xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x55, 0x00], "andnps xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x56, 0x00], "orps xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x57, 0x00], "xorps xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x58, 0x00], "addps xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x59, 0x00], "mulps xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x5a, 0x00], "cvtps2pd xmm8, [r8]");
    test_display(&[0x4f, 0x0f, 0x5b, 0x00], "cvtdq2ps xmm8, [r8]");
    test_display(&[0x66, 0x4f, 0x0f, 0x5b, 0x00], "cvtdq2ps xmm8, [r8]");
    test_display(&[0x67, 0x4f, 0x0f, 0x5b, 0x00], "cvtdq2ps xmm8, [r8d]");
    test_display(&[0x4f, 0x66, 0x0f, 0x28, 0x00], "movapd xmm0, [rax]");
    test_display(&[0x66, 0x4f, 0x0f, 0x28, 0x00], "movapd xmm8, [r8]");
    test_display(&[0x66, 0x4f, 0x0f, 0x28, 0x00], "movapd xmm8, [r8]");
    test_display(&[0x67, 0x4f, 0x66, 0x0f, 0x28, 0x00], "movapd xmm0, [eax]");
    test_display(&[0x67, 0x66, 0x4f, 0x0f, 0x28, 0x00], "movapd xmm8, [r8d]");
    test_display(&[0x66, 0x0f, 0x29, 0x00], "movapd [rax], xmm0");
    test_display(&[0x66, 0x0f, 0xef, 0xc0], "pxor xmm0, xmm0");
    test_display(&[0x66, 0x4f, 0x0f, 0xef, 0xc0], "pxor xmm8, xmm8");
    test_display(&[0xf2, 0x0f, 0x10, 0x0c, 0xc6], "movsd xmm1, [rsi + rax * 8]");
    test_display(&[0xf3, 0x0f, 0x10, 0x04, 0x86], "movss xmm0, [rsi + rax * 4]");
    test_display(&[0xf2, 0x0f, 0x59, 0xc8], "mulsd xmm1, xmm0");
    test_display(&[0xf3, 0x0f, 0x59, 0xc8], "mulss xmm1, xmm0");
    test_display(&[0xf2, 0x4f, 0x0f, 0x59, 0xc8], "mulsd xmm9, xmm8");
    test_display(&[0xf2, 0x0f, 0x11, 0x0c, 0xc7], "movsd [rdi + rax * 8], xmm1");
}

// SETLE, SETNG, ...

#[test]
fn test_mov() {
    // test_display(&[0xa1, 0x93, 0x62, 0xc4, 0x00, 0x12, 0x34, 0x12, 0x34], "mov eax, [0x3412341200c46293]");
    // RCT.exe 32bit version, TODO: FIX
    test_display(&[0xa1, 0x93, 0x62, 0xc4, 0x00], "mov eax, [0xc46293]");
    test_display(&[0x48, 0xc7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00], "mov [rsp], 0x0");
    test_display(&[0x48, 0x89, 0x44, 0x24, 0x08], "mov [rsp + 0x8], rax");
    test_display(&[0x48, 0x89, 0x43, 0x18], "mov [rbx + 0x18], rax");
    test_display(&[0x48, 0xc7, 0x43, 0x10, 0x00, 0x00, 0x00, 0x00], "mov [rbx + 0x10], 0x0");
    test_display(&[0x49, 0x89, 0x4e, 0x08], "mov [r14 + 0x8], rcx");
    test_display(&[0x48, 0x8b, 0x32], "mov rsi, [rdx]");
    test_display(&[0x49, 0x89, 0x46, 0x10], "mov [r14 + 0x10], rax");
    test_display(&[0x4d, 0x0f, 0x43, 0xec, 0x49], "cmovnb r13, r12");
    test_display(&[0x0f, 0xb6, 0x06], "movzx eax, byte [rsi]");
    test_display(&[0x0f, 0xb7, 0x06], "movzx eax, word [rsi]");
    test_display(&[0x89, 0x55, 0x94], "mov [rbp - 0x6c], edx");
    test_display(&[0x65, 0x4c, 0x89, 0x04, 0x25, 0xa8, 0x01, 0x00, 0x00], "mov gs:[0x1a8], r8");
    test_display(&[0x0f, 0xbe, 0x83, 0xb4, 0x00, 0x00, 0x00], "movsx eax, byte [rbx + 0xb4]");
    test_display(&[0x46, 0x63, 0xc1], "movsxd r8, ecx");
    test_display(&[0x48, 0x63, 0x04, 0xba], "movsxd rax, [rdx + rdi * 4]");
    test_display(&[0xf3, 0x0f, 0x6f, 0x07], "movdqu xmm0, [rdi]");
    test_display(&[0xf3, 0x0f, 0x7f, 0x45, 0x00], "movdqu [rbp], xmm0");
}

#[test]
fn test_stack() {
    test_display(&[0x66, 0x41, 0x50], "push r8w");
}

#[test]
fn test_prefixes() {
    test_display(&[0x66, 0x41, 0x31, 0xc0], "xor r8w, ax");
    test_display(&[0x66, 0x41, 0x32, 0xc0], "xor al, r8b");
    test_display(&[0x40, 0x32, 0xc5], "xor al, bpl");
}

#[test]
fn test_control_flow() {
    test_display(&[0x73, 0x31], "jnb 0x31");
    test_display(&[0x72, 0x5a], "jb 0x5a");
    test_display(&[0x0f, 0x86, 0x8b, 0x01, 0x00, 0x00], "jna 0x18b");
    test_display(&[0x74, 0x47], "jz 0x47");
    test_display(&[0xff, 0x15, 0x7e, 0x72, 0x24, 0x00], "call [rip + 0x24727e]");
    test_display(&[0xc3], "ret");
}

#[test]
fn test_test_cmp() {
    test_display(&[0xf6, 0x05, 0x2c, 0x9b, 0xff, 0xff, 0x01], "test [rip - 0x64d4], 0x1");
    test_display(&[0x48, 0x3d, 0x01, 0xf0, 0xff, 0xff], "cmp rax, -0xfff");
    test_display(&[0x3d, 0x01, 0xf0, 0xff, 0xff], "cmp eax, -0xfff");
    test_display(&[0x48, 0x83, 0xf8, 0xff], "cmp rax, -0x1");
    test_display(&[0x48, 0x39, 0xc6], "cmp rsi, rax");
}

#[test]
fn test_push_pop() {
    test_display(&[0x5b], "pop rbx");
    test_display(&[0x41, 0x5e], "pop r14");
    test_display(&[0x68, 0x7f, 0x63, 0xc4, 0x00], "push 0xc4637f");
}

#[test]
fn test_bmi1() {
    let bmi1 = InstDecoder::minimal().with_bmi1();
    let no_bmi1 = InstDecoder::minimal();
    test_display_under(&bmi1, &[0x41, 0x0f, 0xbc, 0xd3], "tzcnt edx, r11d");
    test_display_under(&no_bmi1, &[0x41, 0x0f, 0xbc, 0xd3], "bsf edx, r11d");
}

#[test]
fn test_bitwise() {
    test_display_under(&InstDecoder::minimal(), &[0x41, 0x0f, 0xbc, 0xd3], "bsf edx, r11d");
    test_display(&[0x48, 0x0f, 0xa3, 0xd0], "bt rax, rdx");
    test_display(&[0x48, 0x0f, 0xab, 0xd0], "bts rax, rdx");
}

#[test]
fn test_misc() {
    test_display(&[0x9c], "pushf");
    test_display(&[0x48, 0x98], "cdqe");
    test_display(&[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], "nop cs:[rax + rax * 1]");
    test_display(&[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00], "nop [rax + rax * 1]");
    test_display(&[0x48, 0x8d, 0xa4, 0xc7, 0x20, 0x00, 0x00, 0x12], "lea rsp, [rdi + rax * 8 + 0x12000020]");
    test_display(&[0x33, 0xc0], "xor eax, eax");
    test_display(&[0x48, 0x8d, 0x53, 0x08], "lea rdx, [rbx + 0x8]");
    test_display(&[0x31, 0xc9], "xor ecx, ecx");
    test_display(&[0x48, 0x29, 0xc8], "sub rax, rcx");
    test_display(&[0x48, 0x03, 0x0b], "add rcx, [rbx]");
    test_display(&[0x48, 0x8d, 0x0c, 0x12], "lea rcx, [rdx + rdx * 1]");
    test_display(&[0xf6, 0xc2, 0x18], "test dl, 0x18");
    test_display(&[0xf3, 0x48, 0xab], "rep stos es:[rdi], rax");
    test_display(&[0xf3, 0x48, 0xa5], "rep movs es:[rdi], ds:[rsi]");
    test_display(&[0xf3, 0x45, 0x0f, 0xbc, 0xd7], "tzcnt r10d, r15d");
}

#[test]
#[ignore]
// TODO also not supported at all
fn evex() {
    test_display(&[0x62, 0xf2, 0x7d, 0x48, 0x2a, 0x44, 0x40, 0x01], "vmovntdqa zmm0, [rax + rax*2 + 0x40]");
    test_display(&[0x62, 0xf2, 0x7d, 0x08, 0x2a, 0x44, 0x40, 0x01], "vmovntdqa xmm0, [rax + rax*2 + 0x10]");
}

#[test]
fn test_vex() {
    fn test_instr(bytes: &[u8], text: &'static str) {
        test_display_under(&InstDecoder::minimal().with_avx(), bytes, text);
        test_display_under(&InstDecoder::default(), bytes, text);
        test_invalid_under(&InstDecoder::minimal(), bytes);
    }

    fn test_instr_invalid(bytes: &[u8]) {
        test_invalid_under(&InstDecoder::minimal().with_avx(), bytes);
        test_invalid_under(&InstDecoder::default(), bytes);
    }

    test_instr(&[0xc5, 0xf8, 0x10, 0x00], "vmovups xmm0, [rax]");
    test_instr(&[0xc5, 0xf8, 0x10, 0x00], "vmovups xmm0, [rax]");
    test_instr(&[0xc5, 0x78, 0x10, 0x0f], "vmovups xmm9, [rdi]");
    test_instr(&[0xc5, 0xf8, 0x10, 0xcf], "vmovups xmm1, xmm7");
    test_instr(&[0xc5, 0xf9, 0x10, 0x0f], "vmovupd xmm1, [rdi]");
    test_instr(&[0xc5, 0xfa, 0x7e, 0x10], "vmovq xmm2, [rax]");
    test_instr(&[0xc5, 0xfc, 0x10, 0x0f], "vmovups ymm1, [rdi]");
    test_instr(&[0xc5, 0xfd, 0x10, 0x0f], "vmovupd ymm1, [rdi]");
    test_instr(&[0xc5, 0xfe, 0x10, 0x0f], "vmovss xmm1, [rdi]");
    test_instr(&[0xc5, 0xff, 0x10, 0xcf], "vmovsd xmm1, xmm0, xmm7");
    test_instr(&[0xc5, 0xff, 0x10, 0x00], "vmovsd xmm0, [rax]");
    test_instr_invalid(&[0x4f, 0xc5, 0xf8, 0x10, 0x00]);
    test_instr_invalid(&[0xf0, 0xc5, 0xf8, 0x10, 0x00]);
    test_instr(&[0xc4, 0x02, 0x71, 0x00, 0x0f], "vpshufb xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x00, 0x0f], "vpshufb ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x00, 0xcd], "vpshufb xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x00, 0xcd], "vpshufb ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x01, 0x0f], "vphaddw xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x01, 0x0f], "vphaddw ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x01, 0xcd], "vphaddw xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x01, 0xcd], "vphaddw ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x02, 0x0f], "vphaddd xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x02, 0x0f], "vphaddd ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x02, 0xcd], "vphaddd xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x02, 0xcd], "vphaddd ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x03, 0x0f], "vphaddsw xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x03, 0x0f], "vphaddsw ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x03, 0xcd], "vphaddsw xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x03, 0xcd], "vphaddsw ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x04, 0x0f], "vphaddubsw xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x04, 0x0f], "vphaddubsw ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x04, 0xcd], "vphaddubsw xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x04, 0xcd], "vphaddubsw ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x05, 0x0f], "vphsubw xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x05, 0x0f], "vphsubw ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x05, 0xcd], "vphsubw xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x05, 0xcd], "vphsubw ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x06, 0x0f], "vphsubd xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x06, 0x0f], "vphsubd ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x06, 0xcd], "vphsubd xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x06, 0xcd], "vphsubd ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x07, 0x0f], "vphsubsw xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x07, 0x0f], "vphsubsw ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x07, 0xcd], "vphsubsw xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x07, 0xcd], "vphsubsw ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x08, 0x0f], "vpsignb xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x08, 0x0f], "vpsignb ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x08, 0xcd], "vpsignb xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x08, 0xcd], "vpsignb ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x09, 0x0f], "vpsignw xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x09, 0x0f], "vpsignw ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x09, 0xcd], "vpsignw xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x09, 0xcd], "vpsignw ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x0a, 0x0f], "vpsignd xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x0a, 0x0f], "vpsignd ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x0a, 0xcd], "vpsignd xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x0a, 0xcd], "vpsignd ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x0b, 0x0f], "vpmulhrsw xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x0b, 0x0f], "vpmulhrsw ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x0b, 0xcd], "vpmulhrsw xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x0b, 0xcd], "vpmulhrsw ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x0c, 0x0f], "vpermilps xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x0c, 0x0f], "vpermilps ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x0c, 0xcd], "vpermilps xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x0c, 0xcd], "vpermilps ymm9, ymm1, ymm13");
    test_instr(&[0xc4, 0x02, 0x71, 0x0d, 0x0f], "vpermilpd xmm9, xmm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x75, 0x0d, 0x0f], "vpermilpd ymm9, ymm1, [r15]");
    test_instr(&[0xc4, 0x02, 0x71, 0x0d, 0xcd], "vpermilpd xmm9, xmm1, xmm13");
    test_instr(&[0xc4, 0x02, 0x75, 0x0d, 0xcd], "vpermilpd ymm9, ymm1, ymm13");
    test_instr_invalid(&[0xc4, 0x02, 0x71, 0x0e, 0x00]);
    test_instr(&[0xc4, 0x02, 0x79, 0x0e, 0x0f], "vtestps xmm9, [r15]");
    test_instr(&[0xc4, 0x02, 0x7d, 0x0e, 0x0f], "vtestps ymm9, [r15]");
    test_instr(&[0xc4, 0x02, 0x79, 0x0e, 0xcd], "vtestps xmm9, xmm13");
    test_instr(&[0xc4, 0x02, 0x7d, 0x0e, 0xcd], "vtestps ymm9, ymm13");
    test_instr_invalid(&[0xc4, 0x02, 0x71, 0x0f, 0x00]);
    test_instr(&[0xc4, 0x02, 0x79, 0x0f, 0x0f], "vtestpd xmm9, [r15]");
    test_instr(&[0xc4, 0x02, 0x7d, 0x0f, 0x0f], "vtestpd ymm9, [r15]");
    test_instr(&[0xc4, 0x02, 0x79, 0x0f, 0xcd], "vtestpd xmm9, xmm13");
    test_instr(&[0xc4, 0x02, 0x7d, 0x0f, 0xcd], "vtestpd ymm9, ymm13");
    test_instr(&[0xc4, 0xe2, 0x65, 0x90, 0x04, 0x51], "vpgatherdd ymm0, [rcx + ymm2 * 2], ymm3");
    test_instr(&[0xc4, 0xe2, 0xe5, 0x90, 0x04, 0x51], "vpgatherdq ymm0, [rcx + ymm2 * 2], ymm3");
    test_instr(&[0xc4, 0xe2, 0x65, 0x91, 0x04, 0x51], "vpgatherqd ymm0, [rcx + ymm2 * 2], ymm3");
    test_instr(&[0xc4, 0xe2, 0xe5, 0x91, 0x04, 0x51], "vpgatherqq ymm0, [rcx + ymm2 * 2], ymm3");
    test_instr(&[0xc4, 0x02, 0x09, 0x9d, 0xcd], "vfnmadd132ss xmm9, xmm14, xmm13");
    test_instr(&[0xc4, 0x02, 0x89, 0x9d, 0xcd], "vfnmadd132sd xmm9, xmm14, xmm13");
// ...
    test_instr(&[0xc4, 0xe3, 0x79, 0x14, 0xd0, 0x0a], "vpextrb rax, xmm2, 0xa");
    test_instr(&[0xc4, 0xe3, 0x79, 0x14, 0x10, 0x0a], "vpextrb [rax], xmm2, 0xa");
    test_instr_invalid(&[0xc4, 0xe3, 0xf9, 0x14, 0x00, 0xd0]);
    test_instr_invalid(&[0xc4, 0xe3, 0xf9, 0x14, 0x00, 0x0a]);
}

#[test]
fn strange_prefixing() {
    test_display(&[0x45, 0x66, 0x0f, 0x21, 0xc8], "mov rax, dr1");
    test_display(&[0x45, 0xf2, 0x0f, 0x21, 0xc8], "mov rax, dr1");
    test_display(&[0x45, 0xf3, 0x0f, 0x21, 0xc8], "mov rax, dr1");
}

#[test]
fn prefixed_0f() {
    test_display(&[0x0f, 0x02, 0xc0], "lar eax, ax");
    test_display(&[0x48, 0x0f, 0x02, 0xc0], "lar rax, ax");
    test_display(&[0x0f, 0x03, 0xc0], "lsl eax, eax");
    test_display(&[0x48, 0x0f, 0x03, 0xc0], "lsl rax, rax");
    test_display(&[0x0f, 0x05], "syscall");
    test_display(&[0x48, 0x0f, 0x05], "syscall");
    test_display(&[0x66, 0x0f, 0x05], "syscall");
    test_display(&[0x0f, 0x06], "clts");
    test_display(&[0xf2, 0x0f, 0x06], "clts");
    test_display(&[0x0f, 0x07], "sysret");
    test_display(&[0xf2, 0x0f, 0x07], "sysret");
    test_display(&[0x0f, 0x12, 0x0f], "movlps xmm1, [rdi]");
    test_display(&[0x0f, 0x12, 0xcf], "movhlps xmm1, xmm7");
    test_display(&[0x0f, 0x16, 0x0f], "movhps xmm1, [rdi]");
    test_display(&[0x0f, 0x16, 0xcf], "movlhps xmm1, xmm7");
    test_display(&[0x0f, 0x12, 0xc0], "movhlps xmm0, xmm0");
    test_invalid(&[0x0f, 0x13, 0xc0]);
    test_display(&[0x0f, 0x13, 0x00], "movlps [rax], xmm0");
    test_display(&[0x0f, 0x14, 0x08], "unpcklps xmm1, [rax]");
    test_display(&[0x0f, 0x15, 0x08], "unpckhps xmm1, [rax]");
    test_display(&[0x0f, 0x16, 0x0f], "movhps xmm1, [rdi]");
    test_display(&[0x0f, 0x16, 0xc0], "movlhps xmm0, xmm0");
    test_invalid(&[0x0f, 0x17, 0xc0]);
    test_display(&[0x0f, 0x17, 0x00], "movhps [rax], xmm0");
    test_invalid(&[0x0f, 0x18, 0xc0]);
    test_display(&[0x0f, 0x18, 0x00], "prefetchnta [rax]");
    test_display(&[0x0f, 0x18, 0x08], "prefetch0 [rax]");
    test_display(&[0x0f, 0x18, 0x10], "prefetch1 [rax]");
    test_display(&[0x0f, 0x18, 0x18], "prefetch2 [rax]");
    test_display(&[0x0f, 0x18, 0x20], "nop [rax]");
    test_display(&[0x4f, 0x0f, 0x18, 0x20], "nop [r8]");
    test_display(&[0x0f, 0x19, 0x20], "nop [rax]");
    test_display(&[0x0f, 0x1a, 0x20], "nop [rax]");
    test_display(&[0x0f, 0x1b, 0x20], "nop [rax]");
    test_display(&[0x0f, 0x1c, 0x20], "nop [rax]");
    test_display(&[0x0f, 0x1d, 0x20], "nop [rax]");
    test_display(&[0x0f, 0x1e, 0x20], "nop [rax]");
    test_display(&[0x0f, 0x1f, 0x20], "nop [rax]");
    test_display(&[0x45, 0x0f, 0x20, 0xc8], "mov r8, cr9");
    test_display(&[0x0f, 0x20, 0xc8], "mov rax, cr1");
    test_display(&[0x45, 0x0f, 0x21, 0xc8], "mov r8, dr9");
    test_display(&[0x0f, 0x21, 0xc8], "mov rax, dr1");
    test_display(&[0x45, 0x0f, 0x22, 0xc8], "mov cr9, r8");
    test_display(&[0x40, 0x0f, 0x22, 0xc8], "mov cr1, rax");
    test_display(&[0x0f, 0x22, 0xc8], "mov cr1, rax");
    test_display(&[0x44, 0x0f, 0x22, 0xcf], "mov cr9, rdi");
    test_display(&[0x0f, 0x22, 0xcf], "mov cr1, rdi");
    test_display(&[0x45, 0x0f, 0x23, 0xc8], "mov dr9, r8");
    test_display(&[0x40, 0x0f, 0x23, 0xc8], "mov dr1, rax");
    test_display(&[0x0f, 0x23, 0xc8], "mov dr1, rax");
    test_display(&[0x44, 0x0f, 0x23, 0xcf], "mov dr9, rdi");
    test_display(&[0x0f, 0x23, 0xcf], "mov dr1, rdi");
    test_display(&[0x0f, 0x30], "wrmsr");
    test_display(&[0x0f, 0x31], "rdtsc");
    test_display(&[0x0f, 0x32], "rdmsr");
    test_display(&[0x0f, 0x33], "rdpmc");
    test_display(&[0x0f, 0x34], "sysenter");
    test_display(&[0x0f, 0x35], "sysexit");
    test_invalid(&[0x0f, 0x36]);
    test_display(&[0x0f, 0x37], "getsec");
    test_display(&[0x0f, 0x60, 0x00], "punpcklbw mm0, [rax]");
    test_display(&[0x0f, 0x60, 0xc2], "punpcklbw mm0, mm2");
    test_display(&[0x0f, 0x61, 0x00], "punpcklwd mm0, [rax]");
    test_display(&[0x0f, 0x61, 0xc2], "punpcklwd mm0, mm2");
    test_display(&[0x0f, 0x62, 0x00], "punpckldq mm0, [rax]");
    test_display(&[0x0f, 0x62, 0xc2], "punpckldq mm0, mm2");
    test_display(&[0x0f, 0x63, 0x00], "packsswb mm0, [rax]");
    test_display(&[0x0f, 0x63, 0xc2], "packsswb mm0, mm2");
    test_display(&[0x0f, 0x64, 0x00], "pcmpgtb mm0, [rax]");
    test_display(&[0x0f, 0x64, 0xc2], "pcmpgtb mm0, mm2");
    test_display(&[0x0f, 0x65, 0x00], "pcmpgtw mm0, [rax]");
    test_display(&[0x0f, 0x65, 0xc2], "pcmpgtw mm0, mm2");
    test_display(&[0x0f, 0x66, 0x00], "pcmpgtd mm0, [rax]");
    test_display(&[0x0f, 0x66, 0xc2], "pcmpgtd mm0, mm2");
    test_display(&[0x0f, 0x67, 0x00], "packuswb mm0, [rax]");
    test_display(&[0x0f, 0x67, 0xc2], "packuswb mm0, mm2");
    test_display(&[0x0f, 0x68, 0x00], "punpckhbw mm0, [rax]");
    test_display(&[0x0f, 0x68, 0xc2], "punpckhbw mm0, mm2");
    test_display(&[0x0f, 0x69, 0x00], "punpckhwd mm0, [rax]");
    test_display(&[0x0f, 0x69, 0xc2], "punpckhwd mm0, mm2");
    test_display(&[0x0f, 0x6a, 0x00], "punpckhdq mm0, [rax]");
    test_display(&[0x0f, 0x6a, 0xc2], "punpckhdq mm0, mm2");
    test_display(&[0x0f, 0x6b, 0x00], "packssdw mm0, [rax]");
    test_display(&[0x0f, 0x6b, 0xc2], "packssdw mm0, mm2");
    test_invalid(&[0x0f, 0x6c]);
    test_invalid(&[0x0f, 0x6d]);
    test_display(&[0x0f, 0x6e, 0x00], "movd mm0, [rax]");
    test_display(&[0x0f, 0x6e, 0xc2], "movd mm0, edx");
    test_display(&[0x0f, 0x6f, 0x00], "movq mm0, [rax]");
    test_display(&[0x0f, 0x6f, 0xc2], "movq mm0, mm2");
    test_display(&[0x0f, 0x70, 0x00, 0x7f], "pshufw mm0, [rax], 0x7f");
    test_display(&[0x4f, 0x0f, 0x70, 0x00, 0x7f], "pshufw mm0, [r8], 0x7f");
    test_invalid(&[0x0f, 0x71, 0x00, 0x7f]);
    test_invalid(&[0x0f, 0x71, 0xc0, 0x7f]);
    test_display(&[0x0f, 0x71, 0xd0, 0x7f], "psrlw mm0, 0x7f");
    test_display(&[0x0f, 0x71, 0xe0, 0x7f], "psraw mm0, 0x7f");
    test_display(&[0x0f, 0x71, 0xf0, 0x7f], "psllw mm0, 0x7f");
    test_invalid(&[0x0f, 0x72, 0x00, 0x7f]);
    test_invalid(&[0x0f, 0x72, 0xc0, 0x7f]);
    test_display(&[0x0f, 0x72, 0xd0, 0x7f], "psrld mm0, 0x7f");
    test_display(&[0x0f, 0x72, 0xe0, 0x7f], "psrad mm0, 0x7f");
    test_display(&[0x0f, 0x72, 0xf0, 0x7f], "pslld mm0, 0x7f");
    test_invalid(&[0x0f, 0x73, 0x00, 0x7f]);
    test_invalid(&[0x0f, 0x73, 0xc0, 0x7f]);
    test_display(&[0x0f, 0x73, 0xd0, 0x7f], "psrlq mm0, 0x7f");
    test_invalid(&[0x0f, 0x73, 0xe0, 0x7f]);
    test_display(&[0x0f, 0x73, 0xf0, 0x7f], "psllq mm0, 0x7f");
    test_display(&[0x0f, 0xa0], "push fs");
    test_display(&[0x0f, 0xa1], "pop fs");
    test_display(&[0x0f, 0xa2], "cpuid");
    test_display(&[0x0f, 0xa4, 0xc0, 0x11], "shld eax, eax, 0x11");
    test_display(&[0x66, 0x0f, 0xa4, 0xcf, 0x11], "shld di, cx, 0x11");
    test_display(&[0x66, 0x45, 0x0f, 0xa4, 0xcf, 0x11], "shld r15w, r9w, 0x11");
    test_display(&[0x0f, 0xa5, 0xc0], "shld eax, eax, cl");
    test_display(&[0x0f, 0xa5, 0xc9], "shld ecx, ecx, cl");
}

#[test]
fn prefixed_660f() {
    test_display(&[0x66, 0x0f, 0x10, 0xc0], "movupd xmm0, xmm0");
    test_display(&[0x66, 0x48, 0x0f, 0x10, 0xc0], "movupd xmm0, xmm0");
    test_display(&[0x66, 0x4a, 0x0f, 0x10, 0xc0], "movupd xmm0, xmm0");
    test_display(&[0x66, 0x4b, 0x0f, 0x10, 0xc0], "movupd xmm0, xmm8");
    test_display(&[0x66, 0x4c, 0x0f, 0x10, 0xc0], "movupd xmm8, xmm0");
    test_display(&[0x66, 0x4d, 0x0f, 0x10, 0xc0], "movupd xmm8, xmm8");
    test_display(&[0xf2, 0x66, 0x66, 0x4d, 0x0f, 0x10, 0xc0], "movupd xmm8, xmm8");
}

#[test]
fn prefixed_f20f() {
    test_display(&[0xf2, 0x0f, 0x16, 0xcf], "movlhps xmm1, xmm7");
    test_display(&[0xf2, 0x4d, 0x0f, 0x16, 0xcf], "movlhps xmm9, xmm15");
    test_display(&[0x40, 0x66, 0xf2, 0x66, 0x4d, 0x0f, 0x16, 0xcf], "movlhps xmm9, xmm15");
}

#[test]
fn prefixed_f30f() {
    test_display(&[0xf3, 0x0f, 0x16, 0xcf], "movshdup xmm1, xmm7");
    test_display(&[0xf3, 0x4d, 0x0f, 0x16, 0xcf], "movshdup xmm9, xmm15");
}
