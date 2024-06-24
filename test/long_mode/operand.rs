use yaxpeax_x86::long_mode::{InstDecoder, Operand, RegSpec};
use yaxpeax_x86::MemoryAccessSize;

#[test]
fn register_widths() {
    assert_eq!(Operand::Register { reg: RegSpec::rsp() }.width(), Some(8));
    assert_eq!(Operand::Register { reg: RegSpec::esp() }.width(), Some(4));
    assert_eq!(Operand::Register { reg: RegSpec::sp() }.width(), Some(2));
    assert_eq!(Operand::Register { reg: RegSpec::cl() }.width(), Some(1));
    assert_eq!(Operand::Register { reg: RegSpec::ch() }.width(), Some(1));
    assert_eq!(Operand::Register { reg: RegSpec::gs() }.width(), Some(2));
}

#[test]
fn memory_widths() {
    // the register operand directly doesn't report a size - it comes from the `Instruction` for
    // which this is an operand .
    assert_eq!(Operand::MemDeref { base: RegSpec::rsp() }.width(), None);

    fn mem_size_of(data: &[u8]) -> MemoryAccessSize {
        let decoder = InstDecoder::default();
        decoder.decode_slice(data).unwrap().mem_size().unwrap()
    }

    // and checking the memory size direcly reports correct names
    assert_eq!(mem_size_of(&[0x32, 0x00]).size_name(), "byte");
    assert_eq!(mem_size_of(&[0x66, 0x33, 0x00]).size_name(), "word");
    assert_eq!(mem_size_of(&[0x33, 0x00]).size_name(), "dword");
    assert_eq!(mem_size_of(&[0x48, 0x33, 0x00]).size_name(), "qword");
}

#[test]
fn test_implied_memory_width() {
    fn mem_size_of(data: &[u8]) -> Option<u8> {
        let decoder = InstDecoder::default();
        decoder.decode_slice(data).unwrap().mem_size().unwrap().bytes_size()
    }

    // test push, pop, call, and ret
    assert_eq!(mem_size_of(&[0xc3]), Some(8));
    assert_eq!(mem_size_of(&[0xe8, 0x11, 0x22, 0x33, 0x44]), Some(8));
    assert_eq!(mem_size_of(&[0x50]), Some(8));
    assert_eq!(mem_size_of(&[0x58]), Some(8));
    assert_eq!(mem_size_of(&[0x66, 0x50]), Some(8));
    assert_eq!(mem_size_of(&[0x66, 0x58]), Some(8));
    assert_eq!(mem_size_of(&[0xff, 0xf0]), Some(8));
    assert_eq!(mem_size_of(&[0x66, 0xff, 0xf0]), Some(2));
    // operand-size prefixed call and jump still reads 8 bytes (prefix ignored)
    assert_eq!(mem_size_of(&[0x66, 0xff, 0x10]), Some(8));
    assert_eq!(mem_size_of(&[0x66, 0xff, 0x20]), Some(8));
}
