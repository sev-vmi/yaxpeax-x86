use core::fmt;

use crate::safer_unchecked::unreachable_kinda_unchecked;

extern crate alloc;

// TODO: find a better place to put this....
fn c_to_hex(c: u8) -> u8 {
    /*
    static CHARSET: &'static [u8; 16] = b"0123456789abcdef";
    CHARSET[c as usize]
    */
    // the conditional branch below is faster than a lookup, yes
    if c < 10 {
        b'0' + c
    } else {
        b'a' + c - 10
    }
}

pub enum TokenType {
    Mnemonic,
    Operand,
    Immediate,
    Register,
    Offset,
}

/// `DisplaySink` allows client code to collect output and minimal markup. this is currently used
/// in formatting instructions for two reasons:
/// * `DisplaySink` implementations have the opportunity to collect starts and ends of tokens at
///   the same time as collecting output itself.
/// * `DisplaySink` implementations provides specialized functions for writing strings in
///   circumstances where a simple "use `core::fmt`" might incur unwanted overhead.
///
/// spans are reported through `span_start` and `span_exit` to avoid constraining implementations
/// into tracking current output offset (which may not be knowable) or span size (which may be
/// knowable, but incur additional overhead to compute or track).
///
/// spans are entered and exited in a FILO manner: a function writing to some `DisplaySink` must
/// exit spans in reverse order to when they are entered. a function sequence like
/// `sink.span_start(Operand); sink.span_start(Immediate); sink.span_exit(Operand)` is in error.
///
/// the `write_*` helpers on `DisplaySink` may be able to take advantage of contraints described in
/// documentation here to better support writing some kinds of inputs than a fully-general solution
/// (such as `core::fmt`) might be able to yield.
///
/// currently there are two motivating factors for `write_*` helpers:
///
/// instruction formatting often involves writing small but variable-size strings, such as register
/// names, which is something of a pathological case for string appending as Rust currently exists:
/// this often becomes `memcpy` and specifically a call to the platform's `memcpy` (rather than an
/// inlined `rep movsb`) just to move 3-5 bytes. one relevant Rust issue for reference:
/// https://github.com/rust-lang/rust/issues/92993#issuecomment-2028915232
///
/// there are similar papercuts around formatting integers as base-16 numbers, such as
/// https://github.com/rust-lang/rust/pull/122770 . in isolation and in most applications these are
/// not a significant source of overhead. but for programs bounded on decoding and printing
/// instructions, these can add up to significant overhead - on the order of 10-20% of total
/// runtime.
///
/// `DisplaySink`
pub trait DisplaySink: fmt::Write {
    #[inline(always)]
    fn write_fixed_size(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.write_str(s)
    }

    /// write a string to this sink that is less than 32 bytes. this is provided for optimization
    /// opportunities when writing a variable-length string with known max size.
    ///
    /// SAFETY: the provided `s` must be less than 32 bytes. if the provided string is longer than
    /// 31 bytes, implementations may only copy part of a multi-byte codepoint while writing to a
    /// utf-8 string. this may corrupt Rust strings.
    unsafe fn write_lt_32(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.write_str(s)
    }
    /// write a string to this sink that is less than 16 bytes. this is provided for optimization
    /// opportunities when writing a variable-length string with known max size.
    ///
    /// SAFETY: the provided `s` must be less than 16 bytes. if the provided string is longer than
    /// 15 bytes, implementations may only copy part of a multi-byte codepoint while writing to a
    /// utf-8 string. this may corrupt Rust strings.
    unsafe fn write_lt_16(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.write_str(s)
    }
    /// write a string to this sink that is less than 8 bytes. this is provided for optimization
    /// opportunities when writing a variable-length string with known max size.
    ///
    /// SAFETY: the provided `s` must be less than 8 bytes. if the provided string is longer than
    /// 7 bytes, implementations may only copy part of a multi-byte codepoint while writing to a
    /// utf-8 string. this may corrupt Rust strings.
    unsafe fn write_lt_8(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.write_str(s)
    }

    /// write a u8 to the output as a base-16 integer.
    ///
    /// this is provided for optimization opportunities when the formatted integer can be written
    /// directly to the sink (rather than formatted to an intermediate buffer and output as a
    /// followup step)
    fn write_u8(&mut self, v: u8) -> Result<(), core::fmt::Error> {
        write!(self, "{:x}", v)
    }
    /// write a u16 to the output as a base-16 integer.
    ///
    /// this is provided for optimization opportunities when the formatted integer can be written
    /// directly to the sink (rather than formatted to an intermediate buffer and output as a
    /// followup step)
    fn write_u16(&mut self, v: u16) -> Result<(), core::fmt::Error> {
        write!(self, "{:x}", v)
    }
    /// write a u32 to the output as a base-16 integer.
    ///
    /// this is provided for optimization opportunities when the formatted integer can be written
    /// directly to the sink (rather than formatted to an intermediate buffer and output as a
    /// followup step)
    fn write_u32(&mut self, v: u32) -> Result<(), core::fmt::Error> {
        write!(self, "{:x}", v)
    }
    /// write a u64 to the output as a base-16 integer.
    ///
    /// this is provided for optimization opportunities when the formatted integer can be written
    /// directly to the sink (rather than formatted to an intermediate buffer and output as a
    /// followup step)
    fn write_u64(&mut self, v: u64) -> Result<(), core::fmt::Error> {
        write!(self, "{:x}", v)
    }
    /// enter a region inside which output corresponds to a `ty`.
    ///
    /// the default implementation of these functions is as a no-op. this way, providing span
    /// information to a `DisplaySink` that does not want it is eliminated at compile time.
    ///
    /// spans are entered and ended in a FILO manner: a function writing to some `DisplaySink` must
    /// end spans in reverse order to when they are entered. a function sequence like
    /// `sink.span_start(Operand); sink.span_start(Immediate); sink.span_end(Operand)` is in error.
    ///
    /// a simple use of `span_start`/`span_end` might look something like:
    /// ```compile_fail
    /// sink.span_start(Operand)
    /// sink.write_char('[')
    /// sink.span_start(Register)
    /// sink.write_fixed_size("rbp")
    /// sink.span_end(Register)
    /// sink.write_char(']')
    /// sink.span_end(Operand)
    /// ```
    /// which writes the text `[rbp]`, with span indicators where the operand (`[ ... ]`) begins,
    /// as well as the start and end of a register name.
    fn span_start(&mut self, _ty: TokenType) { }
    /// end a region where a `ty` was written. see docs on [`DisplaySink::span_start`] for more.
    fn span_end(&mut self, _ty: TokenType) { }
}

pub struct NoColorsSink<'a, T: fmt::Write> {
    pub out: &'a mut T,
}

impl<'a, T: fmt::Write> DisplaySink for NoColorsSink<'a, T> {
    fn span_start(&mut self, _ty: TokenType) { }
    fn span_end(&mut self, _ty: TokenType) { }
}

impl<'a, T: fmt::Write> fmt::Write for NoColorsSink<'a, T> {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.out.write_str(s)
    }
    fn write_char(&mut self, c: char) -> Result<(), core::fmt::Error> {
        self.out.write_char(c)
    }
    fn write_fmt(&mut self, f: fmt::Arguments) -> Result<(), core::fmt::Error> {
        self.out.write_fmt(f)
    }
}

/// this is an implementation detail of yaxpeax-arch and related crates. if you are a user of the
/// disassemblers, do not use this struct. do not depend on this struct existing. this struct is
/// not stable. this struct is not safe for general use. if you use this struct you and your
/// program will be eaten by gremlins.
///
/// if you are implementing an instruction formatter for the yaxpeax family of crates: this struct
/// is guaranteed to contain a string that is long enough to hold a fully-formatted instruction.
/// because the buffer is guaranteed to be long enough, writes through `InstructionTextSink` are
/// not bounds-checked, and the buffer is never grown.
///
/// this is wildly dangerous in general use. the public constructor of `InstructionTextSink` is
/// unsafe as a result. as used in `InstructionFormatter`, the buffer is guaranteed to be
/// `clear()`ed before use, `InstructionFormatter` ensures the buffer is large enough, *and*
/// `InstructionFormatter` never allows `InstructionTextSink` to exist in a context where it would
/// be written to without being rewound first.
///
/// because this opens a very large hole through which `fmt::Write` can become unsafe, incorrect
/// uses of this struct will be hard to debug in general. `InstructionFormatter` is probably at the
/// limit of easily-reasoned-about lifecycle of the buffer, which "only" leaves the problem of
/// ensuring that instruction formatting impls this buffer is passed to are appropriately sized.
///
/// this is intended to be hidden in docs. if you see this in docs, it's a bug.
#[doc(hidden)]
pub(crate) struct InstructionTextSink<'buf> {
    buf: &'buf mut alloc::string::String
}

impl<'buf> InstructionTextSink<'buf> {
    pub unsafe fn new(buf: &'buf mut alloc::string::String) -> Self {
        Self { buf }
    }
}

impl<'buf> fmt::Write for InstructionTextSink<'buf> {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.buf.write_str(s)
    }
    fn write_char(&mut self, c: char) -> Result<(), core::fmt::Error> {
        if cfg!(debug_assertions) {
            if self.buf.capacity() < self.buf.len() + 1 {
                panic!("InstructionTextSink::write_char would overflow output");
            }
        }
        // SAFETY: `buf` is assumed to be long enough to hold all input, `buf` at `underlying.len()`
        // is valid for writing, but may be uninitialized.
        //
        // this function is essentially equivalent to `Vec::push` specialized for the case that
        // `len < buf.capacity()`:
        // https://github.com/rust-lang/rust/blob/be9e27e/library/alloc/src/vec/mod.rs#L1993-L2006
        unsafe {
            let underlying = self.buf.as_mut_vec();
            // `InstructionTextSink::write_char` is only used by yaxpeax-x86, and is only used to
            // write single ASCII characters. this is wrong in the general case, but `write_char`
            // here is not going to be used in the general case.
            if cfg!(debug_asertions) {
                panic!("InstructionTextSink::write_char would truncate output");
            }
            let to_push = c as u8;
            // `ptr::write` here because `underlying.add(underlying.len())` may not point to an
            // initialized value, which would mean that turning that pointer into a `&mut u8` to
            // store through would be UB. `ptr::write` avoids taking the mut ref.
            underlying.as_mut_ptr().offset(underlying.len() as isize).write(to_push);
            // we have initialized all (one) bytes that `set_len` is increasing the length to
            // include.
            underlying.set_len(underlying.len() + 1);
        }
        Ok(())
    }
}

/// this DisplaySink impl exists to support somewhat more performant buffering of the kinds of
/// strings `yaxpeax-x86` uses in formatting instructions.
impl DisplaySink for alloc::string::String {
    #[inline(always)]
    fn write_fixed_size(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.reserve(s.len());
        let buf = unsafe { self.as_mut_vec() };
        let new_bytes = s.as_bytes();

        if new_bytes.len() == 0 {
            unsafe { unreachable_kinda_unchecked() }
        }

        if new_bytes.len() >= 16 {
            unsafe { unreachable_kinda_unchecked() }
        }

        unsafe {
            let dest = buf.as_mut_ptr().offset(buf.len() as isize);

            // this used to be enough to bamboozle llvm away from
            // https://github.com/rust-lang/rust/issues/92993#issuecomment-2028915232
            // if `s` is not fixed size. somewhere between Rust 1.68 and Rust 1.74 this stopped
            // being sufficient, so `write_fixed_size` truly should only be used for fixed size `s`
            // (otherwise this is a libc memcpy call in disguise). for fixed-size strings this
            // unrolls into some kind of appropriate series of `mov`.
            dest.offset(0 as isize).write(new_bytes[0]);
            for i in 1..new_bytes.len() {
                dest.offset(i as isize).write(new_bytes[i]);
            }

            buf.set_len(buf.len() + new_bytes.len());
        }

        Ok(())
    }
    unsafe fn write_lt_32(&mut self, s: &str) -> Result<(), fmt::Error> {
        self.reserve(s.len());

        // SAFETY: todo
        let buf = unsafe { self.as_mut_vec() };
        let new_bytes = s.as_bytes();

        // should get DCE
        if new_bytes.len() >= 32 {
            unsafe { core::hint::unreachable_unchecked() }
        }

        unsafe {
            let dest = buf.as_mut_ptr().offset(buf.len() as isize);
            let src = new_bytes.as_ptr();

            let rem = new_bytes.len() as isize;

            // set_len early because there is no way to avoid the following asm!() writing that
            // same number of bytes into buf
            buf.set_len(buf.len() + new_bytes.len());

            core::arch::asm!(
                "6:",
                "cmp {rem:e}, 16",
                "jb 7f",
                "mov {buf:r}, qword ptr [{src} + {rem} - 16]",
                "mov qword ptr [{dest} + {rem} - 16], {buf:r}",
                "mov {buf:r}, qword ptr [{src} + {rem} - 8]",
                "mov qword ptr [{dest} + {rem} - 8], {buf:r}",
                "sub {rem:e}, 16",
                "jz 11f",
                "7:",
                "cmp {rem:e}, 8",
                "jb 8f",
                "mov {buf:r}, qword ptr [{src} + {rem} - 8]",
                "mov qword ptr [{dest} + {rem} - 8], {buf:r}",
                "sub {rem:e}, 8",
                "jz 11f",
                "8:",
                "cmp {rem:e}, 4",
                "jb 9f",
                "mov {buf:e}, dword ptr [{src} + {rem} - 4]",
                "mov dword ptr [{dest} + {rem} - 4], {buf:e}",
                "sub {rem:e}, 4",
                "jz 11f",
                "9:",
                "cmp {rem:e}, 2",
                "jb 10f",
                "mov {buf:x}, word ptr [{src} + {rem} - 2]",
                "mov word ptr [{dest} + {rem} - 2], {buf:x}",
                "sub {rem:e}, 2",
                "jz 11f",
                "10:",
                "cmp {rem:e}, 1",
                "jb 11f",
                "mov {buf:l}, byte ptr [{src} + {rem} - 1]",
                "mov byte ptr [{dest} + {rem} - 1], {buf:l}",
                "11:",
                src = in(reg) src,
                dest = in(reg) dest,
                rem = inout(reg) rem => _,
                buf = out(reg) _,
                options(nostack),
            );
        }
        /*
        for i in 0..new_bytes.len() {
            unsafe {
                buf.as_mut_ptr().offset(buf.len() as isize).offset(i as isize).write_volatile(new_bytes[i]);
            }
        }
        */

        Ok(())
    }
    unsafe fn write_lt_16(&mut self, s: &str) -> Result<(), fmt::Error> {
        self.reserve(s.len());

        // SAFETY: todo
        let buf = unsafe { self.as_mut_vec() };
        let new_bytes = s.as_bytes();

        // should get DCE
        if new_bytes.len() >= 16 {
            unsafe { core::hint::unreachable_unchecked() }
        }

        unsafe {
            let dest = buf.as_mut_ptr().offset(buf.len() as isize);
            let src = new_bytes.as_ptr();

            let rem = new_bytes.len() as isize;

            // set_len early because there is no way to avoid the following asm!() writing that
            // same number of bytes into buf
            buf.set_len(buf.len() + new_bytes.len());

            core::arch::asm!(
                "7:",
                "cmp {rem:e}, 8",
                "jb 8f",
                "mov {buf:r}, qword ptr [{src} + {rem} - 8]",
                "mov qword ptr [{dest} + {rem} - 8], {buf:r}",
                "sub {rem:e}, 8",
                "jz 11f",
                "8:",
                "cmp {rem:e}, 4",
                "jb 9f",
                "mov {buf:e}, dword ptr [{src} + {rem} - 4]",
                "mov dword ptr [{dest} + {rem} - 4], {buf:e}",
                "sub {rem:e}, 4",
                "jz 11f",
                "9:",
                "cmp {rem:e}, 2",
                "jb 10f",
                "mov {buf:x}, word ptr [{src} + {rem} - 2]",
                "mov word ptr [{dest} + {rem} - 2], {buf:x}",
                "sub {rem:e}, 2",
                "jz 11f",
                "10:",
                "cmp {rem:e}, 1",
                "jb 11f",
                "mov {buf:l}, byte ptr [{src} + {rem} - 1]",
                "mov byte ptr [{dest} + {rem} - 1], {buf:l}",
                "11:",
                src = in(reg) src,
                dest = in(reg) dest,
                rem = inout(reg) rem => _,
                buf = out(reg) _,
                options(nostack),
            );
        }
        /*
        for i in 0..new_bytes.len() {
            unsafe {
                buf.as_mut_ptr().offset(buf.len() as isize).offset(i as isize).write_volatile(new_bytes[i]);
            }
        }
        */

        Ok(())
    }
    unsafe fn write_lt_8(&mut self, s: &str) -> Result<(), fmt::Error> {
        self.reserve(s.len());

        // SAFETY: todo
        let buf = unsafe { self.as_mut_vec() };
        let new_bytes = s.as_bytes();

        // should get DCE
        if new_bytes.len() >= 8 {
            unsafe { core::hint::unreachable_unchecked() }
        }

        unsafe {
            let dest = buf.as_mut_ptr().offset(buf.len() as isize);
            let src = new_bytes.as_ptr();

            let rem = new_bytes.len() as isize;

            // set_len early because there is no way to avoid the following asm!() writing that
            // same number of bytes into buf
            buf.set_len(buf.len() + new_bytes.len());

            core::arch::asm!(
                "8:",
                "cmp {rem:e}, 4",
                "jb 9f",
                "mov {buf:e}, dword ptr [{src} + {rem} - 4]",
                "mov dword ptr [{dest} + {rem} - 4], {buf:e}",
                "sub {rem:e}, 4",
                "jz 11f",
                "9:",
                "cmp {rem:e}, 2",
                "jb 10f",
                "mov {buf:x}, word ptr [{src} + {rem} - 2]",
                "mov word ptr [{dest} + {rem} - 2], {buf:x}",
                "sub {rem:e}, 2",
                "jz 11f",
                "10:",
                "cmp {rem:e}, 1",
                "jb 11f",
                "mov {buf:l}, byte ptr [{src} + {rem} - 1]",
                "mov byte ptr [{dest} + {rem} - 1], {buf:l}",
                "11:",
                src = in(reg) src,
                dest = in(reg) dest,
                rem = inout(reg) rem => _,
                buf = out(reg) _,
                options(nostack),
            );
        }
        /*
        for i in 0..new_bytes.len() {
            unsafe {
                buf.as_mut_ptr().offset(buf.len() as isize).offset(i as isize).write_volatile(new_bytes[i]);
            }
        }
        */

        Ok(())
    }
    /// write a u8 to the output as a base-16 integer.
    ///
    /// this is provided for optimization opportunities when the formatted integer can be written
    /// directly to the sink (rather than formatted to an intermediate buffer and output as a
    /// followup step)
    #[inline(always)]
    fn write_u8(&mut self, mut v: u8) -> Result<(), core::fmt::Error> {
        if v == 0 {
            return self.write_fixed_size("0");
        }
        // we can fairly easily predict the size of a formatted string here with lzcnt, which also
        // means we can write directly into the correct offsets of the output string.
        let printed_size = ((8 - v.leading_zeros() + 3) >> 2) as usize;

        self.reserve(printed_size);

        let buf = unsafe { self.as_mut_vec() };
        let new_len = buf.len() + printed_size;

        unsafe {
            buf.set_len(new_len);
        }
        let mut p = unsafe { buf.as_mut_ptr().offset(new_len as isize) };

        loop {
            let digit = v % 16;
            let c = c_to_hex(digit as u8);
            unsafe {
                p = p.offset(-1);
                p.write(c);
            }
            v = v / 16;
            if v == 0 {
                break;
            }
        }

        Ok(())
    }
    /// write a u16 to the output as a base-16 integer.
    ///
    /// this is provided for optimization opportunities when the formatted integer can be written
    /// directly to the sink (rather than formatted to an intermediate buffer and output as a
    /// followup step)
    #[inline(always)]
    fn write_u16(&mut self, mut v: u16) -> Result<(), core::fmt::Error> {
        if v == 0 {
            return self.write_fixed_size("0");
        }
        // we can fairly easily predict the size of a formatted string here with lzcnt, which also
        // means we can write directly into the correct offsets of the output string.
        let printed_size = ((16 - v.leading_zeros() + 3) >> 2) as usize;

        self.reserve(printed_size);

        let buf = unsafe { self.as_mut_vec() };
        let new_len = buf.len() + printed_size;

        unsafe {
            buf.set_len(new_len);
        }
        let mut p = unsafe { buf.as_mut_ptr().offset(new_len as isize) };

        loop {
            let digit = v % 16;
            let c = c_to_hex(digit as u8);
            unsafe {
                p = p.offset(-1);
                p.write(c);
            }
            v = v / 16;
            if v == 0 {
                break;
            }
        }

        Ok(())
    }
    /// write a u32 to the output as a base-16 integer.
    ///
    /// this is provided for optimization opportunities when the formatted integer can be written
    /// directly to the sink (rather than formatted to an intermediate buffer and output as a
    /// followup step)
    #[inline(always)]
    fn write_u32(&mut self, mut v: u32) -> Result<(), core::fmt::Error> {
        if v == 0 {
            return self.write_fixed_size("0");
        }
        // we can fairly easily predict the size of a formatted string here with lzcnt, which also
        // means we can write directly into the correct offsets of the output string.
        let printed_size = ((32 - v.leading_zeros() + 3) >> 2) as usize;

        self.reserve(printed_size);

        let buf = unsafe { self.as_mut_vec() };
        let new_len = buf.len() + printed_size;

        unsafe {
            buf.set_len(new_len);
        }
        let mut p = unsafe { buf.as_mut_ptr().offset(new_len as isize) };

        loop {
            let digit = v % 16;
            let c = c_to_hex(digit as u8);
            unsafe {
                p = p.offset(-1);
                p.write(c);
            }
            v = v / 16;
            if v == 0 {
                break;
            }
        }

        Ok(())
    }
    /// write a u64 to the output as a base-16 integer.
    ///
    /// this is provided for optimization opportunities when the formatted integer can be written
    /// directly to the sink (rather than formatted to an intermediate buffer and output as a
    /// followup step)
    #[inline(always)]
    fn write_u64(&mut self, mut v: u64) -> Result<(), core::fmt::Error> {
        if v == 0 {
            return self.write_fixed_size("0");
        }
        // we can fairly easily predict the size of a formatted string here with lzcnt, which also
        // means we can write directly into the correct offsets of the output string.
        let printed_size = ((64 - v.leading_zeros() + 3) >> 2) as usize;

        self.reserve(printed_size);

        let buf = unsafe { self.as_mut_vec() };
        let new_len = buf.len() + printed_size;

        unsafe {
            buf.set_len(new_len);
        }
        let mut p = unsafe { buf.as_mut_ptr().offset(new_len as isize) };

        loop {
            let digit = v % 16;
            let c = c_to_hex(digit as u8);
            unsafe {
                p = p.offset(-1);
                p.write(c);
            }
            v = v / 16;
            if v == 0 {
                break;
            }
        }

        Ok(())
    }
    fn span_start(&mut self, _ty: TokenType) {}
    fn span_end(&mut self, _ty: TokenType) {}
}

impl<'buf> DisplaySink for InstructionTextSink<'buf> {
    #[inline(always)]
    fn write_fixed_size(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        if cfg!(debug_assertions) {
            if self.buf.capacity() < self.buf.len() + s.len() {
                panic!("InstructionTextSink::write_fixed_size would overflow output");
            }
        }

        let buf = unsafe { self.buf.as_mut_vec() };
        let new_bytes = s.as_bytes();

        if new_bytes.len() == 0 {
            return Ok(());
        }

        if new_bytes.len() >= 16 {
            unsafe { unreachable_kinda_unchecked() }
        }

        unsafe {
            let dest = buf.as_mut_ptr().offset(buf.len() as isize);

            // this used to be enough to bamboozle llvm away from
            // https://github.com/rust-lang/rust/issues/92993#issuecomment-2028915232https://github.com/rust-lang/rust/issues/92993#issuecomment-2028915232
            // if `s` is not fixed size. somewhere between Rust 1.68 and Rust 1.74 this stopped
            // being sufficient, so `write_fixed_size` truly should only be used for fixed size `s`
            // (otherwise this is a libc memcpy call in disguise). for fixed-size strings this
            // unrolls into some kind of appropriate series of `mov`.
            dest.offset(0 as isize).write(new_bytes[0]);
            for i in 1..new_bytes.len() {
                dest.offset(i as isize).write(new_bytes[i]);
            }

            buf.set_len(buf.len() + new_bytes.len());
        }

        Ok(())
    }
    unsafe fn write_lt_32(&mut self, s: &str) -> Result<(), fmt::Error> {
        if cfg!(debug_assertions) {
            if self.buf.capacity() < self.buf.len() + s.len() {
                panic!("InstructionTextSink::write_lt_32 would overflow output");
            }
        }

        // SAFETY: todo
        let buf = unsafe { self.buf.as_mut_vec() };
        let new_bytes = s.as_bytes();

        // should get DCE
        if new_bytes.len() >= 32 {
            unsafe { core::hint::unreachable_unchecked() }
        }

        unsafe {
            let dest = buf.as_mut_ptr().offset(buf.len() as isize);
            let src = new_bytes.as_ptr();

            let rem = new_bytes.len() as isize;

            // set_len early because there is no way to avoid the following asm!() writing that
            // same number of bytes into buf
            buf.set_len(buf.len() + new_bytes.len());

            core::arch::asm!(
                "6:",
                "cmp {rem:e}, 16",
                "jb 7f",
                "mov {buf:r}, qword ptr [{src} + {rem} - 16]",
                "mov qword ptr [{dest} + {rem} - 16], {buf:r}",
                "mov {buf:r}, qword ptr [{src} + {rem} - 8]",
                "mov qword ptr [{dest} + {rem} - 8], {buf:r}",
                "sub {rem:e}, 16",
                "jz 11f",
                "7:",
                "cmp {rem:e}, 8",
                "jb 8f",
                "mov {buf:r}, qword ptr [{src} + {rem} - 8]",
                "mov qword ptr [{dest} + {rem} - 8], {buf:r}",
                "sub {rem:e}, 8",
                "jz 11f",
                "8:",
                "cmp {rem:e}, 4",
                "jb 9f",
                "mov {buf:e}, dword ptr [{src} + {rem} - 4]",
                "mov dword ptr [{dest} + {rem} - 4], {buf:e}",
                "sub {rem:e}, 4",
                "jz 11f",
                "9:",
                "cmp {rem:e}, 2",
                "jb 10f",
                "mov {buf:x}, word ptr [{src} + {rem} - 2]",
                "mov word ptr [{dest} + {rem} - 2], {buf:x}",
                "sub {rem:e}, 2",
                "jz 11f",
                "10:",
                "cmp {rem:e}, 1",
                "jb 11f",
                "mov {buf:l}, byte ptr [{src} + {rem} - 1]",
                "mov byte ptr [{dest} + {rem} - 1], {buf:l}",
                "11:",
                src = in(reg) src,
                dest = in(reg) dest,
                rem = inout(reg) rem => _,
                buf = out(reg) _,
                options(nostack),
            );
        }
        /*
        for i in 0..new_bytes.len() {
            unsafe {
                buf.as_mut_ptr().offset(buf.len() as isize).offset(i as isize).write_volatile(new_bytes[i]);
            }
        }
        */

        Ok(())
    }
    unsafe fn write_lt_16(&mut self, s: &str) -> Result<(), fmt::Error> {
        if cfg!(debug_assertions) {
            if self.buf.capacity() < self.buf.len() + s.len() {
                panic!("InstructionTextSink::write_lt_16 would overflow output");
            }
        }

        // SAFETY: todo
        let buf = unsafe { self.buf.as_mut_vec() };
        let new_bytes = s.as_bytes();

        // should get DCE
        if new_bytes.len() >= 16 {
            unsafe { core::hint::unreachable_unchecked() }
        }

        unsafe {
            let dest = buf.as_mut_ptr().offset(buf.len() as isize);
            let src = new_bytes.as_ptr();

            let rem = new_bytes.len() as isize;

            // set_len early because there is no way to avoid the following asm!() writing that
            // same number of bytes into buf
            buf.set_len(buf.len() + new_bytes.len());

            core::arch::asm!(
                "7:",
                "cmp {rem:e}, 8",
                "jb 8f",
                "mov {buf:r}, qword ptr [{src} + {rem} - 8]",
                "mov qword ptr [{dest} + {rem} - 8], {buf:r}",
                "sub {rem:e}, 8",
                "jz 11f",
                "8:",
                "cmp {rem:e}, 4",
                "jb 9f",
                "mov {buf:e}, dword ptr [{src} + {rem} - 4]",
                "mov dword ptr [{dest} + {rem} - 4], {buf:e}",
                "sub {rem:e}, 4",
                "jz 11f",
                "9:",
                "cmp {rem:e}, 2",
                "jb 10f",
                "mov {buf:x}, word ptr [{src} + {rem} - 2]",
                "mov word ptr [{dest} + {rem} - 2], {buf:x}",
                "sub {rem:e}, 2",
                "jz 11f",
                "10:",
                "cmp {rem:e}, 1",
                "jb 11f",
                "mov {buf:l}, byte ptr [{src} + {rem} - 1]",
                "mov byte ptr [{dest} + {rem} - 1], {buf:l}",
                "11:",
                src = in(reg) src,
                dest = in(reg) dest,
                rem = inout(reg) rem => _,
                buf = out(reg) _,
                options(nostack),
            );
        }
        /*
        for i in 0..new_bytes.len() {
            unsafe {
                buf.as_mut_ptr().offset(buf.len() as isize).offset(i as isize).write_volatile(new_bytes[i]);
            }
        }
        */

        Ok(())
    }
    unsafe fn write_lt_8(&mut self, s: &str) -> Result<(), fmt::Error> {
        if cfg!(debug_assertions) {
            if self.buf.capacity() < self.buf.len() + s.len() {
                panic!("InstructionTextSink::write_lt_8 would overflow output");
            }
        }

        // SAFETY: todo
        let buf = unsafe { self.buf.as_mut_vec() };
        let new_bytes = s.as_bytes();

        // should get DCE
        if new_bytes.len() >= 8 {
            unsafe { core::hint::unreachable_unchecked() }
        }

        unsafe {
            let dest = buf.as_mut_ptr().offset(buf.len() as isize);
            let src = new_bytes.as_ptr();

            let rem = new_bytes.len() as isize;

            // set_len early because there is no way to avoid the following asm!() writing that
            // same number of bytes into buf
            buf.set_len(buf.len() + new_bytes.len());

            core::arch::asm!(
                "8:",
                "cmp {rem:e}, 4",
                "jb 9f",
                "mov {buf:e}, dword ptr [{src} + {rem} - 4]",
                "mov dword ptr [{dest} + {rem} - 4], {buf:e}",
                "sub {rem:e}, 4",
                "jz 11f",
                "9:",
                "cmp {rem:e}, 2",
                "jb 10f",
                "mov {buf:x}, word ptr [{src} + {rem} - 2]",
                "mov word ptr [{dest} + {rem} - 2], {buf:x}",
                "sub {rem:e}, 2",
                "jz 11f",
                "10:",
                "cmp {rem:e}, 1",
                "jb 11f",
                "mov {buf:l}, byte ptr [{src} + {rem} - 1]",
                "mov byte ptr [{dest} + {rem} - 1], {buf:l}",
                "11:",
                src = in(reg) src,
                dest = in(reg) dest,
                rem = inout(reg) rem => _,
                buf = out(reg) _,
                options(nostack),
            );
        }
        /*
        for i in 0..new_bytes.len() {
            unsafe {
                buf.as_mut_ptr().offset(buf.len() as isize).offset(i as isize).write_volatile(new_bytes[i]);
            }
        }
        */

        Ok(())
    }
    /// write a u8 to the output as a base-16 integer.
    ///
    /// this is provided for optimization opportunities when the formatted integer can be written
    /// directly to the sink (rather than formatted to an intermediate buffer and output as a
    /// followup step)
    #[inline(always)]
    fn write_u8(&mut self, mut v: u8) -> Result<(), core::fmt::Error> {
        if v == 0 {
            return self.write_fixed_size("0");
        }
        // we can fairly easily predict the size of a formatted string here with lzcnt, which also
        // means we can write directly into the correct offsets of the output string.
        let printed_size = ((8 - v.leading_zeros() + 3) >> 2) as usize;

        if cfg!(debug_assertions) {
            if self.buf.capacity() < self.buf.len() + printed_size {
                panic!("InstructionTextSink::write_u8 would overflow output");
            }
        }

        let buf = unsafe { self.buf.as_mut_vec() };
        let new_len = buf.len() + printed_size;

        unsafe {
            buf.set_len(new_len);
        }
        let mut p = unsafe { buf.as_mut_ptr().offset(new_len as isize) };

        loop {
            let digit = v % 16;
            let c = c_to_hex(digit as u8);
            unsafe {
                p = p.offset(-1);
                p.write(c);
            }
            v = v / 16;
            if v == 0 {
                break;
            }
        }

        Ok(())
    }
    /// write a u16 to the output as a base-16 integer.
    ///
    /// this is provided for optimization opportunities when the formatted integer can be written
    /// directly to the sink (rather than formatted to an intermediate buffer and output as a
    /// followup step)
    #[inline(always)]
    fn write_u16(&mut self, mut v: u16) -> Result<(), core::fmt::Error> {
        if v == 0 {
            return self.write_fixed_size("0");
        }

        // we can fairly easily predict the size of a formatted string here with lzcnt, which also
        // means we can write directly into the correct offsets of the output string.
        let printed_size = ((16 - v.leading_zeros() + 3) >> 2) as usize;

        if cfg!(debug_assertions) {
            if self.buf.capacity() < self.buf.len() + printed_size {
                panic!("InstructionTextSink::write_u16 would overflow output");
            }
        }

        let buf = unsafe { self.buf.as_mut_vec() };
        let new_len = buf.len() + printed_size;

        unsafe {
            buf.set_len(new_len);
        }
        let mut p = unsafe { buf.as_mut_ptr().offset(new_len as isize) };

        loop {
            let digit = v % 16;
            let c = c_to_hex(digit as u8);
            unsafe {
                p = p.offset(-1);
                p.write(c);
            }
            v = v / 16;
            if v == 0 {
                break;
            }
        }

        Ok(())
    }
    /// write a u32 to the output as a base-16 integer.
    ///
    /// this is provided for optimization opportunities when the formatted integer can be written
    /// directly to the sink (rather than formatted to an intermediate buffer and output as a
    /// followup step)
    #[inline(always)]
    fn write_u32(&mut self, mut v: u32) -> Result<(), core::fmt::Error> {
        if v == 0 {
            return self.write_fixed_size("0");
        }

        // we can fairly easily predict the size of a formatted string here with lzcnt, which also
        // means we can write directly into the correct offsets of the output string.
        let printed_size = ((32 - v.leading_zeros() + 3) >> 2) as usize;

        if cfg!(debug_assertions) {
            if self.buf.capacity() < self.buf.len() + printed_size {
                panic!("InstructionTextSink::write_u32 would overflow output");
            }
        }

        let buf = unsafe { self.buf.as_mut_vec() };
        let new_len = buf.len() + printed_size;

        unsafe {
            buf.set_len(new_len);
        }
        let mut p = unsafe { buf.as_mut_ptr().offset(new_len as isize) };

        loop {
            let digit = v % 16;
            let c = c_to_hex(digit as u8);
            unsafe {
                p = p.offset(-1);
                p.write(c);
            }
            v = v / 16;
            if v == 0 {
                break;
            }
        }

        Ok(())
    }
    /// write a u64 to the output as a base-16 integer.
    ///
    /// this is provided for optimization opportunities when the formatted integer can be written
    /// directly to the sink (rather than formatted to an intermediate buffer and output as a
    /// followup step)
    #[inline(always)]
    fn write_u64(&mut self, mut v: u64) -> Result<(), core::fmt::Error> {
        if v == 0 {
            return self.write_fixed_size("0");
        }

        // we can fairly easily predict the size of a formatted string here with lzcnt, which also
        // means we can write directly into the correct offsets of the output string.
        let printed_size = ((64 - v.leading_zeros() + 3) >> 2) as usize;

        if cfg!(debug_assertions) {
            if self.buf.capacity() < self.buf.len() + printed_size {
                panic!("InstructionTextSink::write_u64 would overflow output");
            }
        }

        let buf = unsafe { self.buf.as_mut_vec() };
        let new_len = buf.len() + printed_size;

        unsafe {
            buf.set_len(new_len);
        }
        let mut p = unsafe { buf.as_mut_ptr().offset(new_len as isize) };

        loop {
            let digit = v % 16;
            let c = c_to_hex(digit as u8);
            unsafe {
                p = p.offset(-1);
                p.write(c);
            }
            v = v / 16;
            if v == 0 {
                break;
            }
        }

        Ok(())
    }
    fn span_start(&mut self, _ty: TokenType) {}
    fn span_end(&mut self, _ty: TokenType) {}
}
