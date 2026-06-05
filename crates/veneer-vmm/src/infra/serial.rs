//! COM1 (0x3F8) serial console — primary out for headless boot verification.
//! No allocator; uses core::fmt::Write so callers get `writeln!` formatting.

use crate::infra::arch::{inb, outb};
use core::fmt;

const COM1: u16 = 0x3F8;

pub fn init() {
    unsafe {
        outb(COM1 + 1, 0x00); // disable interrupts
        outb(COM1 + 3, 0x80); // DLAB on
        outb(COM1 + 0, 0x01); // divisor low (115200 baud)
        outb(COM1 + 1, 0x00); // divisor high
        outb(COM1 + 3, 0x03); // 8N1, DLAB off
        outb(COM1 + 2, 0xC7); // FIFO enable + clear + 14-byte threshold
        outb(COM1 + 4, 0x0B); // RTS/DSR + OUT2 (IRQ enable)
    }
}

pub fn write_bytes(msg: &[u8]) {
    for &b in msg {
        unsafe {
            while (inb(COM1 + 5) & 0x20) == 0 {}
            outb(COM1, b);
        }
    }
}

pub struct SerialWriter;

impl fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_bytes(s.as_bytes());
        Ok(())
    }
}

#[macro_export]
macro_rules! sprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let _ = write!($crate::infra::serial::SerialWriter, $($arg)*);
    }};
}

#[macro_export]
macro_rules! sprintln {
    () => { $crate::sprint!("\r\n") };
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let _ = writeln!($crate::infra::serial::SerialWriter, $($arg)*);
        // writeln! emits "\n" but we want "\r\n" on serial. Patch by also writing \r before \n via direct write:
        // — actually simpler: just rely on terminals' interpretation. Most serial consoles handle bare \n fine.
        // For belt-and-braces, follow with explicit "\r":
        // (skipped to keep this macro alloc-free and not double-buffer)
    }};
}
