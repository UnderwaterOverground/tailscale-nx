//! Bare-metal glue for Horizon builds: the heap comes from the C runtime
//! (newlib on Horizon) and panics are handed to the platform to log and abort.

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::fmt::Write;

extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn aligned_alloc(align: usize, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);

    /// Provided by the embedding program. Must not return.
    fn tsnx_platform_panic(msg: *const u8, len: usize) -> !;
}

// newlib's malloc returns 16-byte aligned blocks on AArch64.
const MALLOC_ALIGN: usize = 16;

struct CAlloc;

fn note_alloc(n: usize) {
    crate::heap_count::alloc(n);
}

fn note_free(n: usize) {
    crate::heap_count::free(n);
}

unsafe impl GlobalAlloc for CAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p: *mut u8 = if layout.align() <= MALLOC_ALIGN {
            malloc(layout.size()).cast()
        } else {
            // aligned_alloc requires size to be a multiple of align.
            let size = layout.size().next_multiple_of(layout.align());
            aligned_alloc(layout.align(), size).cast()
        };
        if !p.is_null() {
            note_alloc(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note_free(layout.size());
        free(ptr.cast())
    }

    // Never the C realloc: libstratosphere's (Atmosphère 1.12.0,
    // CentralHeap::Reallocate) copies the new size into a block of the old
    // size class when a small block grows, corrupting the heap.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_ptr = self.alloc(new_layout);
        if !new_ptr.is_null() {
            core::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
            self.dealloc(ptr, layout);
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOC: CAlloc = CAlloc;

/// Fixed buffer so formatting a panic message never allocates.
struct PanicBuf {
    buf: [u8; 256],
    len: usize,
}

impl Write for PanicBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut out = PanicBuf { buf: [0; 256], len: 0 };
    let _ = write!(out, "{info}");
    unsafe { tsnx_platform_panic(out.buf.as_ptr(), out.len) }
}
