//! Routes the core's `log` records to a C callback (stderr, nxlink, SD card).

use core::ffi::c_char;
use core::fmt::Write;
use core::sync::atomic::{AtomicPtr, Ordering};

/// `level`: 1 error, 2 warn, 3 info, 4 debug, 5 trace. `msg` is NUL-terminated
/// and only valid during the call.
pub type TsnxLogFn = unsafe extern "C" fn(level: u32, msg: *const c_char);

static CALLBACK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

struct CLogger;

impl log::Log for CLogger {
    fn enabled(&self, _: &log::Metadata) -> bool {
        !CALLBACK.load(Ordering::Relaxed).is_null()
    }

    fn log(&self, record: &log::Record) {
        let cb = CALLBACK.load(Ordering::Acquire);
        if cb.is_null() {
            return;
        }
        // Fixed buffer: logging must not allocate.
        let mut buf = Buf { b: [0; 512], n: 0 };
        let _ = write!(buf, "{}: {}", record.target(), record.args());
        let n = buf.n.min(buf.b.len() - 1);
        buf.b[n] = 0;
        let f: TsnxLogFn = unsafe { core::mem::transmute(cb) };
        unsafe { f(record.level() as u32, buf.b.as_ptr().cast()) };
    }

    fn flush(&self) {}
}

struct Buf {
    b: [u8; 512],
    n: usize,
}

impl Write for Buf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let room = self.b.len() - 1 - self.n.min(self.b.len() - 1);
        let take = s.len().min(room);
        self.b[self.n..self.n + take].copy_from_slice(&s.as_bytes()[..take]);
        self.n += take;
        Ok(())
    }
}

static LOGGER: CLogger = CLogger;

/// Installs `cb` for log records up to `max_level` (1-5; 0 disables).
#[no_mangle]
pub extern "C" fn tsnx_set_log_callback(cb: Option<TsnxLogFn>, max_level: u32) {
    CALLBACK.store(cb.map_or(core::ptr::null_mut(), |f| f as *mut ()), Ordering::Release);
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(match max_level {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    });
}
