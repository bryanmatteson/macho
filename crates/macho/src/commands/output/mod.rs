pub mod sarif;

use std::cell::RefCell;
use std::fmt;
use std::io::Write;
use std::rc::Rc;

#[derive(Clone, Default)]
struct OutputCapture {
    stdout: Rc<RefCell<Vec<u8>>>,
    stderr: Rc<RefCell<Vec<u8>>>,
}

pub(crate) struct CaptureGuard {
    previous: Option<OutputCapture>,
    current: OutputCapture,
}

pub(crate) struct CapturedOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

thread_local! {
    static CAPTURE: RefCell<Option<OutputCapture>> = const { RefCell::new(None) };
}

pub(crate) fn begin_capture() -> CaptureGuard {
    let current = OutputCapture::default();
    let previous = CAPTURE.with(|slot| slot.replace(Some(current.clone())));
    CaptureGuard { previous, current }
}

impl CaptureGuard {
    pub(crate) fn finish(self) -> CapturedOutput {
        CapturedOutput {
            stdout: self.current.stdout.borrow().clone(),
            stderr: self.current.stderr.borrow().clone(),
        }
    }
}

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        CAPTURE.with(|slot| {
            slot.replace(self.previous.take());
        });
    }
}

#[doc(hidden)]
pub fn write_stdout(args: fmt::Arguments<'_>) {
    write_capture(Stream::Stdout, args);
}

#[doc(hidden)]
pub fn write_stderr(args: fmt::Arguments<'_>) {
    write_capture(Stream::Stderr, args);
}

enum Stream {
    Stdout,
    Stderr,
}

fn write_capture(stream: Stream, args: fmt::Arguments<'_>) {
    CAPTURE.with(|slot| {
        if let Some(capture) = slot.borrow().as_ref() {
            let mut buffer = match stream {
                Stream::Stdout => capture.stdout.borrow_mut(),
                Stream::Stderr => capture.stderr.borrow_mut(),
            };
            buffer
                .write_fmt(args)
                .expect("write to captured output buffer");
            return;
        }

        match stream {
            Stream::Stdout => std::print!("{args}"),
            Stream::Stderr => std::eprint!("{args}"),
        }
    });
}

#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => {
        $crate::commands::output::write_stdout(format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! outln {
    () => {
        $crate::commands::output::write_stdout(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::commands::output::write_stdout(format_args!("{}\n", format_args!($($arg)*)))
    };
}

#[macro_export]
macro_rules! errln {
    () => {
        $crate::commands::output::write_stderr(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::commands::output::write_stderr(format_args!("{}\n", format_args!($($arg)*)))
    };
}
