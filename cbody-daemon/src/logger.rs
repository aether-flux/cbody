use std::{
    fs::{File, OpenOptions},
    io::Write,
    sync::Mutex,
};

use cbody_common::{EV_EXEC, EV_FILE, Event};
use log::{Log, Metadata, Record};

// #[derive(Clone, Debug)]
pub struct FileLogger {
    file: Mutex<File>,
}

impl FileLogger {
    pub fn new(path: &str) -> Self {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("Failed to open log file");

        Self {
            file: Mutex::new(file),
        }
    }

    pub fn write_line(&self, line: &str) {
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "{line}");
        }
    }
}

impl Log for FileLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let mut file = self.file.lock().unwrap();
            let _ = writeln!(file, "[{}] {}", record.level(), record.args());
        }
    }

    fn flush(&self) {
        if let Ok(mut file) = self.file.lock() {
            let _ = file.flush();
        }
    }
}

pub fn format_event(ev: &Event) -> String {
    let end = ev
        .path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(ev.path.len());
    let path = String::from_utf8_lossy(&ev.path[..end]);
    let action = if ev.denied == 1 { "DENY" } else { "ALLOW" };
    match ev.kind {
        EV_EXEC => format!(
            "[INFO] Binary execution: pid={} uid={} file={} action={}",
            ev.pid, ev.uid, path, action
        ),
        EV_FILE => {
            let perm = if ev.perm == 2 { "noaccess" } else { "readonly" };
            let mode = match ev.mode {
                0 => "r",
                1 => "w",
                _ => "rw",
            };
            format!(
                "[INFO] File access ({perm}): pid={} uid={} file={} mode={} action={}",
                ev.pid, ev.uid, path, mode, action
            )
        }
        _ => format!(
            "[INFO] Port connection: pid={} uid={} port={} family={} action={}",
            ev.pid, ev.uid, ev.port, ev.family, action
        ),
    }
}
