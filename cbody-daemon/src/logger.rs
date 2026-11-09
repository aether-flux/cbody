use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Mutex,
};

use cbody_common::{EV_EXEC, EV_FILE, Event};
use log::{Log, Metadata, Record};

// #[derive(Clone, Debug)]
pub struct FileLogger {
    log_path: PathBuf,
}

impl FileLogger {
    pub fn new(path: &str) -> Self {
        let path = PathBuf::from(path);
        Self::ensure_file(&path);

        Self { log_path: path }
    }

    fn ensure_file(path: &PathBuf) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    pub fn write_line(&self, line: &str) {
        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
        {
            Ok(f) => f,
            Err(e) => {
                println!("Failed to open/recreate log file: {}", e);
                return;
            }
        };

        let _ = writeln!(file, "{line}");
    }
}

pub fn format_event(ev: &Event) -> String {
    let end = ev
        .path
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(ev.path.len());
    let path = String::from_utf8_lossy(&ev.path[..end]);
    let action = if ev.denied == 1 { "DENIED" } else { "ALLOWED" };

    match ev.kind {
        EV_EXEC => format!(
            "[Binary execution] [PID={}] [UID={}] [FILE={}] [ACTION={}]",
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
                "[File access ({perm})] [PID={}] [UID={}] [FILE={}] [MODE={}] [ACTION={}]",
                ev.pid, ev.uid, path, mode, action
            )
        }
        _ => format!(
            "[Port connection] [PID={}] [UID={}] [PORT={}] [FAMILY={}] [ACTION={}]",
            ev.pid, ev.uid, ev.port, ev.family, action
        ),
    }
}
