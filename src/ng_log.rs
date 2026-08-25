use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::config::LogConfig;

/// Initialize the global logger. Call once at startup before any log macros.
pub fn init(config: &LogConfig) -> Result<(), SetLoggerError> {
    let level = parse_level(&config.level);

    let rotating = config.file.as_ref().map(|path| {
        let r = RotatingFile::new(
            PathBuf::from(path),
            config.max_size,
            config.max_files,
        );
        r
    });

    let logger = NekoLogger {
        level,
        file: rotating.map(|r| Mutex::new(r)),
        requests: config.requests,
    };

    log::set_logger(Box::leak(Box::new(logger)))?;
    log::set_max_level(level);
    Ok(())
}

fn parse_level(s: &str) -> LevelFilter {
    match s.to_ascii_lowercase().as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => {
            eprintln!("unknown log level '{s}', defaulting to info");
            LevelFilter::Info
        }
    }
}

struct NekoLogger {
    level: LevelFilter,
    file: Option<Mutex<RotatingFile>>,
    requests: bool,
}

impl Log for NekoLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let ts = timestamp();
        let level = match record.level() {
            Level::Error => "ERROR",
            Level::Warn => "WARN ",
            Level::Info => "INFO ",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        };
        let msg = format!("[{ts}] [{level}] {}\n", record.args());

        // Always write to stderr
        eprint!("{msg}");

        // Write to file if configured
        if let Some(file) = &self.file {
            if let Ok(mut f) = file.lock() {
                f.write_all(msg.as_bytes());
            }
        }
    }

    fn flush(&self) {
        if let Some(file) = &self.file {
            if let Ok(mut f) = file.lock() {
                f.flush();
            }
        }
    }
}

pub fn request_log(
    method: &str,
    path: &str,
    status: u16,
    host: &str,
    upstream: &str,
    elapsed_ms: u64,
) {
    if !log::log_enabled!(Level::Info) {
        return;
    }
    log::info!(
        "{} {} → {} ({} → {}) {}ms",
        method,
        path,
        status,
        host,
        upstream,
        elapsed_ms
    );
}

pub fn ws_log(host: &str, upstream: &str, path: &str) {
    log::info!("WS upgrade {} {} → {}", host, path, upstream);
}

fn timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = now / 86400;
    let secs = now % 86400;
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;

    // Approximate Y-M-D from epoch days (good enough for log timestamps)
    let (y, mo, d) = epoch_days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

fn epoch_days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Simple civil calendar from epoch days
    let mut y = 1970u64;
    let mut remaining = days;
    loop {
        let year_days = if is_leap(y) { 366 } else { 365 };
        if remaining < year_days {
            break;
        }
        remaining -= year_days;
        y += 1;
    }
    let leap = is_leap(y);
    let month_days: [u64; 12] = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut m = 1u64;
    for &md in &month_days {
        if remaining < md {
            break;
        }
        remaining -= md;
        m += 1;
    }
    (y, m, remaining + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ── Rotating file writer ─────────────────────────────────────────

struct RotatingFile {
    path: PathBuf,
    file: Option<File>,
    size: u64,
    max_size: u64,
    max_files: u32,
}

impl RotatingFile {
    fn new(path: PathBuf, max_size: u64, max_files: u32) -> Self {
        let mut rf = RotatingFile {
            path,
            file: None,
            size: 0,
            max_size,
            max_files,
        };
        rf.open();
        rf
    }

    fn open(&mut self) {
        // Check existing file size
        self.size = fs::metadata(&self.path)
            .map(|m| m.len())
            .unwrap_or(0);

        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .ok();
    }

    fn write_all(&mut self, buf: &[u8]) {
        if self.size + buf.len() as u64 > self.max_size && self.size > 0 {
            self.rotate();
        }

        if let Some(f) = &mut self.file {
            let _ = f.write_all(buf);
            self.size += buf.len() as u64;
        }
    }

    fn flush(&mut self) {
        if let Some(f) = &mut self.file {
            let _ = f.flush();
        }
    }

    fn rotate(&mut self) {
        // Close current file
        self.file = None;

        // Shift .N → .N+1 (delete oldest beyond max_files)
        for i in (1..=self.max_files).rev() {
            let from = self.path_with_suffix(i);
            let to = self.path_with_suffix(i + 1);
            if from.exists() {
                if i == self.max_files {
                    let _ = fs::remove_file(&from);
                } else {
                    let _ = fs::rename(&from, &to);
                }
            }
        }

        // Rename current → .1
        let first = self.path_with_suffix(1);
        if self.path.exists() {
            let _ = fs::rename(&self.path, &first);
        }

        // Open fresh file
        self.size = 0;
        self.open();
    }

    fn path_with_suffix(&self, n: u32) -> PathBuf {
        let p = self.path.to_string_lossy().to_string();
        PathBuf::from(format!("{p}.{n}"))
    }
}

impl Drop for RotatingFile {
    fn drop(&mut self) {
        self.flush();
    }
}
