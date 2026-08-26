use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::config::LogConfig;

/// Initialize the global logger. Call once at startup before any log macros.
pub fn init(config: &LogConfig) -> Result<(), SetLoggerError> {
    let level = parse_level(&config.level);

    let file = config.file.as_ref().map(|path| {
        // Ensure parent directory exists
        if let Some(parent) = PathBuf::from(path).parent() {
            let _ = fs::create_dir_all(parent);
        }
        // Start with existing size if file already exists
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .truncate(false)
            .open(path)
            .unwrap_or_else(|e| panic!("failed to open log file '{path}': {e}"));
        Mutex::new(LogFile { f, size, max_size: config.max_size, path: PathBuf::from(path) })
    });

    let logger = NekoLogger { level, file };

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

struct LogFile {
    f: std::fs::File,
    size: u64,
    max_size: u64,
    path: PathBuf,
}

struct NekoLogger {
    level: LevelFilter,
    file: Option<Mutex<LogFile>>,
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
        if let Some(log) = &self.file {
            if let Ok(mut lf) = log.lock() {
                let msg_bytes = msg.as_bytes();
                // Truncate when file exceeds max_size (0 = never truncate)
                if lf.max_size > 0 && lf.size + msg_bytes.len() as u64 > lf.max_size {
                    // Truncate by reopening — clears content and resets append position
                    if let Ok(new_f) = OpenOptions::new()
                        .create(true)
                        .truncate(true)
                        .write(true)
                        .open(&lf.path)
                    {
                        lf.f = new_f;
                        lf.size = 0;
                    }
                }
                let _ = lf.f.write_all(msg_bytes);
                lf.size += msg_bytes.len() as u64;
            }
        }
    }

    fn flush(&self) {
        if let Some(log) = &self.file {
            if let Ok(mut lf) = log.lock() {
                let _ = lf.f.flush();
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
    let (y, mo, d) = epoch_days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02}")
}

fn epoch_days_to_ymd(days: u64) -> (u64, u64, u64) {
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
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}
