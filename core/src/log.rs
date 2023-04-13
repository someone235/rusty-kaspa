//! Logger and logging macros
//!
//! For the macros to properly compile, the calling crate must add a dependency to
//! crate log (ie. `log.workspace = true`) when target architecture is not wasm32.

#[allow(unused_imports)]
use log::{Level, LevelFilter};

cfg_if::cfg_if! {
    if #[cfg(target_arch = "wasm32")] {
        static mut LEVEL_FILTER : LevelFilter = LevelFilter::Trace;
        #[inline(always)]
        pub fn log_level_enabled(level: Level) -> bool {
            unsafe { LEVEL_FILTER >= level }
        }
        pub fn set_log_level(level: LevelFilter) {
            unsafe { LEVEL_FILTER = level };
        }
    }
}

// TODO: enhance logger with parallel output to file, rotation, compression

#[cfg(not(target_arch = "wasm32"))]
pub fn init_logger(filters: &str) {
    use log4rs::{
        append::{
            console::{ConsoleAppender, Target},
            file::FileAppender,
        },
        config::{Appender, Root},
        encode::pattern::PatternEncoder,
        filter::threshold::ThresholdFilter,
        Config,
    };

    let level = log::LevelFilter::Info;
    let file_path = "/tmp/foo.log";

    // Build a stderr logger.
    let stderr = ConsoleAppender::builder().target(Target::Stderr).build();

    // Logging to log file.
    let logfile = FileAppender::builder()
        // Pattern: https://docs.rs/log4rs/*/log4rs/encode/pattern/index.html
        .encoder(Box::new(PatternEncoder::new("{l} - {m}\n")))
        .build(file_path)
        .unwrap();

    // Log Trace level output to file where trace is the default level
    // and the programmatically specified level to stderr.
    let config = Config::builder()
        .appender(Appender::builder().filter(Box::new(ThresholdFilter::new(level))).build("logfile", Box::new(logfile)))
        .appender(Appender::builder().filter(Box::new(ThresholdFilter::new(level))).build("stderr", Box::new(stderr)))
        .build(Root::builder().appender("logfile").appender("stderr").build(LevelFilter::Trace))
        .unwrap();

    log4rs::init_config(config).unwrap();

    workflow_log::set_log_level(level);
}

/// Tries to init the global logger, but does not panic if it was already setup.
/// Should be used for tests.
#[cfg(not(target_arch = "wasm32"))]
pub fn try_init_logger(filters: &str) {
    let _ = env_logger::Builder::new()
        .format_target(false)
        .format_timestamp_secs()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .parse_filters(filters)
        .try_init();
}

#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! trace {
    ($($t:tt)*) => {
        if kaspa_core::log::log_level_enabled(log::Level::Trace) {
            kaspa_core::console::log(&format_args!($($t)*).to_string());
        }
    };
}

#[cfg(not(target_arch = "wasm32"))]
#[macro_export]
macro_rules! trace {
    ($($t:tt)*) => {
        log::trace!($($t)*);
    };
}

#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! debug {
    ($($t:tt)*) => (
        if kaspa_core::log::log_level_enabled(log::Level::Debug) {
            kaspa_core::console::log(&format_args!($($t)*).to_string());
        }
    )
}

#[cfg(not(target_arch = "wasm32"))]
#[macro_export]
macro_rules! debug {
    ($($t:tt)*) => (
        log::debug!($($t)*);
    )
}

#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! info {
    ($($t:tt)*) => (
        if kaspa_core::log::log_level_enabled(log::Level::Info) {
            kaspa_core::console::log(&format_args!($($t)*).to_string());
        }
    )
}

#[cfg(not(target_arch = "wasm32"))]
#[macro_export]
macro_rules! info {
    ($($t:tt)*) => (
        log::info!($($t)*);
    )
}

#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! warn {
    ($($t:tt)*) => (
        if kaspa_core::log::log_level_enabled(log::Level::Warn) {
            kaspa_core::console::warn(&format_args!($($t)*).to_string());
        }
    )
}

#[cfg(not(target_arch = "wasm32"))]
#[macro_export]
macro_rules! warn {
    ($($t:tt)*) => (
        log::warn!($($t)*);
    )
}

#[cfg(target_arch = "wasm32")]
#[macro_export]
macro_rules! error {
    ($($t:tt)*) => (
        if kaspa_core::log::log_level_enabled(log::Level::Error) {
            kaspa_core::console::error(&format_args!($($t)*).to_string());
        }
    )
}

#[cfg(not(target_arch = "wasm32"))]
#[macro_export]
macro_rules! error {
    ($($t:tt)*) => (
        log::error!($($t)*);
    )
}
