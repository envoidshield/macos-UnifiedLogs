// Copyright 2022 Mandiant, Inc. All Rights Reserved
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

use chrono::{SecondsFormat, TimeZone, Utc};
use log::{LevelFilter, debug, error, info};
use macos_unifiedlogs::filesystem::{
    LiveSystemProvider, LogarchiveProvider, SharedLogarchiveProvider,
};
use macos_unifiedlogs::iterator::UnifiedLogIterator;
use macos_unifiedlogs::parser::{build_log, collect_timesync, parse_log};
use macos_unifiedlogs::timesync::TimesyncBoot;
use macos_unifiedlogs::traits::FileProvider;
use macos_unifiedlogs::unified_log::{LogData, UnifiedLogData};
use rayon::prelude::*;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::Display;
use std::fs;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::sync_channel;
use std::thread;
use std::time::Instant;

use clap::{Parser, ValueEnum, builder};
use csv::Writer;
use serde::Serialize;

/// Event format output structure for optimized downstream processing
#[derive(Serialize)]
struct Event<'a> {
    datetime: String,
    timestamp: f64,
    message: &'a str,
    timestamp_desc: &'static str,
    module: &'static str,
    data: EventData<'a>,
}

/// Data object within Event format
#[derive(Serialize)]
struct EventData<'a> {
    subsystem: &'a str,
    thread_id: u64,
    pid: u64,
    euid: u32,
    library: &'a str,
    time: f64,
    category: &'a str,
    event_type: String,
    log_type: String,
    process: &'a str,
}

#[derive(Clone, Debug)]
enum RuntimeError {
    FileOpen { path: String, message: String },
    FileParse { path: String, message: String },
}

impl Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            RuntimeError::FileOpen { path, message } => {
                f.write_str(&format!("Failed to open source file {path}: {message}"))
            }
            RuntimeError::FileParse { path, message } => {
                f.write_str(&format!("Failed to parse {path}: {message}"))
            }
        }
    }
}

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// Mode of operation
    #[clap(short, long)]
    mode: Mode,

    /// Path to logarchive formatted directory (log-archive mode) or tracev3 file (single-file
    /// mode)
    #[clap(short, long)]
    input: Option<PathBuf>,

    /// Filename to save results to
    #[clap(short, long)]
    output: Option<PathBuf>,

    /// Output format. Options: csv, jsonl
    #[clap(short, long, default_value = Format::Jsonl)]
    format: Format,

    /// Append to output file.
    /// If false, will overwrite output file
    #[clap(short, long, default_value = "false")]
    append: bool,

    /// Maximum number of files to process (for benchmarking)
    #[clap(long)]
    max_files: Option<usize>,

    /// Comma-separated list of fields to exclude from output.
    /// Available fields: raw_message, message_entries, library_uuid, process_uuid, boot_uuid
    #[clap(long, value_delimiter = ',')]
    exclude_fields: Option<Vec<String>>,

    /// Output format for JSON data. 'default' outputs Mandiant's format,
    /// 'event' outputs the Event format for downstream processing.
    #[clap(long, default_value = "default")]
    output_format: OutputFormat,

    /// Enable parallel processing of tracev3 files
    #[clap(long, short = 'j')]
    parallel: bool,

    /// Number of threads for parallel processing (default: all cores)
    #[clap(long, short = 't')]
    threads: Option<usize>,

    /// Comma-separated list of full process paths to skip emission for.
    /// Filtering happens before serialization, so dropped entries pay no
    /// JSON/CSV cost. Repeat or comma-join to add multiple paths.
    #[clap(long, value_delimiter = ',')]
    exclude_processes: Option<Vec<String>>,

    /// File with newline-separated full process paths to skip emission for.
    /// Lines starting with '#' and blank lines are ignored.
    /// Merged with --exclude-processes if both are given.
    #[clap(long)]
    exclude_processes_file: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone, ValueEnum)]
enum Mode {
    Live,
    LogArchive,
    SingleFile,
}

#[derive(Parser, Debug, Clone, ValueEnum)]
enum Format {
    Csv,
    Jsonl,
}

/// Output format for JSON data
#[derive(Parser, Debug, Clone, ValueEnum, Default, PartialEq)]
pub enum OutputFormat {
    /// Default format (Mandiant's UnifiedLogReader format)
    #[default]
    Default,
    /// Event format optimized for downstream processing
    Event,
}

impl From<Format> for builder::OsStr {
    fn from(value: Format) -> Self {
        match value {
            Format::Csv => "csv".into(),
            Format::Jsonl => "jsonl".into(),
        }
    }
}

impl From<Format> for &str {
    fn from(value: Format) -> Self {
        match value {
            Format::Csv => "csv",
            Format::Jsonl => "jsonl",
        }
    }
}

fn main() {
    TermLogger::init(
        LevelFilter::Warn,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .expect("Failed to initialize simple logger");
    info!("Starting Unified Log parser...");

    let args = Args::parse();
    let output_format = args.format;

    // Configure thread pool if --threads is specified
    if let Some(num_threads) = args.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build_global()
            .expect("Failed to configure thread pool");
    }

    // Use BufWriter for better I/O performance (64KB buffer).
    // `+ Send` is required so the streaming writer thread in
    // parse_trace_file_parallel can take ownership via thread::scope.
    let handle: Box<dyn Write + Send> = if let Some(path) = args.output {
        Box::new(BufWriter::with_capacity(
            64 * 1024,
            fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .unwrap(),
        ))
    } else {
        Box::new(BufWriter::with_capacity(64 * 1024, std::io::stdout()))
    };

    let exclude_fields: HashSet<String> = args
        .exclude_fields
        .unwrap_or_default()
        .into_iter()
        .collect();

    let mut exclude_processes: HashSet<String> = args
        .exclude_processes
        .unwrap_or_default()
        .into_iter()
        .filter(|p| !p.is_empty())
        .collect();
    if let Some(path) = args.exclude_processes_file {
        match fs::read_to_string(&path) {
            Ok(contents) => {
                for line in contents.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        exclude_processes.insert(trimmed.to_string());
                    }
                }
            }
            Err(e) => {
                error!("Failed to read --exclude-processes-file {path:?}: {e}");
                std::process::exit(1);
            }
        }
    }
    if !exclude_processes.is_empty() {
        info!("Filtering {} process path(s) before output", exclude_processes.len());
    }

    let json_output_format = args.output_format;
    let mut writer = OutputWriter::new(
        handle,
        output_format.into(),
        exclude_fields,
        exclude_processes,
        json_output_format,
    )
    .unwrap();

    match (args.mode, args.input) {
        (Mode::Live, None) => {
            parse_live_system(&mut writer, args.max_files, args.parallel);
        }
        (Mode::LogArchive, Some(path)) => {
            parse_log_archive(&path, &mut writer, args.max_files, args.parallel);
        }
        (Mode::SingleFile, Some(path)) => {
            parse_single_file(&path, &mut writer);
        }
        _ => {
            error!("log-archive and single-file modes require an --input argument");
        }
    }
}

fn parse_single_file(path: &Path, writer: &mut OutputWriter) {
    let mut provider = LogarchiveProvider::new(path);
    let results = match fs::File::open(path)
        .map_err(|e| RuntimeError::FileOpen {
            path: path.to_string_lossy().to_string(),
            message: e.to_string(),
        })
        .and_then(|mut reader| {
            parse_log(&mut reader).map_err(|err| RuntimeError::FileParse {
                path: path.to_string_lossy().to_string(),
                message: format!("{err}"),
            })
        })
        .map(|ref log| {
            let (results, _) = build_log(log, &mut provider, &HashMap::new(), false);
            results
        }) {
        Ok(reader) => reader,
        Err(e) => {
            error!("Failed to parse {path:?}: {e}");
            return;
        }
    };
    for row in results {
        if let Err(e) = writer.write_record(&row) {
            error!("Error writing record: {e}");
        };
    }
}

// Parse a provided directory path. Currently, expect the path to follow macOS log collect structure
fn parse_log_archive(path: &Path, writer: &mut OutputWriter, max_files: Option<usize>, parallel: bool) {
    let provider = LogarchiveProvider::new(path);

    // Parse all timesync files
    let timesync_data = collect_timesync(&provider).unwrap();

    // Keep UUID, UUID cache, timesync files in memory while we parse all tracev3 files
    // Allows for faster lookups
    if parallel {
        parse_trace_file_parallel(path, &timesync_data, writer, max_files);
    } else {
        let mut provider = LogarchiveProvider::new(path);
        parse_trace_file(&timesync_data, &mut provider, writer, max_files);
    }

    info!("Finished parsing Unified Log data.");
}

// Parse a live macOS system
fn parse_live_system(writer: &mut OutputWriter, max_files: Option<usize>, parallel: bool) {
    let mut provider = LiveSystemProvider::default();
    let timesync_data = collect_timesync(&provider).unwrap();

    if parallel {
        eprintln!("[WARNING] Parallel mode not supported for live system, falling back to sequential");
    }
    parse_trace_file(&timesync_data, &mut provider, writer, max_files);

    info!("Finished parsing Unified Log data.");
}

// Use the provided strings, shared strings, timesync data to parse the Unified Log data at provided path.
fn parse_trace_file(
    timesync_data: &HashMap<String, TimesyncBoot>,
    provider: &mut dyn FileProvider,
    writer: &mut OutputWriter,
    max_files: Option<usize>,
) {
    // We need to persist the Oversize log entries (they contain large strings that don't fit in normal log entries)
    // Some log entries have Oversize strings located in different tracev3 files.
    // This is very rare. Seen in ~20 log entries out of ~700,000. Seen in ~700 out of ~18 million
    let mut oversize_strings = UnifiedLogData {
        header: Vec::new(),
        catalog_data: Vec::new(),
        oversize: Vec::new(),
    };

    let mut missing_data: Vec<UnifiedLogData> = Vec::new();

    // Loop through all tracev3 files in Persist directory
    let mut log_count = 0;
    let mut file_count = 0;
    let total_start = Instant::now();
    
    for mut source in provider.tracev3_files() {
        if Path::new(source.source_path())
            .file_name()
            .is_some_and(|f| f.to_str().unwrap().starts_with("._"))
        {
            continue;
        }
        
        if let Some(max) = max_files {
            if file_count >= max {
                eprintln!("\n[BENCHMARK] Stopping after {} files (max_files limit)", file_count);
                break;
            }
        }
        
        file_count += 1;
        let file_start = Instant::now();
        let file_path = source.source_path().to_string();
        
        eprintln!("[{}] Parsing: {}", file_count, file_path);
        
        let file_log_count = iterate_chunks(
            source.reader(),
            &mut missing_data,
            provider,
            timesync_data,
            writer,
            &mut oversize_strings,
        );
        
        let file_duration = file_start.elapsed();
        log_count += file_log_count;
        
        eprintln!(
            "[{}] Completed in {:.2}s - {} log entries ({:.0} entries/sec)",
            file_count,
            file_duration.as_secs_f64(),
            file_log_count,
            file_log_count as f64 / file_duration.as_secs_f64()
        );
        
        debug!("count: {log_count}");
    }
    
    let total_duration = total_start.elapsed();
    eprintln!("\n[BENCHMARK] Total parsing time: {:.2}s", total_duration.as_secs_f64());
    eprintln!("[BENCHMARK] Files processed: {}", file_count);
    eprintln!("[BENCHMARK] Total log entries: {}", log_count);
    eprintln!("[BENCHMARK] Average: {:.0} entries/sec", log_count as f64 / total_duration.as_secs_f64());
    let include_missing = false;
    debug!("Oversize cache size: {}", oversize_strings.oversize.len());
    debug!("Logs with missing Oversize strings: {}", missing_data.len());
    debug!("Checking Oversize cache one more time...");

    // Since we have all Oversize entries now. Go through any log entries that we were not able to build before
    for mut leftover_data in missing_data {
        // Add all of our previous oversize data to logs for lookups
        leftover_data.oversize = oversize_strings.oversize.clone();

        // Exclude_missing = false
        // If we fail to find any missing data its probably due to the logs rolling
        // Ex: tracev3A rolls, tracev3B references Oversize entry in tracev3A will trigger missing data since tracev3A is gone
        let (results, _) = build_log(&leftover_data, provider, timesync_data, include_missing);
        log_count += results.len();

        if let Err(err) = output(&results, writer) {
            log::error!("Failed to output remaining log data: {err:?}");
        }
    }
    info!("Parsed {log_count} log entries");
}

// Parallel version of parse_trace_file.
//
// Memory-conscious design (was OOM-killing the deep_forensic container at
// MemoryMax=2G with the previous implementation):
//
//   1. DSC strings cache (~500 MB) is preloaded ONCE into a SharedLogarchiveProvider
//      whose `dsc_cache: Arc<HashMap>` is shared across worker threads via cheap
//      Arc::clone. Previously each rayon task did `LogarchiveProvider::clone()`,
//      deep-copying the entire HashMap and inflating peak RSS to ~3-4x DSC size.
//
//   2. Parsed LogData batches stream through a bounded `sync_channel(8)` to a
//      dedicated writer thread instead of `par_iter().map(...).collect()`-ing
//      every Vec<LogData> into RAM and only then writing. The writer borrows
//      `&mut OutputWriter` via `thread::scope`, so no extra ownership shuffle
//      is needed.
//
//   3. Phase 5 (oversize-string fixup) still merges per-file leftovers, but
//      those payloads are tiny relative to the parsed log stream.
fn parse_trace_file_parallel(
    archive_path: &Path,
    timesync_data: &HashMap<String, TimesyncBoot>,
    writer: &mut OutputWriter,
    max_files: Option<usize>,
) {
    let total_start = Instant::now();

    // Phase 1: Pre-load all DSC files into the shared, immutable cache.
    eprintln!("[PARALLEL] Pre-loading DSC files...");
    let preload_start = Instant::now();
    let base_provider = SharedLogarchiveProvider::with_preloaded_dsc(archive_path);
    let (_, dsc_count) = base_provider.cache_stats();
    eprintln!(
        "[PARALLEL] Pre-loaded {} DSC files in {:.2}s",
        dsc_count,
        preload_start.elapsed().as_secs_f64()
    );

    // Phase 2: Collect tracev3 file paths.
    let file_paths: Vec<String> = base_provider
        .tracev3_files()
        .filter(|source| {
            !Path::new(source.source_path())
                .file_name()
                .is_some_and(|f| f.to_str().unwrap().starts_with("._"))
        })
        .map(|source| source.source_path().to_string())
        .take(max_files.unwrap_or(usize::MAX))
        .collect();

    let file_count = file_paths.len();
    eprintln!(
        "[PARALLEL] Processing {} files with {} threads",
        file_count,
        rayon::current_num_threads()
    );

    // Bounded channel: caps in-flight parsed batches. Each slot holds one
    // file-chunk's Vec<LogData> (typically a few hundred to a few thousand
    // entries). 8 slots * threads keeps peak RAM bounded but still hides
    // disk-write latency from the parser threads.
    let (tx_logs, rx_logs) = sync_channel::<Vec<LogData>>(8);

    // Phases 3 + 4 inside thread::scope so the writer thread can borrow
    // &mut writer without 'static. Reborrow as a shorter-lived &mut so the
    // original `writer` is usable again after the scope ends (for phase 5).
    let writer_for_scope: &mut OutputWriter = &mut *writer;
    let (all_oversize, all_missing, mut total_log_count) = thread::scope(|scope| {
        // Writer thread: drains the channel one batch at a time, writes
        // serially. Closing `tx_logs` is what makes this loop terminate.
        // `move` is required because mpsc::Receiver is not Sync.
        let writer_thread = scope.spawn(move || {
            let mut written = 0usize;
            while let Ok(batch) = rx_logs.recv() {
                for record in &batch {
                    if let Err(e) = writer_for_scope.write_record(record) {
                        log::error!("Failed to write record: {e:?}");
                    }
                    written += 1;
                }
            }
            if let Err(e) = writer_for_scope.flush() {
                log::error!("Failed to flush writer: {e:?}");
            }
            written
        });

        // Workers: parse each tracev3, stream results, return per-file meta
        // (oversize cache + missing-string fixups) for phase 5.
        let meta: Vec<(UnifiedLogData, Vec<UnifiedLogData>, usize)> = file_paths
            .par_iter()
            .enumerate()
            .map_with(tx_logs.clone(), |tx, (idx, file_path)| {
                let file_start = Instant::now();
                // Cheap clone: Arc::clone for dsc_cache + fresh empty
                // uuidtext_cache. No HashMap deep-copy.
                let mut thread_provider = base_provider.clone();

                let mut buf = Vec::new();
                if let Err(err) =
                    fs::File::open(file_path).and_then(|mut f| f.read_to_end(&mut buf))
                {
                    log::error!("Failed to read {file_path}: {err}");
                    return (
                        UnifiedLogData {
                            header: Vec::new(),
                            catalog_data: Vec::new(),
                            oversize: Vec::new(),
                        },
                        Vec::new(),
                        0usize,
                    );
                }

                let log_iterator = UnifiedLogIterator {
                    data: buf,
                    header: Vec::new(),
                };

                let mut local_oversize = UnifiedLogData {
                    header: Vec::new(),
                    catalog_data: Vec::new(),
                    oversize: Vec::new(),
                };
                let mut local_missing: Vec<UnifiedLogData> = Vec::new();
                let mut count = 0usize;
                let exclude_missing = true;

                for mut chunk in log_iterator {
                    // Carry oversize-string state forward across chunks of
                    // the same file (mirrors iterate_chunks).
                    chunk.oversize.append(&mut local_oversize.oversize);
                    let (results, missing_logs) =
                        build_log(&chunk, &mut thread_provider, timesync_data, exclude_missing);
                    count += results.len();
                    local_oversize.oversize = chunk.oversize;

                    if !results.is_empty() {
                        // Backpressure: blocks if the writer thread is
                        // behind. This is the core of the OOM fix.
                        if tx.send(results).is_err() {
                            log::error!("Writer thread closed early; dropping batch");
                            break;
                        }
                    }

                    if !missing_logs.catalog_data.is_empty()
                        || !missing_logs.header.is_empty()
                        || !missing_logs.oversize.is_empty()
                    {
                        local_missing.push(missing_logs);
                    }
                }

                let file_duration = file_start.elapsed();
                eprintln!(
                    "[{}/{}] {} - {} entries ({:.0}/sec) in {:.2}s",
                    idx + 1,
                    file_count,
                    Path::new(file_path).file_name().unwrap().to_str().unwrap(),
                    count,
                    count as f64 / file_duration.as_secs_f64().max(0.0001),
                    file_duration.as_secs_f64()
                );

                (local_oversize, local_missing, count)
            })
            .collect();

        // Drop the original tx so the writer thread sees EOF once all
        // map_with clones have also been dropped (at this point they have,
        // because collect() has joined all workers).
        drop(tx_logs);
        let written = writer_thread.join().expect("writer thread panicked");
        eprintln!("[PARALLEL] Writer drained {written} records");

        let mut all_oversize = UnifiedLogData {
            header: Vec::new(),
            catalog_data: Vec::new(),
            oversize: Vec::new(),
        };
        let mut all_missing: Vec<UnifiedLogData> = Vec::new();
        let mut total_log_count = 0usize;
        for (mut local_oversize, local_missing, count) in meta {
            total_log_count += count;
            all_oversize.oversize.append(&mut local_oversize.oversize);
            all_missing.extend(local_missing);
        }
        (all_oversize, all_missing, total_log_count)
    });

    let total_duration = total_start.elapsed();
    eprintln!(
        "\n[BENCHMARK] Total parsing time: {:.2}s",
        total_duration.as_secs_f64()
    );
    eprintln!("[BENCHMARK] Files processed: {file_count}");
    eprintln!("[BENCHMARK] Total log entries: {total_log_count}");
    eprintln!(
        "[BENCHMARK] Average: {:.0} entries/sec",
        total_log_count as f64 / total_duration.as_secs_f64().max(0.0001)
    );

    debug!("Oversize cache size: {}", all_oversize.oversize.len());
    debug!("Logs with missing Oversize strings: {}", all_missing.len());

    // Phase 5: re-process logs that referenced an oversize string located in
    // a different tracev3. Sequential and small.
    if !all_missing.is_empty() {
        eprintln!(
            "[PARALLEL] Processing {} missing data entries...",
            all_missing.len()
        );
        let mut provider = LogarchiveProvider::new(archive_path);
        let include_missing = false;

        for mut leftover_data in all_missing {
            leftover_data.oversize = all_oversize.oversize.clone();
            let (results, _) =
                build_log(&leftover_data, &mut provider, timesync_data, include_missing);
            total_log_count += results.len();

            if let Err(err) = output(&results, writer) {
                log::error!("Failed to output remaining log data: {err:?}");
            }
        }
    }

    info!("Parsed {total_log_count} log entries");
}

fn iterate_chunks(
    mut reader: impl Read,
    missing: &mut Vec<UnifiedLogData>,
    provider: &mut dyn FileProvider,
    timesync_data: &HashMap<String, TimesyncBoot>,
    writer: &mut OutputWriter,
    oversize_strings: &mut UnifiedLogData,
) -> usize {
    let mut buf = Vec::new();

    if let Err(err) = reader.read_to_end(&mut buf) {
        log::error!("Failed to read tracev3 file: {err:?}");
        return 0;
    }

    let log_iterator = UnifiedLogIterator {
        data: buf,
        header: Vec::new(),
    };

    // Exclude missing data from returned output. Keep separate until we parse all oversize entries.
    // Then after parsing all logs, go through all missing data and check all parsed oversize entries again
    let exclude_missing = true;

    let mut count = 0;
    for mut chunk in log_iterator {
        chunk.oversize.append(&mut oversize_strings.oversize);
        let (results, missing_logs) = build_log(&chunk, provider, timesync_data, exclude_missing);
        count += results.len();
        oversize_strings.oversize = chunk.oversize;
        if let Err(err) = output(&results, writer) {
            log::error!("Failed to output log data: {err:?}");
        }
        if missing_logs.catalog_data.is_empty()
            && missing_logs.header.is_empty()
            && missing_logs.oversize.is_empty()
        {
            continue;
        }
        // Track possible missing log data due to oversize strings being in another file
        missing.push(missing_logs);
    }

    count
}

pub struct OutputWriter {
    writer: OutputWriterEnum,
    exclude_fields: HashSet<String>,
    exclude_processes: HashSet<String>,
    output_format: OutputFormat,
}

enum OutputWriterEnum {
    Csv(Box<Writer<Box<dyn Write + Send>>>),
    Json(Box<dyn Write + Send>),
}

impl OutputWriter {
    pub fn new(
        writer: Box<dyn Write + Send>,
        file_format: &str,
        exclude_fields: HashSet<String>,
        exclude_processes: HashSet<String>,
        output_format: OutputFormat,
    ) -> Result<Self, Box<dyn Error>> {
        let writer_enum = match file_format {
            "csv" => {
                let mut csv_writer = Writer::from_writer(writer);
                // Write CSV headers
                csv_writer.write_record([
                    "Timestamp",
                    "Event Type",
                    "Log Type",
                    "Subsystem",
                    "Thread ID",
                    "PID",
                    "EUID",
                    "Library",
                    "Library UUID",
                    "Activity ID",
                    "Category",
                    "Process",
                    "Process UUID",
                    "Message",
                    "Raw Message",
                    "Boot UUID",
                    "System Timezone Name",
                ])?;
                csv_writer.flush()?;
                OutputWriterEnum::Csv(Box::new(csv_writer))
            }
            "jsonl" => OutputWriterEnum::Json(writer),
            _ => {
                error!("Unsupported file format: {file_format}");
                std::process::exit(1);
            }
        };

        Ok(OutputWriter {
            writer: writer_enum,
            exclude_fields,
            exclude_processes,
            output_format,
        })
    }

    pub fn write_record(&mut self, record: &LogData) -> Result<(), Box<dyn Error>> {
        // Drop entries from known-noise processes before paying serialization cost.
        // Filter is exact-path; basename-only matches would risk false positives
        // on user binaries that happen to share a daemon name.
        if !self.exclude_processes.is_empty()
            && self.exclude_processes.contains(record.process.as_str())
        {
            return Ok(());
        }
        match &mut self.writer {
            OutputWriterEnum::Csv(csv_writer) => {
                let date_time = Utc.timestamp_nanos(record.time as i64);
                csv_writer.write_record(&[
                    date_time.to_rfc3339_opts(SecondsFormat::Millis, true),
                    format!("{:?}", record.event_type),
                    format!("{:?}", record.log_type),
                    record.subsystem.to_owned(),
                    record.thread_id.to_string(),
                    record.pid.to_string(),
                    record.euid.to_string(),
                    record.library.to_owned(),
                    if self.exclude_fields.contains("library_uuid") {
                        String::new()
                    } else {
                        record.library_uuid.to_owned()
                    },
                    record.activity_id.to_string(),
                    record.category.to_owned(),
                    record.process.to_owned(),
                    if self.exclude_fields.contains("process_uuid") {
                        String::new()
                    } else {
                        record.process_uuid.to_owned()
                    },
                    record.message.to_owned(),
                    if self.exclude_fields.contains("raw_message") {
                        String::new()
                    } else {
                        record.raw_message.to_owned()
                    },
                    if self.exclude_fields.contains("boot_uuid") {
                        String::new()
                    } else {
                        record.boot_uuid.to_owned()
                    },
                    record.timezone_name.to_owned(),
                ])?;
            }
            OutputWriterEnum::Json(json_writer) => {
                if self.output_format == OutputFormat::Event {
                    // Event format: optimized for downstream processing
                    write_event_format(json_writer, record, &self.exclude_fields)?;
                } else if self.exclude_fields.is_empty() {
                    writeln!(json_writer, "{}", serde_json::to_string(record).unwrap())?;
                } else {
                    // Convert to JSON Value and remove excluded fields
                    let mut json_value = serde_json::to_value(record).unwrap();
                    if let serde_json::Value::Object(ref mut map) = json_value {
                        for field in &self.exclude_fields {
                            map.remove(field);
                        }
                    }
                    writeln!(json_writer, "{}", serde_json::to_string(&json_value).unwrap())?;
                }
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        match &mut self.writer {
            OutputWriterEnum::Csv(csv_writer) => csv_writer.flush()?,
            OutputWriterEnum::Json(json_writer) => json_writer.flush()?,
        }
        Ok(())
    }
}

// Append or create csv file
fn output(results: &Vec<LogData>, writer: &mut OutputWriter) -> Result<(), Box<dyn Error>> {
    for data in results {
        writer.write_record(data)?;
    }
    writer.flush()?;
    Ok(())
}

/// Write record in Event format for optimized downstream processing
/// Uses struct-based serialization with simd-json for maximum performance
fn write_event_format(
    json_writer: &mut Box<dyn Write + Send>,
    record: &LogData,
    _exclude_fields: &HashSet<String>,
) -> Result<(), Box<dyn Error>> {
    // Convert time from nanoseconds to datetime and timestamp
    let time_nanos = record.time as i64;
    let datetime = Utc.timestamp_nanos(time_nanos);
    let datetime_str = datetime.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
    let timestamp_float = time_nanos as f64 / 1_000_000_000.0;

    // Build the EventData struct (core fields only for maximum performance)
    let data = EventData {
        subsystem: &record.subsystem,
        thread_id: record.thread_id,
        pid: record.pid,
        euid: record.euid,
        library: &record.library,
        time: record.time,
        category: &record.category,
        event_type: format!("{:?}", record.event_type),
        log_type: format!("{:?}", record.log_type),
        process: &record.process,
    };

    // Build the Event struct
    let event = Event {
        datetime: datetime_str,
        timestamp: timestamp_float,
        message: &record.message,
        timestamp_desc: "logarchive",
        module: "logarchive",
        data,
    };

    writeln!(json_writer, "{}", serde_json::to_string(&event)?)?;
    Ok(())
}
