use anyhow::{bail, ensure};
use aya::maps::{MapData, PerCpuArray, PerCpuHashMap, PerCpuValues, StackTraceMap};
use aya::programs::UProbe;
use aya::util::nr_cpus;
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use clap::{ArgGroup, Parser};
use jeprofl::report::{csv, flame, pretty};
use jeprofl::{
    filter_symbols, list_text_symbols, run_collector_thread, MatchMode, MetricKind, MetricRuntime,
    MetricSpec, OrderBy, Retention, SymEntry,
};
use jeprofl_common::{Config, Histogram, HistogramKey, CONFIG_SLOT, COUNTER_SLOT};
use log::{debug, info, warn};
use minus::{ExitStrategy, Pager};
use std::fmt::Write as _;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;

#[derive(Debug, Parser)]
#[command(
    group(
        ArgGroup::new("target")
            .required(true)
            .multiple(true)
            .args(["pid", "program"])
    )
)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,

    #[clap(long)]
    program: Option<PathBuf>,

    #[clap(
        short = 'f',
        long = "function",
        required = true,
        num_args = 1..,
        value_delimiter = ','
    )]
    functions: Vec<String>,

    #[clap(long = "match", value_enum, default_value_t = MatchCli::Contains)]
    match_mode: MatchCli,

    #[clap(long = "list-only")]
    list_only: bool,

    #[clap(long("metric"), value_enum, default_values_t = [MetricKind::Count])]
    metrics: Vec<MetricKind>,

    #[clap(long, default_value_t = 0)]
    min_time: u64,

    #[clap(long, default_value_t = u64::MAX)]
    max_time: u64,

    #[clap(long, default_value_t = 0)]
    min_count: u64,

    #[clap(long, default_value_t = u64::MAX)]
    max_count: u64,

    #[clap(short, long, default_value_t = OrderBy::Count)]
    order_by: OrderBy,

    /// Specify the sampling interval for events.
    /// For example, '1' samples every event, '1000' samples every 1000th event.
    #[clap(short = 'e', long)]
    #[clap(default_value_t = NonZeroU32::new(1).unwrap())]
    sample_every: NonZeroU32,

    /// Skip stack traces with total value below the threshold
    #[clap(short = 's', long, default_value_t = 0)]
    skip_value: u64,

    /// Skip stack traces with total count below the threshold
    #[clap(long, default_value_t = 0)]
    skip_count: u64,

    #[clap(long("csv"))]
    csv_path: Option<PathBuf>,

    /// Writes a flamegraph to the path_by_size.svg and path_by_count.svg
    #[clap(long("flame"))]
    flame_graph: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum MatchCli {
    Contains,
    Exact,
    Regex,
}

impl From<MatchCli> for MatchMode {
    fn from(value: MatchCli) -> Self {
        match value {
            MatchCli::Contains => MatchMode::Contains,
            MatchCli::Exact => MatchMode::Exact,
            MatchCli::Regex => MatchMode::Regex,
        }
    }
}

struct MetricDesc {
    config_map: &'static str,
    counter_map: &'static str,
    histogram_map: &'static str,
    entry_prog: &'static str,
    ret_prog: Option<&'static str>,
    min: u64,
    max: u64,
}

struct MatchResolution {
    program_path: PathBuf,
    matches: Vec<SymEntry>,
}

fn metric_desc(kind: MetricKind, opt: &Opt) -> MetricDesc {
    match kind {
        MetricKind::Count => MetricDesc {
            config_map: "CONFIG_COUNT",
            counter_map: "COUNTER_COUNT",
            histogram_map: "HISTOGRAMS_COUNT",
            entry_prog: "probe_count_entry",
            ret_prog: None,
            min: opt.min_count,
            max: opt.max_count,
        },
        MetricKind::Duration => MetricDesc {
            config_map: "CONFIG_LATENCY",
            counter_map: "COUNTER_LATENCY",
            histogram_map: "HISTOGRAMS_LATENCY",
            entry_prog: "probe_latency_entry",
            ret_prog: Some("probe_latency_ret"),
            min: opt.min_time,
            max: opt.max_time,
        },
    }
}

fn select_metrics(opt: &Opt) -> Vec<MetricKind> {
    let mut metrics = Vec::new();
    for metric in opt.metrics.iter().copied() {
        if !metrics.contains(&metric) {
            metrics.push(metric);
        }
    }
    if metrics.is_empty() {
        metrics.push(MetricKind::Count);
    }
    metrics
}

fn load_bpf() -> Result<Ebpf, anyhow::Error> {
    #[cfg(debug_assertions)]
    let bytes = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/jeprofl");
    #[cfg(not(debug_assertions))]
    let bytes = include_bytes_aligned!("../../target/bpfel-unknown-none/release/jeprofl");
    Ok(Ebpf::load(bytes)?)
}

fn configure_metric_maps(
    bpf: &mut Ebpf,
    metrics: &[MetricKind],
    opt: &Opt,
) -> Result<(), anyhow::Error> {
    let num_cpus = nr_cpus().unwrap();

    for &kind in metrics {
        let desc = metric_desc(kind, opt);

        let config_map = bpf
            .map_mut(desc.config_map)
            .unwrap_or_else(|| panic!("{map} not found", map = desc.config_map));
        let mut config_map = PerCpuArray::<_, Config>::try_from(config_map)?;
        let cfg = Config {
            mode: kind.to_mode() as u32,
            min_value: desc.min,
            max_value: desc.max,
            sample_every: opt.sample_every.get(),
            _pad: 0,
        };
        config_map.set(CONFIG_SLOT, PerCpuValues::try_from(vec![cfg; num_cpus])?, 0)?;

        let counter_map = bpf
            .map_mut(desc.counter_map)
            .unwrap_or_else(|| panic!("{map} not found", map = desc.counter_map));
        let mut counter_map = PerCpuArray::<_, u64>::try_from(counter_map)?;
        counter_map.set(COUNTER_SLOT, PerCpuValues::try_from(vec![0; num_cpus])?, 0)?;

        info!(
            "Recording {} between {} and {}",
            kind.value_label(),
            desc.min,
            desc.max
        );
    }

    Ok(())
}

fn resolve_matches(opt: &Opt) -> Result<MatchResolution, anyhow::Error> {
    let program_path = opt
        .program
        .clone()
        .or_else(|| opt.pid.map(|pid| PathBuf::from(format!("/proc/{pid}/exe"))))
        .expect("target group ensures pid or program is set");

    let patterns: Vec<String> = opt
        .functions
        .iter()
        .map(|pattern| pattern.trim().to_string())
        .filter(|pattern| !pattern.is_empty())
        .collect();
    if patterns.is_empty() {
        bail!("no function patterns supplied");
    }

    let symbols = list_text_symbols(program_path.as_path())?;
    let match_mode: MatchMode = opt.match_mode.into();
    let matches = filter_symbols(&symbols, &patterns, match_mode)?;
    let missing = unmatched_patterns(&symbols, &patterns, match_mode)?;
    if !missing.is_empty() {
        warn!("no functions matched for patterns: {:?}", missing);
    }
    if matches.is_empty() {
        bail!(
            "no functions matched in {} for patterns {:?}",
            program_path.display(),
            patterns
        );
    }

    info!("Matched {} function(s):", matches.len());
    for sym in &matches {
        info!(
            "  {} (mangled: {}) @ 0x{:x}",
            sym.demangled, sym.mangled, sym.addr
        );
    }

    let owned = matches.into_iter().cloned().collect();
    Ok(MatchResolution {
        program_path,
        matches: owned,
    })
}

fn unmatched_patterns<'a>(
    symbols: &'a [SymEntry],
    patterns: &'a [String],
    mode: MatchMode,
) -> Result<Vec<&'a str>, anyhow::Error> {
    use MatchMode::*;
    let missing = match mode {
        Contains => patterns
            .iter()
            .filter_map(|pattern| {
                if symbols
                    .iter()
                    .any(|symbol| symbol.demangled.contains(pattern))
                {
                    None
                } else {
                    Some(pattern.as_str())
                }
            })
            .collect(),
        Exact => patterns
            .iter()
            .filter_map(|pattern| {
                if symbols.iter().any(|symbol| symbol.demangled == *pattern) {
                    None
                } else {
                    Some(pattern.as_str())
                }
            })
            .collect(),
        Regex => {
            let compiled = patterns
                .iter()
                .map(|pattern| regex::Regex::new(pattern))
                .collect::<Result<Vec<_>, _>>()?;
            patterns
                .iter()
                .zip(compiled.iter())
                .filter_map(|(pattern, matcher)| {
                    if symbols
                        .iter()
                        .any(|symbol| matcher.is_match(&symbol.demangled))
                    {
                        None
                    } else {
                        Some(pattern.as_str())
                    }
                })
                .collect()
        }
    };
    Ok(missing)
}

fn attach_metric_probes(
    bpf: &mut Ebpf,
    metrics: &[MetricKind],
    matches: &[SymEntry],
    program_path: &Path,
    opt: &Opt,
) -> Result<(), anyhow::Error> {
    for &kind in metrics {
        let desc = metric_desc(kind, opt);

        let entry: &mut UProbe = bpf.program_mut(desc.entry_prog).unwrap().try_into()?;
        entry.load()?;
        for sym in matches {
            info!(
                "Attaching {} entry probe: {}:{} ({})",
                kind.value_label(),
                program_path.display(),
                sym.demangled,
                sym.mangled
            );
            entry.attach(Some(sym.mangled.as_str()), 0, program_path, opt.pid)?;
        }

        if let Some(ret_prog) = desc.ret_prog {
            let ret_probe: &mut UProbe = bpf.program_mut(ret_prog).unwrap().try_into()?;
            ret_probe.load()?;
            for sym in matches {
                info!(
                    "Attaching {} return probe: {}:{} ({})",
                    kind.value_label(),
                    program_path.display(),
                    sym.demangled,
                    sym.mangled
                );
                ret_probe.attach(Some(sym.mangled.as_str()), 0, program_path, opt.pid)?;
            }
        }
    }

    Ok(())
}

fn open_runtime_maps(
    bpf: &mut Ebpf,
    metrics: &[MetricKind],
    opt: &Opt,
) -> Result<(StackTraceMap<MapData>, Vec<MetricRuntime>), anyhow::Error> {
    let stack_traces = StackTraceMap::try_from(bpf.take_map("STACKTRACES").unwrap())?;

    let start = std::time::Instant::now();
    let mut metric_runtimes = Vec::new();

    for &kind in metrics {
        let desc = metric_desc(kind, opt);
        let spec = MetricSpec::new(kind, opt.skip_value, opt.skip_count);
        let map: PerCpuHashMap<_, HistogramKey, Histogram> = PerCpuHashMap::try_from(
            bpf.take_map(desc.histogram_map)
                .unwrap_or_else(|| panic!("{map} not found", map = desc.histogram_map)),
        )?;
        metric_runtimes.push(MetricRuntime::new(spec, map));
        info!(
            "{} metric: skip stack traces with total {} < {} or sample count < {}",
            spec.kind, spec.value_label, spec.skip_total_value_lt, spec.skip_total_count_lt
        );
    }

    info!(
        "Opened histogram maps, took {:?}",
        start.elapsed().as_secs_f64()
    );

    Ok((stack_traces, metric_runtimes))
}

fn suffix_path(base: &Path, suffix: &str) -> PathBuf {
    let stem = base
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let mut candidate = base.with_file_name(format!("{stem}-{suffix}"));
    if let Some(ext) = base.extension() {
        candidate.set_extension(ext);
    }
    candidate
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    scopeguard::defer! {
        crossterm::execute!(std::io::stdout(),crossterm::cursor::Show).ok();
    };
    let opt = Opt::parse();

    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    ensure!(
        opt.min_time <= opt.max_time,
        "--min-time must be less than or equal to --max-time"
    );
    ensure!(
        opt.min_count <= opt.max_count,
        "--min-count must be less than or equal to --max-count"
    );

    let metrics = select_metrics(&opt);

    let mut bpf = load_bpf()?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    configure_metric_maps(&mut bpf, &metrics, &opt)?;

    let resolution = resolve_matches(&opt)?;
    if opt.list_only {
        return Ok(());
    }

    attach_metric_probes(
        &mut bpf,
        &metrics,
        &resolution.matches,
        resolution.program_path.as_path(),
        &opt,
    )?;

    let (stack_traces, metric_runtimes) = open_runtime_maps(&mut bpf, &metrics, &opt)?;

    let canceled = Arc::new(AtomicBool::new(false));
    let handle = run_collector_thread(
        metric_runtimes,
        canceled.clone(),
        stack_traces,
        Retention::default(),
    );

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");
    canceled.store(true, std::sync::atomic::Ordering::Release);
    tokio::time::sleep(Duration::from_secs(1)).await;

    let mut pager = Pager::new();
    pager.set_exit_strategy(ExitStrategy::PagerQuit)?;
    let pager_thread = {
        let pager = pager.clone();
        std::thread::spawn(move || minus::dynamic_paging(pager))
    };

    let results = handle.join()?;
    let multi_metric = results.len() > 1;

    for (kind, aggregator) in results {
        if multi_metric {
            writeln!(&mut pager, "{} metric\n", kind)?;
        }

        let merged = aggregator.merged();
        pretty::render(&mut pager, &merged, opt.order_by, &aggregator)?;

        if let Some(base) = &opt.csv_path {
            let path = if multi_metric {
                suffix_path(base, kind.file_suffix())
            } else {
                base.clone()
            };
            csv::write(path.as_path(), &merged, &aggregator)?;
        }

        if let Some(base) = &opt.flame_graph {
            let target = if multi_metric {
                suffix_path(base, kind.file_suffix())
            } else {
                base.clone()
            };

            let path_without_extension = match target.file_stem() {
                Some(stem) => target.with_file_name(stem),
                None => target.clone(),
            };

            let result = path_without_extension.to_string_lossy();
            let outputs = [
                (
                    PathBuf::from(format!("{result}-by-count.svg")),
                    OrderBy::Count,
                ),
                (
                    PathBuf::from(format!("{result}-by-traffic.svg")),
                    OrderBy::Traffic,
                ),
            ];

            for (output_path, mode) in outputs {
                let file = std::fs::File::create(&output_path)?;
                let writer = std::io::BufWriter::new(file);
                flame::write(writer, &merged, &aggregator, mode)?;
                log::info!("Flamegraph written to {:?}", output_path);
            }
        }
    }

    pager_thread.join().unwrap()?;
    log::info!("Exited");
    Ok(())
}
