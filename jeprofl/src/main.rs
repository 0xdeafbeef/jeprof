use anyhow::ensure;
use aya::maps::{PerCpuArray, PerCpuHashMap, PerCpuValues, StackTraceMap};
use aya::programs::UProbe;
use aya::util::nr_cpus;
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use clap::{ArgGroup, Parser};
use jeprofl::report::{csv, flame, pretty};
use jeprofl::{run_collector_thread, MetricKind, MetricRuntime, MetricSpec, OrderBy, Retention};
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

    #[clap(short, long)]
    function: String,

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

    let mut metrics = Vec::new();
    for metric in opt.metrics.iter().copied() {
        if !metrics.contains(&metric) {
            metrics.push(metric);
        }
    }
    if metrics.is_empty() {
        metrics.push(MetricKind::Count);
    }

    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/jeprofl"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/jeprofl"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    {
        let num_cpus = nr_cpus().unwrap();
        if metrics.contains(&MetricKind::Count) {
            let config_map = bpf.map_mut("CONFIG_COUNT").expect("CONFIG_COUNT not found");
            let mut config_map = PerCpuArray::<_, Config>::try_from(config_map)?;
            let cfg = Config {
                mode: MetricKind::Count.to_mode() as u32,
                min_value: opt.min_count,
                max_value: opt.max_count,
                sample_every: opt.sample_every.get(),
                _pad: 0,
            };
            config_map.set(CONFIG_SLOT, PerCpuValues::try_from(vec![cfg; num_cpus])?, 0)?;
            let counter_map = bpf
                .map_mut("COUNTER_COUNT")
                .expect("COUNTER_COUNT not found");
            let mut counter_map = PerCpuArray::<_, u64>::try_from(counter_map)?;
            counter_map.set(COUNTER_SLOT, PerCpuValues::try_from(vec![0; num_cpus])?, 0)?;
            log::info!(
                "Recording {} between {} and {}",
                MetricKind::Count.value_label(),
                opt.min_count,
                opt.max_count
            );
        }
        if metrics.contains(&MetricKind::Duration) {
            let config_map = bpf
                .map_mut("CONFIG_LATENCY")
                .expect("CONFIG_LATENCY not found");
            let mut config_map = PerCpuArray::<_, Config>::try_from(config_map)?;
            let cfg = Config {
                mode: MetricKind::Duration.to_mode() as u32,
                min_value: opt.min_time,
                max_value: opt.max_time,
                sample_every: opt.sample_every.get(),
                _pad: 0,
            };
            config_map.set(CONFIG_SLOT, PerCpuValues::try_from(vec![cfg; num_cpus])?, 0)?;
            let counter_map = bpf
                .map_mut("COUNTER_LATENCY")
                .expect("COUNTER_LATENCY not found");
            let mut counter_map = PerCpuArray::<_, u64>::try_from(counter_map)?;
            counter_map.set(COUNTER_SLOT, PerCpuValues::try_from(vec![0; num_cpus])?, 0)?;
            log::info!(
                "Recording {} between {} and {}",
                MetricKind::Duration.value_label(),
                opt.min_time,
                opt.max_time
            );
        }
    }

    let function = opt.function.clone();
    let program_path = opt
        .program
        .clone()
        .or_else(|| opt.pid.map(|pid| PathBuf::from(format!("/proc/{pid}/exe"))))
        .expect("target group ensures pid or program is set");
    if metrics.contains(&MetricKind::Count) {
        let entry: &mut UProbe = bpf.program_mut("probe_count_entry").unwrap().try_into()?;
        entry.load()?;
        log::info!(
            "Attaching count entry probe: {}:{}",
            program_path.display(),
            function
        );
        entry.attach(Some(function.as_str()), 0, &program_path, opt.pid)?;
    }
    if metrics.contains(&MetricKind::Duration) {
        let entry: &mut UProbe = bpf.program_mut("probe_latency_entry").unwrap().try_into()?;
        entry.load()?;
        log::info!(
            "Attaching latency entry probe: {}:{}",
            program_path.display(),
            function
        );
        entry.attach(Some(function.as_str()), 0, &program_path, opt.pid)?;

        let ret_probe: &mut UProbe = bpf.program_mut("probe_latency_ret").unwrap().try_into()?;
        ret_probe.load()?;
        log::info!(
            "Attaching latency return probe: {}:{}",
            program_path.display(),
            opt.function
        );
        ret_probe.attach(Some(opt.function.as_str()), 0, &program_path, opt.pid)?;
    }

    let stack_traces = StackTraceMap::try_from(bpf.take_map("STACKTRACES").unwrap())?;

    let start = std::time::Instant::now();
    let mut metric_runtimes = Vec::new();
    if metrics.contains(&MetricKind::Count) {
        let spec = MetricSpec::new(MetricKind::Count, opt.skip_value, opt.skip_count);
        let map: PerCpuHashMap<_, HistogramKey, Histogram> =
            PerCpuHashMap::try_from(bpf.take_map("HISTOGRAMS_COUNT").unwrap())?;
        metric_runtimes.push(MetricRuntime::new(spec, map));
        log::info!(
            "{} metric: skip stack traces with total {} < {} or sample count < {}",
            spec.kind,
            spec.value_label,
            spec.skip_total_value_lt,
            spec.skip_total_count_lt
        );
    }
    if metrics.contains(&MetricKind::Duration) {
        let spec = MetricSpec::new(MetricKind::Duration, opt.skip_value, opt.skip_count);
        let map: PerCpuHashMap<_, HistogramKey, Histogram> =
            PerCpuHashMap::try_from(bpf.take_map("HISTOGRAMS_LATENCY").unwrap())?;
        metric_runtimes.push(MetricRuntime::new(spec, map));
        log::info!(
            "{} metric: skip stack traces with total {} < {} or sample count < {}",
            spec.kind,
            spec.value_label,
            spec.skip_total_value_lt,
            spec.skip_total_count_lt
        );
    }
    log::info!(
        "Opened histogram maps, took {:?}",
        start.elapsed().as_secs_f64()
    );

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
