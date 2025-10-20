use crate::core::merge::{hist_merge, hist_saturating_sub};
use crate::core::model::{MetricKind, MetricRuntime, MetricSpec, Retention};
use crate::core::resolver::{BlazeResolver, ResolvedStackTrace, SymbolResolver};
use aya::maps::{MapData, PerCpuHashMap, StackTraceMap};
use jeprofl_common::{Histogram, HistogramKey, ReducedEventKey, UnpackedHistogramKey};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::hash_map::Entry;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_secs(1);

pub struct CollectorHandle {
    join: JoinHandle<Vec<(MetricKind, StatsAggregator)>>,
}

impl CollectorHandle {
    pub fn join(self) -> anyhow::Result<Vec<(MetricKind, StatsAggregator)>> {
        self.join.join().map_err(|err| {
            if let Some(msg) = err.downcast_ref::<&str>() {
                anyhow::anyhow!("collector thread panicked: {msg}")
            } else if let Some(msg) = err.downcast_ref::<String>() {
                anyhow::anyhow!("collector thread panicked: {msg}")
            } else {
                anyhow::anyhow!("collector thread panicked")
            }
        })
    }
}

pub fn run_collector_thread(
    metrics: Vec<MetricRuntime>,
    canceled: Arc<AtomicBool>,
    stack_trace_map: StackTraceMap<MapData>,
    retention: Retention,
) -> CollectorHandle {
    let join = thread::spawn(move || {
        let resolver = BlazeResolver::new();
        let mut workers: Vec<MetricWorker> = metrics
            .into_iter()
            .map(|metric| MetricWorker {
                map: metric.map,
                aggregator: StatsAggregator::new(metric.spec),
                keys_to_drop: FxHashSet::default(),
            })
            .collect();

        let mut last_cleanup = Instant::now();

        while !canceled.load(Ordering::Acquire) {
            thread::sleep(POLL_INTERVAL);

            for worker in workers.iter_mut() {
                let spec = worker.aggregator.spec();

                let iter = worker.map.iter();
                for entry in iter {
                    let (key, per_cpu_histograms) = match entry {
                        Ok(value) => value,
                        Err(err) => {
                            log::warn!("Failed to read map entry: {err}");
                            continue;
                        }
                    };

                    let unpacked = key.into_parts();
                    let mut skipped_on_all_cpus = true;

                    for (cpu, hist) in per_cpu_histograms.iter().enumerate() {
                        if hist.total < spec.skip_total_value_lt
                            && hist.total_count() < spec.skip_total_count_lt
                        {
                            continue;
                        }

                        skipped_on_all_cpus = false;
                        worker.aggregator.ingest_snapshot(unpacked, hist, cpu);

                        if let Err(err) = worker.aggregator.ensure_resolved(
                            unpacked.stack_id,
                            unpacked.pid,
                            &stack_trace_map,
                            &resolver,
                        ) {
                            log::debug!(
                                "Failed to resolve stack {} (pid {}): {err}",
                                unpacked.stack_id,
                                unpacked.pid
                            );
                        }

                        if canceled.load(Ordering::Acquire) {
                            break;
                        }
                    }

                    if skipped_on_all_cpus {
                        worker.keys_to_drop.insert(key);
                    } else {
                        worker.keys_to_drop.remove(&key);
                    }

                    if canceled.load(Ordering::Acquire) {
                        break;
                    }
                }

                if canceled.load(Ordering::Acquire) {
                    break;
                }
            }

            if last_cleanup.elapsed() >= retention.sweep_every {
                for worker in workers.iter_mut() {
                    for key in worker.keys_to_drop.drain() {
                        if let Err(err) = worker.map.remove(&key) {
                            log::debug!("Failed to drop key {key:?} from map: {err}");
                        }
                    }
                }
                last_cleanup = Instant::now();
            }
        }

        workers
            .into_iter()
            .map(|worker| (worker.aggregator.kind(), worker.aggregator))
            .collect()
    });

    CollectorHandle { join }
}

struct MetricWorker {
    map: PerCpuHashMap<MapData, HistogramKey, Histogram>,
    aggregator: StatsAggregator,
    keys_to_drop: FxHashSet<HistogramKey>,
}

pub struct StatsAggregator {
    spec: MetricSpec,
    totals: FxHashMap<ReducedEventKey, Histogram>,
    last_seen: FxHashMap<(ReducedEventKey, usize), Histogram>,
    resolved_traces: FxHashMap<u32, ResolvedStackTrace>,
}

impl StatsAggregator {
    pub fn new(spec: MetricSpec) -> Self {
        Self {
            spec,
            totals: FxHashMap::default(),
            last_seen: FxHashMap::default(),
            resolved_traces: FxHashMap::default(),
        }
    }

    pub fn spec(&self) -> MetricSpec {
        self.spec
    }

    pub fn kind(&self) -> MetricKind {
        self.spec.kind
    }

    pub fn value_label(&self) -> &'static str {
        self.spec.value_label
    }

    pub fn ingest_snapshot(&mut self, key: UnpackedHistogramKey, current: &Histogram, cpu: usize) {
        let reduced = key.as_reduced();
        let cpu_key = (reduced, cpu);

        let previous = self.last_seen.insert(cpu_key, *current);
        let delta = match previous {
            Some(prev) => hist_saturating_sub(current, &prev),
            None => *current,
        };

        if delta.total == 0 && delta.total_count() == 0 {
            return;
        }

        let entry = self.totals.entry(reduced).or_insert_with(Histogram::new);
        hist_merge(entry, &delta);
    }

    pub fn ensure_resolved<R: SymbolResolver>(
        &mut self,
        stack_id: u32,
        pid: u32,
        stack_traces: &StackTraceMap<MapData>,
        resolver: &R,
    ) -> anyhow::Result<()> {
        match self.resolved_traces.entry(stack_id) {
            Entry::Occupied(_) => Ok(()),
            Entry::Vacant(entry) => {
                let trace = stack_traces
                    .get(&stack_id, 0)
                    .map_err(|err| anyhow::anyhow!("stack trace lookup failed: {err}"))?;
                let resolved = resolver.resolve_stacktrace(&trace, pid)?;
                entry.insert(resolved);
                Ok(())
            }
        }
    }

    pub fn merged(&self) -> FxHashMap<ReducedEventKey, Histogram> {
        self.totals.clone()
    }

    pub fn resolved(&self, stack_id: u32) -> Option<&ResolvedStackTrace> {
        self.resolved_traces.get(&stack_id)
    }
}
