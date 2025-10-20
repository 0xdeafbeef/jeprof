use aya::maps::{MapData, PerCpuHashMap};
use clap::ValueEnum;
use jeprofl_common::{Histogram, HistogramKey, MetricMode};
use std::time::Duration;

#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum, derive_more::Display)]
pub enum MetricKind {
    Count,
    Duration,
}

impl MetricKind {
    pub fn to_mode(self) -> MetricMode {
        match self {
            Self::Count => MetricMode::Count,
            Self::Duration => MetricMode::DurationNs,
        }
    }

    pub fn value_label(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Duration => "time (ns)",
        }
    }

    pub fn file_suffix(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Duration => "latency",
        }
    }
}

#[derive(Debug, Copy, Clone, derive_more::Display, derive_more::FromStr)]
pub enum OrderBy {
    Count,
    Traffic,
}

#[derive(Debug, Copy, Clone)]
pub struct MetricSpec {
    pub kind: MetricKind,
    pub skip_total_value_lt: u64,
    pub skip_total_count_lt: u64,
    pub value_label: &'static str,
}

impl MetricSpec {
    pub fn new(kind: MetricKind, skip_total_value_lt: u64, skip_total_count_lt: u64) -> Self {
        Self {
            kind,
            skip_total_value_lt,
            skip_total_count_lt,
            value_label: kind.value_label(),
        }
    }
}

pub struct MetricRuntime {
    pub spec: MetricSpec,
    pub map: PerCpuHashMap<MapData, HistogramKey, Histogram>,
}

impl MetricRuntime {
    pub fn new(spec: MetricSpec, map: PerCpuHashMap<MapData, HistogramKey, Histogram>) -> Self {
        Self { spec, map }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Retention {
    pub sweep_every: Duration,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            sweep_every: Duration::from_secs(60),
        }
    }
}
