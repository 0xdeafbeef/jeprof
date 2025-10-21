#![no_std]

pub const CONFIG_SLOT: u32 = 0;
pub const COUNTER_SLOT: u32 = 0;

pub const HISTOGRAM_BUCKETS: usize = 40;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricMode {
    Count = 0,
    DurationNs = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub mode: u32,
    pub min_value: u64,
    pub max_value: u64,
    pub sample_every: u32,
    pub _pad: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Config {}

#[repr(C)]
#[derive(Clone, Debug, Copy, Hash, PartialEq, Eq)]
pub struct HistogramKey {
    pid_stack: u64,
}

impl HistogramKey {
    pub fn new(pid: u32, stack_id: u32) -> Self {
        Self {
            pid_stack: ((pid as u64) << 32) | (stack_id as u64),
        }
    }

    pub fn into_parts(&self) -> UnpackedHistogramKey {
        let pid = (self.pid_stack >> 32) as u32;
        let stack_id = self.pid_stack as u32;
        UnpackedHistogramKey { pid, stack_id }
    }
}

#[derive(Clone, Debug, Copy, Hash, Eq, PartialEq)]
pub struct UnpackedHistogramKey {
    pub pid: u32,
    pub stack_id: u32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ReducedEventKey {
    pub pid: u32,
    pub stack_id: u32,
}

impl UnpackedHistogramKey {
    pub fn as_reduced(&self) -> ReducedEventKey {
        ReducedEventKey {
            pid: self.pid,
            stack_id: self.stack_id,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for HistogramKey {}

#[repr(C)]
#[derive(Clone, Debug, Copy)]
pub struct Histogram {
    pub data: [u64; HISTOGRAM_BUCKETS],
    pub total: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Histogram {}

impl Histogram {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            data: [0; HISTOGRAM_BUCKETS],
            total: 0,
        }
    }

    pub fn increment(&mut self, value: u64) {
        if value == 0 {
            // log(0) is undefined
            return;
        }
        let mut pow2 = value.ilog2() as usize;
        if pow2 >= self.data.len() {
            pow2 = self.data.len() - 1;
        }
        self.data[pow2] = self.data[pow2].saturating_add(1);
        self.total = self.total.saturating_add(value);
    }

    pub fn merge(&mut self, other: &Histogram) {
        self.total = self.total.saturating_add(other.total);
        for (l, r) in self.data.iter_mut().zip(other.data.iter()) {
            *l = l.saturating_add(*r);
        }
    }

    pub fn total_count(&self) -> u64 {
        self.data.iter().sum()
    }
}
