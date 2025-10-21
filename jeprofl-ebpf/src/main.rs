#![no_std]
#![no_main]
#![expect(
    static_mut_refs,
    reason = "Aya eBPF maps require referencing `static mut` handles"
)]

use aya_ebpf::bindings::BPF_F_USER_STACK;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns};
use aya_ebpf::macros::{map, uprobe, uretprobe};
use aya_ebpf::maps::{LruHashMap, PerCpuArray, PerCpuHashMap, StackTrace};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use jeprofl_common::{Config, Histogram, HistogramKey, MetricMode, CONFIG_SLOT, COUNTER_SLOT};

#[map(name = "CONFIG_COUNT")]
static CONFIG_COUNT: PerCpuArray<Config> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "CONFIG_LATENCY")]
static CONFIG_LATENCY: PerCpuArray<Config> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "COUNTER_COUNT")]
static COUNTER_COUNT: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "COUNTER_LATENCY")]
static COUNTER_LATENCY: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "STACKTRACES")]
static mut STACKTRACES: StackTrace = StackTrace::with_max_entries(10_000, 0);

#[map(name = "HISTOGRAMS_COUNT")]
static mut HISTOGRAMS_COUNT: PerCpuHashMap<HistogramKey, Histogram> =
    PerCpuHashMap::with_max_entries(1024 * 1024, 0);

#[map(name = "HISTOGRAMS_LATENCY")]
static mut HISTOGRAMS_LATENCY: PerCpuHashMap<HistogramKey, Histogram> =
    PerCpuHashMap::with_max_entries(1024 * 1024, 0);

const MAX_LATENCY_STACK_DEPTH: usize = 8;
const MAX_LATENCY_STACK_DEPTH_U32: u32 = MAX_LATENCY_STACK_DEPTH as u32;

#[repr(C)]
struct LatencyStack {
    depth: u32,
    overflow: u32, // counts pushes that overflowed the fixed-size arrays
    ts: [u64; MAX_LATENCY_STACK_DEPTH],
    stack_ids: [i32; MAX_LATENCY_STACK_DEPTH],
}

#[map(name = "INFLIGHT_LATENCY")]
static mut INFLIGHT_LATENCY: LruHashMap<u64, LatencyStack> = LruHashMap::with_max_entries(10240, 0);

#[uprobe]
pub fn probe_count_entry(ctx: ProbeContext) -> u32 {
    try_probe_count_entry(ctx).unwrap_or(0)
}

fn try_probe_count_entry(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let cfg = match CONFIG_COUNT.get(CONFIG_SLOT) {
            Some(c) => *c,
            None => return Ok(0),
        };
        if cfg.mode != MetricMode::Count as u32 {
            return Ok(0);
        }
        if !should_sample_count(cfg.sample_every) {
            return Ok(0);
        }

        let stack_id = match STACKTRACES.get_stackid(&ctx, BPF_F_USER_STACK.into()) {
            Ok(stack_id) => stack_id as u32,
            Err(_) => return Ok(0),
        };

        let pid_tgid = bpf_get_current_pid_tgid();
        let tgid = (pid_tgid >> 32) as u32; // process id
        update_count_hist(1, tgid, stack_id);
    }
    Ok(0)
}

#[uprobe]
pub fn probe_latency_entry(ctx: ProbeContext) -> u32 {
    try_probe_latency_entry(ctx).unwrap_or(0)
}

fn try_probe_latency_entry(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let cfg = match CONFIG_LATENCY.get(CONFIG_SLOT) {
            Some(c) => *c,
            None => return Ok(0),
        };
        if cfg.mode != MetricMode::DurationNs as u32 {
            return Ok(0);
        }

        let sampled = should_sample_latency(cfg.sample_every);
        let key = bpf_get_current_pid_tgid(); // thread-unique inflight key
        let mut timestamp: u64 = 0;
        let mut stack_id: i32 = -1;

        if sampled {
            timestamp = bpf_ktime_get_ns();
            match STACKTRACES.get_stackid(&ctx, BPF_F_USER_STACK.into()) {
                Ok(id) => {
                    stack_id = id as i32;
                }
                Err(_) => {
                    timestamp = 0;
                    stack_id = -1;
                }
            }
        }

        match INFLIGHT_LATENCY.get_ptr_mut(&key) {
            None => {
                let mut stack = LatencyStack {
                    depth: 0,
                    overflow: 0,
                    ts: [0; MAX_LATENCY_STACK_DEPTH],
                    stack_ids: [-1; MAX_LATENCY_STACK_DEPTH],
                };
                push_latency_sample(&mut stack, timestamp, stack_id);
                let _ = INFLIGHT_LATENCY.insert(&key, &stack, 0);
            }
            Some(ptr) => {
                if let Some(stack) = ptr.as_mut() {
                    push_latency_sample(stack, timestamp, stack_id);
                }
            }
        }
    }
    Ok(0)
}

#[uretprobe]
pub fn probe_latency_ret(ctx: RetProbeContext) -> u32 {
    try_probe_latency_ret(ctx).unwrap_or(0)
}

fn try_probe_latency_ret(_ctx: RetProbeContext) -> Result<u32, u32> {
    unsafe {
        let cfg = match CONFIG_LATENCY.get(CONFIG_SLOT) {
            Some(c) => *c,
            None => return Ok(0),
        };
        if cfg.mode != MetricMode::DurationNs as u32 {
            return Ok(0);
        }

        let key = bpf_get_current_pid_tgid();
        let now = bpf_ktime_get_ns();

        let mut value: u64 = 0;
        let mut stored_stack_id: i32 = -1;
        let mut should_delete = false;

        if let Some(ptr) = INFLIGHT_LATENCY.get_ptr_mut(&key) {
            if let Some(stack) = ptr.as_mut() {
                let (start, sid) = pop_latency_sample(stack);
                if start != 0 && sid >= 0 {
                    value = now.saturating_sub(start);
                    stored_stack_id = sid;
                }
                if stack.depth == 0 && stack.overflow == 0 {
                    should_delete = true;
                }
            }
        }

        if should_delete {
            let _ = INFLIGHT_LATENCY.remove(&key);
        }

        if value == 0 {
            return Ok(0);
        }
        if value < cfg.min_value || value > cfg.max_value {
            return Ok(0);
        }

        let tgid = (key >> 32) as u32;
        if stored_stack_id < 0 {
            return Ok(0);
        }
        let stack_id = stored_stack_id as u32;
        update_latency_hist(value, tgid, stack_id);
    }
    Ok(0)
}

fn should_sample_count(sample_every: u32) -> bool {
    if sample_every <= 1 {
        return true;
    }
    let interval = sample_every as u64;
    let Some(ptr) = COUNTER_COUNT.get_ptr_mut(COUNTER_SLOT) else {
        return true;
    };
    let Some(counter) = (unsafe { ptr.as_mut() }) else {
        return true;
    };
    *counter = counter.wrapping_add(1);
    (*counter % interval) == 0
}

fn should_sample_latency(sample_every: u32) -> bool {
    if sample_every <= 1 {
        return true;
    }
    let interval = sample_every as u64;
    let Some(ptr) = COUNTER_LATENCY.get_ptr_mut(COUNTER_SLOT) else {
        return true;
    };
    let Some(counter) = (unsafe { ptr.as_mut() }) else {
        return true;
    };
    *counter = counter.wrapping_add(1);
    (*counter % interval) == 0
}

#[inline(always)]
unsafe fn update_count_hist(value: u64, tgid: u32, stack_id: u32) {
    let key = HistogramKey::new(tgid, stack_id);
    match HISTOGRAMS_COUNT.get_ptr_mut(&key) {
        None => {
            let mut histogram = Histogram::new();
            histogram.increment(value);
            let _ = HISTOGRAMS_COUNT.insert(&key, &histogram, 0);
        }
        Some(hist) => {
            if let Some(hist) = hist.as_mut() {
                hist.increment(value);
            }
        }
    }
}

#[inline(always)]
unsafe fn update_latency_hist(value: u64, tgid: u32, stack_id: u32) {
    let key = HistogramKey::new(tgid, stack_id);
    match HISTOGRAMS_LATENCY.get_ptr_mut(&key) {
        None => {
            let mut histogram = Histogram::new();
            histogram.increment(value);
            let _ = HISTOGRAMS_LATENCY.insert(&key, &histogram, 0);
        }
        Some(hist) => {
            if let Some(hist) = hist.as_mut() {
                hist.increment(value);
            }
        }
    }
}

#[inline(always)]
fn push_latency_sample(stack: &mut LatencyStack, ts: u64, stack_id: i32) {
    // Use the same variable for the check and the index so the verifier can track bounds
    let d_u32 = stack.depth;
    if d_u32 < MAX_LATENCY_STACK_DEPTH_U32 {
        let idx = d_u32 as usize;
        stack.ts[idx] = ts;
        stack.stack_ids[idx] = stack_id;
        // Safe increment since d_u32 < MAX
        stack.depth = d_u32 + 1;
    } else {
        stack.overflow = stack.overflow.saturating_add(1);
    }
}

#[inline(always)]
fn pop_latency_sample(stack: &mut LatencyStack) -> (u64, i32) {
    // First consume overflow "tickets" (no timing recorded)
    if stack.overflow > 0 {
        stack.overflow -= 1;
        return (0, -1);
    }

    let depth_u32 = stack.depth;
    if depth_u32 == 0 {
        return (0, -1);
    }

    // We will access index = depth - 1; bound it explicitly for the verifier
    let next_u32 = depth_u32 - 1;
    if next_u32 >= MAX_LATENCY_STACK_DEPTH_U32 {
        // Should never happen if push respects the bound, but keep safe for the verifier
        return (0, -1);
    }

    let idx = next_u32 as usize;
    stack.depth = next_u32;

    let ts = stack.ts[idx];
    stack.ts[idx] = 0;

    let sid = stack.stack_ids[idx];
    stack.stack_ids[idx] = -1;

    (ts, sid)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
