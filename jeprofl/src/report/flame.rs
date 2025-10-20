use crate::core::collector::StatsAggregator;
use crate::core::model::OrderBy;
use anyhow::Result;
use inferno::flamegraph::Options;
use jeprofl_common::{Histogram, ReducedEventKey};
use rustc_hash::FxHashMap;
use std::io::Write;

pub fn write(
    mut writer: impl Write,
    stats: &FxHashMap<ReducedEventKey, Histogram>,
    aggregator: &StatsAggregator,
    order_by: OrderBy,
) -> Result<()> {
    let mut lines = Vec::new();

    for (key, hist) in stats.iter() {
        let Some(resolved) = aggregator.resolved(key.stack_id) else {
            continue;
        };
        let weight = match order_by {
            OrderBy::Count => hist.data.iter().sum::<u64>(),
            OrderBy::Traffic => hist.total,
        };

        if weight == 0 {
            continue;
        }

        lines.push(resolved.as_inferno_line(weight));
    }

    if lines.is_empty() {
        return Ok(());
    }

    let mut options = Options::default();
    options.reverse_stack_order = true;
    options.count_name = match order_by {
        OrderBy::Count => "event count".to_string(),
        OrderBy::Traffic => aggregator.value_label().to_string(),
    };

    let refs = lines.iter().map(|line| line.as_str()).collect::<Vec<_>>();
    inferno::flamegraph::from_lines(&mut options, refs, &mut writer)?;
    Ok(())
}
