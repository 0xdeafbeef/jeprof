use crate::core::collector::StatsAggregator;
use crate::report::pretty::write_histogram;
use anyhow::Result;
use jeprofl_common::{Histogram, ReducedEventKey};
use rustc_hash::FxHashMap;
use std::cmp::Reverse;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

const HEADERS: [&str; 6] = [
    "pid",
    "stack_id",
    "total",
    "count",
    "histogram",
    "stacktrace",
];

pub fn write(
    path: &Path,
    stats: &FxHashMap<ReducedEventKey, Histogram>,
    aggregator: &StatsAggregator,
) -> Result<()> {
    let file = File::create(path)?;
    let mut writer = csv::Writer::from_writer(BufWriter::new(file));
    writer.write_record(HEADERS)?;

    let mut entries: Vec<(&ReducedEventKey, &Histogram)> = stats.iter().collect();
    entries.sort_by_key(|(_, hist)| Reverse(hist.total));

    for (key, hist) in entries {
        let stacktrace = aggregator
            .resolved(key.stack_id)
            .map(|trace| {
                trace
                    .symbols
                    .iter()
                    .map(|frame| format!("{:x} - {}", frame.address, frame.symbol))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_else(|| "No resolved stacktrace".to_string());

        let mut histogram_text = String::new();
        write_histogram(hist, &mut histogram_text, aggregator.spec())?;

        writer.serialize((
            key.pid,
            key.stack_id,
            hist.total,
            hist.data.iter().sum::<u64>(),
            histogram_text,
            stacktrace,
        ))?;
    }

    writer.flush()?;
    Ok(())
}
