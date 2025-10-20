use crate::core::collector::StatsAggregator;
use crate::core::model::OrderBy;
use anyhow::Result;
use jeprofl_common::{Histogram, ReducedEventKey};
use rustc_hash::FxHashMap;
use std::fmt::{self, Write};

const SECTION_WIDTH: usize = 80;
const BAR_WIDTH: usize = 50;

pub fn render(
    writer: &mut impl Write,
    stats: &FxHashMap<ReducedEventKey, Histogram>,
    order_by: OrderBy,
    aggregator: &StatsAggregator,
) -> Result<()> {
    let mut entries: Vec<(&ReducedEventKey, &Histogram)> = stats
        .iter()
        .filter(|(_, hist)| hist.total_count() > 0)
        .collect();

    entries.sort_by_key(|(_, hist)| match order_by {
        OrderBy::Count => hist.data.iter().sum::<u64>(),
        OrderBy::Traffic => hist.total,
    });
    entries.reverse();

    writeln!(writer, "total stack traces: {}\n", entries.len())?;

    for (key, hist) in entries {
        write_section(writer, '*')?;
        if let Some(resolved) = aggregator.resolved(key.stack_id) {
            for frame in &resolved.symbols {
                writeln!(writer, "{:x} - {}", frame.address, frame.symbol)?;
            }
        } else {
            writeln!(writer, "No resolved stacktrace")?;
        }
        write_section(writer, '-')?;
        write_histogram(hist, writer, aggregator.value_label())?;
        writeln!(writer)?;
    }

    Ok(())
}

pub fn write_histogram(hist: &Histogram, writer: &mut impl Write, value_label: &str) -> Result<()> {
    let mut entries: Vec<(usize, u64)> = hist
        .data
        .iter()
        .enumerate()
        .filter(|(_, &count)| count > 0)
        .map(|(index, &count)| (index, count))
        .collect();
    entries.sort_by_key(|&(bucket, _)| bucket);

    let max_count = entries.iter().map(|&(_, count)| count).max().unwrap_or(1);
    let total_count: u64 = entries.iter().map(|&(_, count)| count).sum();

    writeln!(
        writer,
        "≤UpperBound | Count     | Percentage | {}",
        "#".repeat(BAR_WIDTH)
    )?;
    writeln!(
        writer,
        "----------+-----------+------------+{}",
        "-".repeat(BAR_WIDTH)
    )?;

    for (bucket, count) in entries {
        let percentage = if total_count == 0 {
            0.0
        } else {
            (count as f64 / total_count as f64) * 100.0
        };
        let bar_length = ((count as f64 / max_count as f64) * BAR_WIDTH as f64).round() as usize;
        writeln!(
            writer,
            "{:10} | {:9} | {:9.2}% | {}",
            format!("<={}", bucket_upper_bound(bucket)),
            count,
            percentage,
            "#".repeat(bar_length)
        )?;
    }

    writeln!(
        writer,
        "Total {value_label}: {} across {} events",
        hist.total, total_count
    )?;

    Ok(())
}

fn write_section(writer: &mut impl Write, fill: char) -> fmt::Result {
    for _ in 0..SECTION_WIDTH {
        writer.write_char(fill)?;
    }
    writer.write_char('\n')
}

fn bucket_upper_bound(index: usize) -> u64 {
    if index + 1 >= jeprofl_common::HISTOGRAM_BUCKETS {
        u64::MAX
    } else {
        (1u64 << (index + 1)) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jeprofl_common::Histogram;

    #[test]
    fn histogram_empty() {
        let histogram = Histogram::new();
        let mut buf = String::new();
        write_histogram(&histogram, &mut buf, "value").unwrap();
        insta::assert_snapshot!(buf);
    }

    #[test]
    fn histogram_single_value() {
        let mut histogram = Histogram::new();
        histogram.increment(1023);
        let mut buf = String::new();
        write_histogram(&histogram, &mut buf, "value").unwrap();
        insta::assert_snapshot!(buf);
    }

    #[test]
    fn histogram_multiple_sizes() {
        let mut histogram = Histogram::new();
        histogram.increment(1);
        histogram.increment(512);
        histogram.increment(1026);
        let mut buf = String::new();
        write_histogram(&histogram, &mut buf, "value").unwrap();
        insta::assert_snapshot!(buf);
    }

    #[test]
    fn histogram_large_values() {
        let mut histogram = Histogram::new();
        histogram.increment(1 << 20);
        histogram.increment(1u64 << 30);
        let mut buf = String::new();
        write_histogram(&histogram, &mut buf, "value").unwrap();
        insta::assert_snapshot!(buf);
    }

    #[test]
    fn histogram_many_small_values() {
        let mut histogram = Histogram::new();
        for _ in 0..1000 {
            histogram.increment(1);
        }
        histogram.increment(1023);
        let mut buf = String::new();
        write_histogram(&histogram, &mut buf, "value").unwrap();
        insta::assert_snapshot!(buf);
    }
}
