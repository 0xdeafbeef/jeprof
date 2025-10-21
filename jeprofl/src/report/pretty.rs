use crate::core::collector::StatsAggregator;
use crate::core::model::{MetricKind, MetricSpec, OrderBy};
use anyhow::Result;
use jeprofl_common::{Histogram, ReducedEventKey};
use jiff::{
    fmt::friendly::{Designator, FractionalUnit, SpanPrinter},
    Span,
};
use rustc_hash::FxHashMap;
use std::fmt::{self, Write};
use std::sync::OnceLock;

const SECTION_WIDTH: usize = 80;
const BAR_WIDTH: usize = 50;
const LABEL_WIDTH_DURATION: usize = 24;
const HUMAN_WIDTH: usize = 18;
const LABEL_WIDTH_COUNT: usize = 10;
const COUNT_WIDTH: usize = 9;
const PERCENT_WIDTH: usize = 9;
const PERCENT_NUMBER_WIDTH: usize = PERCENT_WIDTH - 1;

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
        write_histogram(hist, writer, aggregator.spec())?;
        writeln!(writer)?;
    }

    Ok(())
}

pub fn write_histogram(hist: &Histogram, writer: &mut impl Write, spec: MetricSpec) -> Result<()> {
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

    match spec.kind {
        MetricKind::Duration => write_duration_header(writer)?,
        MetricKind::Count => write_count_header(writer)?,
    };

    for (bucket, count) in entries {
        let percentage = if total_count == 0 {
            0.0
        } else {
            (count as f64 / total_count as f64) * 100.0
        };
        let bar_length = ((count as f64 / max_count as f64) * BAR_WIDTH as f64).round() as usize;
        match spec.kind {
            MetricKind::Duration => {
                let (absolute, human) = format_duration_bucket(bucket_upper_bound(bucket));
                write_duration_row(writer, &absolute, &human, count, percentage, bar_length)?
            }
            MetricKind::Count => write_count_row(
                writer,
                &format!("<={}", bucket_upper_bound(bucket)),
                count,
                percentage,
                bar_length,
            )?,
        }
    }

    writeln!(
        writer,
        "Total {}: {}{} across {} events",
        spec.value_label,
        hist.total,
        match spec.kind {
            MetricKind::Duration => total_human_time(hist.total),
            MetricKind::Count => String::new(),
        },
        total_count
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

fn format_duration_bucket(ns: u64) -> (String, String) {
    let absolute = format!("<={ns}");
    let human = humanize_ns(ns).unwrap_or_else(|| String::from("-"));
    (absolute, human)
}

fn total_human_time(total_ns: u64) -> String {
    humanize_ns(total_ns)
        .map(|value| format!(" ({value})"))
        .unwrap_or_default()
}

fn humanize_ns(ns: u64) -> Option<String> {
    if ns == u64::MAX || ns > i64::MAX as u64 {
        return None;
    }
    let span = Span::new().nanoseconds(ns as i64);
    Some(human_printer().span_to_string(&span))
}

fn human_printer() -> &'static SpanPrinter {
    static PRINTER: OnceLock<SpanPrinter> = OnceLock::new();
    PRINTER.get_or_init(|| {
        SpanPrinter::new()
            .designator(Designator::HumanTime)
            .fractional(Some(FractionalUnit::Second))
    })
}

fn write_duration_header(writer: &mut impl Write) -> Result<()> {
    writeln!(
        writer,
        "{:<label_width$} | {:<human_width$} | {:>count_width$} | {:>percent_width$} | {}",
        "≤UpperBound (ns)",
        "Human",
        "Count",
        "Percentage",
        "#".repeat(BAR_WIDTH),
        label_width = LABEL_WIDTH_DURATION,
        human_width = HUMAN_WIDTH,
        count_width = COUNT_WIDTH,
        percent_width = PERCENT_WIDTH,
    )?;
    writeln!(
        writer,
        "{}+{}+{}+{}+{}",
        "-".repeat(LABEL_WIDTH_DURATION),
        "-".repeat(HUMAN_WIDTH + 2),
        "-".repeat(COUNT_WIDTH + 2),
        "-".repeat(PERCENT_WIDTH + 2),
        "-".repeat(BAR_WIDTH),
    )?;
    Ok(())
}

fn write_duration_row(
    writer: &mut impl Write,
    absolute: &str,
    human: &str,
    count: u64,
    percentage: f64,
    bar_length: usize,
) -> Result<()> {
    let percentage_formatted = format!("{percentage:>width$.2}%", width = PERCENT_NUMBER_WIDTH);
    writeln!(
        writer,
        "{:<label_width$} | {:<human_width$} | {:>count_width$} | {:>percent_width$} | {}",
        absolute,
        human,
        count,
        percentage_formatted,
        "#".repeat(bar_length),
        label_width = LABEL_WIDTH_DURATION,
        human_width = HUMAN_WIDTH,
        count_width = COUNT_WIDTH,
        percent_width = PERCENT_WIDTH,
    )?;
    Ok(())
}

fn write_count_header(writer: &mut impl Write) -> Result<()> {
    writeln!(
        writer,
        "{:<label_width$} | {:>count_width$} | {:>percent_width$} | {}",
        "≤UpperBound",
        "Count",
        "Percentage",
        "#".repeat(BAR_WIDTH),
        label_width = LABEL_WIDTH_COUNT,
        count_width = COUNT_WIDTH,
        percent_width = PERCENT_WIDTH,
    )?;
    writeln!(
        writer,
        "{}+{}+{}+{}",
        "-".repeat(LABEL_WIDTH_COUNT),
        "-".repeat(COUNT_WIDTH + 2),
        "-".repeat(PERCENT_WIDTH + 2),
        "-".repeat(BAR_WIDTH),
    )?;
    Ok(())
}

fn write_count_row(
    writer: &mut impl Write,
    absolute: &str,
    count: u64,
    percentage: f64,
    bar_length: usize,
) -> Result<()> {
    let percentage_formatted = format!("{percentage:>width$.2}%", width = PERCENT_NUMBER_WIDTH);
    writeln!(
        writer,
        "{:<label_width$} | {:>count_width$} | {:>percent_width$} | {}",
        absolute,
        count,
        percentage_formatted,
        "#".repeat(bar_length),
        label_width = LABEL_WIDTH_COUNT,
        count_width = COUNT_WIDTH,
        percent_width = PERCENT_WIDTH,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{MetricKind, MetricSpec};
    use jeprofl_common::Histogram;

    #[test]
    fn histogram_empty() {
        let histogram = Histogram::new();
        let mut buf = String::new();
        write_histogram(
            &histogram,
            &mut buf,
            MetricSpec::new(MetricKind::Count, 0, 0),
        )
        .unwrap();
        insta::assert_snapshot!(buf);
    }

    #[test]
    fn histogram_single_value() {
        let mut histogram = Histogram::new();
        histogram.increment(1023);
        let mut buf = String::new();
        write_histogram(
            &histogram,
            &mut buf,
            MetricSpec::new(MetricKind::Count, 0, 0),
        )
        .unwrap();
        insta::assert_snapshot!(buf);
    }

    #[test]
    fn histogram_multiple_sizes() {
        let mut histogram = Histogram::new();
        histogram.increment(1);
        histogram.increment(512);
        histogram.increment(1026);
        let mut buf = String::new();
        write_histogram(
            &histogram,
            &mut buf,
            MetricSpec::new(MetricKind::Count, 0, 0),
        )
        .unwrap();
        insta::assert_snapshot!(buf);
    }

    #[test]
    fn histogram_large_values() {
        let mut histogram = Histogram::new();
        histogram.increment(1 << 20);
        histogram.increment(1u64 << 30);
        let mut buf = String::new();
        write_histogram(
            &histogram,
            &mut buf,
            MetricSpec::new(MetricKind::Count, 0, 0),
        )
        .unwrap();
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
        write_histogram(
            &histogram,
            &mut buf,
            MetricSpec::new(MetricKind::Count, 0, 0),
        )
        .unwrap();
        insta::assert_snapshot!(buf);
    }

    #[test]
    fn histogram_duration_humanized() {
        let mut histogram = Histogram::new();
        histogram.increment(1);
        histogram.increment(3_451);
        histogram.increment(1_073_741_823);
        let mut buf = String::new();
        write_histogram(
            &histogram,
            &mut buf,
            MetricSpec::new(MetricKind::Duration, 0, 0),
        )
        .unwrap();
        insta::assert_snapshot!(buf);
    }
}
