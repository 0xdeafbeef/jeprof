use jeprofl_common::Histogram;

pub fn hist_saturating_sub(current: &Histogram, previous: &Histogram) -> Histogram {
    let mut delta = Histogram::new();
    delta.total = current.total.saturating_sub(previous.total);
    for (dst, (cur, prev)) in delta
        .data
        .iter_mut()
        .zip(current.data.iter().zip(previous.data.iter()))
    {
        *dst = cur.saturating_sub(*prev);
    }
    delta
}

pub fn hist_merge(into: &mut Histogram, add: &Histogram) {
    into.merge(add);
}
