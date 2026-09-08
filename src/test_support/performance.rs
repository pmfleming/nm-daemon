//! Opt-in release benchmarks. No timing assertions or custom unsafe allocator.
use std::hint::black_box;
use std::time::Instant;

use anyhow::Result;

pub(crate) fn measure<T>(
    name: &str,
    iterations: usize,
    prepare: impl Fn() -> T,
    mut operation: impl FnMut(T) -> Result<()>,
) -> Result<()> {
    for _ in 0..5 {
        operation(prepare())?;
    }
    let mut samples = Vec::new();
    for _ in 0..5 {
        // Fixture construction is outside the timed window. External heap
        // profiling still includes it, startup, and the five warmup operations.
        let inputs = (0..iterations).map(|_| prepare()).collect::<Vec<_>>();
        let start = Instant::now();
        for input in inputs {
            operation(black_box(input))?;
        }
        samples.push(start.elapsed().as_nanos() / iterations as u128);
    }
    samples.sort();
    println!(
        "NM_BENCH {}",
        serde_json::json!({
            "name": name, "iterations_per_sample": iterations, "samples": samples.len(),
            "min_ns_per_iteration": samples[0], "median_ns_per_iteration": samples[2],
            "max_ns_per_iteration": samples[4],
        })
    );
    Ok(())
}

#[test]
#[ignore = "opt-in release timing/allocation benchmark"]
fn benchmark_wifi_status() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let _entered = runtime.enter();
    let fake = super::workflows::FakeNm::new([super::workflows::Outcome::Connected], false)?;
    fake.nm.add_and_activate_wifi_connection_for(
        &crate::model::example_connect_target(false),
        None,
        None,
    )?;
    assert!(fake.nm.wifi_status()?.active);
    measure(
        "wifi_status_fake_dbus",
        25,
        || (),
        |()| {
            black_box(fake.nm.wifi_status()?);
            Ok(())
        },
    )
}
