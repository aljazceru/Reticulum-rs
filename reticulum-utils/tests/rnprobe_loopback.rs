//! rnprobe loopback round trip (Phase 8 utilities).

#[tokio::test]
async fn probe_loopback_measures_rtt() {
    let _ = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn"),
    )
    .try_init();

    let (destination, results) = reticulum_utils::rnprobe::run_loopback()
        .await
        .expect("probe loopback");

    assert_eq!(results.len(), 1);
    assert!(results[0].rtt.as_secs() < 5, "loopback RTT must be small");
    let rendered = reticulum_utils::rnprobe::render_results(&destination, &results);
    assert!(rendered.contains("valid proof received"), "{rendered}");
    assert!(rendered.contains(&destination.to_string()), "{rendered}");
}
