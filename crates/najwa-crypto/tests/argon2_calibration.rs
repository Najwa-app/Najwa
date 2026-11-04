//! S02 §6.3 calibration: on this device, calibrated parameters cost about the
//! one-second target. This test sits alone in its own test binary. Cargo runs
//! test binaries one at a time, so no parallel Argon2 test competes for CPU and
//! memory while it measures; on a shared 2-vCPU CI runner, running it beside
//! the identity tests made the same parameters take 5.9 s.
use std::time::Instant;

use najwa_crypto::prelude::*;

/// The identity crate's calibration target (S02 §6.3).
const TARGET_MS: u64 = 1_000;

#[test]
fn calibration_reaches_one_second() {
    // Use the normative 64 MiB floor. On desktops, 512 MiB at the minimum
    // three iterations may already be much slower than one second, and
    // calibration is forbidden from tuning downward.
    let params = calibrate_argon2(TARGET_MS, Argon2Params::ABSOLUTE_MIN.memory_kib).unwrap();

    let started = Instant::now();
    argon2id(&[0u8; 16], &[0u8; 32], &params).unwrap();
    let elapsed_ms = started.elapsed().as_millis() as u64;

    // Scheduling and thermal state vary between the calibration sample and
    // this one, so allow a tolerance band.
    assert!(
        elapsed_ms >= TARGET_MS * 8 / 10,
        "calibrated Argon2 ran too quickly: {elapsed_ms}ms"
    );
    assert!(
        elapsed_ms <= TARGET_MS * 5,
        "calibrated Argon2 exceeded tolerance: {elapsed_ms}ms"
    );
}
