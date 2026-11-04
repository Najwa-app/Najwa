use super::*;

#[test]
fn consensus_does_not_rewind_an_already_correct_clock() {
    let clock = TorClockSync::new();
    let now = system_time_secs();
    assert_eq!(
        clock
            .synchronize_from_consensus(now - 1800, now + 9000)
            .unwrap(),
        0
    );
    assert!(clock.now().abs_diff(now) <= 1);
}

#[test]
fn consensus_only_moves_clock_to_nearest_valid_boundary() {
    let clock = TorClockSync::new();
    let now = system_time_secs();
    assert!(
        clock
            .synchronize_from_consensus(now + 600, now + 1200)
            .unwrap()
            .abs_diff(600)
            <= 1
    );
    assert!(clock.now().abs_diff(now + 600) <= 1);
    assert!(
        clock
            .synchronize_from_consensus(now - 1200, now - 600)
            .unwrap()
            .abs_diff(-601)
            <= 1
    );
    assert!(clock.now().abs_diff(now - 601) <= 1);
}

#[test]
fn invalid_intervals_and_estimates_leave_offset_unchanged() {
    let clock = TorClockSync::new();
    clock
        .synchronize_from_estimates(&[system_time_secs() + 60])
        .unwrap();
    let offset = clock.offset();
    for (a, b) in [(1, 1), (2, 1), (0, 86401), (1, u64::MAX)] {
        assert!(clock.synchronize_from_consensus(a, b).is_err());
        assert_eq!(clock.offset(), offset);
    }
    assert!(clock.synchronize_from_estimates(&[u64::MAX]).is_err());
    assert_eq!(clock.offset(), offset);
}

#[test]
fn clock_arithmetic_saturates_without_wrapping() {
    assert_eq!(apply_offset(0, i64::MIN), 0);
    assert_eq!(apply_offset(u64::MAX, i64::MAX), u64::MAX);
    assert_eq!(apply_offset(100, -50), 50);
}

#[test]
fn dates_reject_impossible_fields_and_unbounded_years() {
    for date in [
        "Thu, 32 Jan 2026 00:00:00 GMT",
        "Thu, 00 Jan 2026 00:00:00 GMT",
        "Tue, 29 Feb 2100 00:00:00 GMT",
        "Thu, 01 Jan 2026 24:00:00 GMT",
        "Thu, 01 Jan 2026 00:60:00 GMT",
        "Thu, 01 Jan 2026 00:00:60 GMT",
        "Thu, 01 Jan 2026 00:00:00 UTC",
        "Fri, 01 Jan 2026 00:00:00 GMT",
        "Thu, 01 Jan 2147483647 00:00:00 GMT",
        "Wed, 31 Dec 1969 23:59:59 GMT",
        "Thu, 1 Jan 2026 00:00:00 GMT",
        "Thu, 01 Jan 2026 00:00:00 GMT extra",
    ] {
        assert!(parse_http_date(date).is_err(), "{date}");
    }
}

#[test]
fn valid_dates_cover_epoch_leap_century_and_upper_bound() {
    for (date, expected) in [
        ("Thu, 01 Jan 1970 00:00:00 GMT", 0),
        ("Tue, 29 Feb 2000 12:34:56 GMT", 951827696),
        ("Fri, 31 Dec 9999 23:59:59 GMT", 253402300799),
    ] {
        assert_eq!(parse_http_date(date).unwrap(), expected);
    }
}
