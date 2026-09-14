//! The moment a header carries, in the two forms the technologies riding
//! on HTTP write it.
//!
//! RFC 1123's `Tue, 08 Sep 2026 12:00:00 GMT` is RFC 9110's `HTTP-date`,
//! what `Date` and Azure's `x-ms-date` take; the basic ISO 8601
//! `20260908T120000Z` is what `x-amz-date` takes and what a Signature
//! Version 4 scope opens with. Both come off one civil-from-days clock,
//! which s3 and azure-blob each carried until 2026-09-14; a header format
//! is HTTP's, so it lives with the carrier (ADR-0044).

use std::time::{SystemTime, UNIX_EPOCH};

/// `at` as RFC 1123 writes it: `Sun, 06 Nov 1994 08:49:37 GMT`.
#[must_use]
pub fn rfc1123(at: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = seconds(at);
    let days = secs.div_euclid(86_400);
    let (year, month, day) = civil(days);
    let rest = secs.rem_euclid(86_400);
    let weekday = usize::try_from((days + 4).rem_euclid(7)).unwrap_or(0);
    let month_name = usize::try_from(month - 1).map_or("Jan", |m| MONTHS[m % 12]);
    format!(
        "{}, {day:02} {month_name} {year:04} {:02}:{:02}:{:02} GMT",
        DAYS[weekday],
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// `at` as `x-amz-date` writes it: `20130524T000000Z`.
#[must_use]
pub fn amz_date(at: SystemTime) -> String {
    let secs = seconds(at);
    let (year, month, day) = civil(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// Seconds since the epoch, zero for a moment before it.
fn seconds(at: SystemTime) -> i64 {
    at.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| i64::try_from(since.as_secs()).ok())
        .unwrap_or(0)
}

/// Year, month and day of a day count since 1970-01-01 — Howard Hinnant's
/// civil-from-days.
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_date_is_written_as_rfc_1123_writes_it() {
        assert_eq!(rfc1123(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        let at = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(rfc1123(at), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert!(rfc1123(SystemTime::now()).ends_with(" GMT"));
    }

    #[test]
    fn the_date_is_written_as_amazon_writes_it() {
        let at = UNIX_EPOCH + Duration::from_secs(1_369_353_600);
        assert_eq!(amz_date(at), "20130524T000000Z");
        assert_eq!(amz_date(UNIX_EPOCH), "19700101T000000Z");
        let at = UNIX_EPOCH + Duration::from_secs(951_782_400 + 3_661);
        assert_eq!(amz_date(at), "20000229T010101Z");
        assert!(amz_date(SystemTime::now()).ends_with('Z'));
    }
}
