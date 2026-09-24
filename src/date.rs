//! The moment a header carries, as RFC 1123 writes it:
//! `Tue, 08 Sep 2026 12:00:00 GMT`, RFC 9110's `HTTP-date`, what `Date`
//! and Azure's `x-ms-date` take. It is written off `codec::civil`, the
//! estate's one civil calendar; s3 and azure-blob each carried the clock
//! until 2026-09-14, and this file until 2026-09-24. A header format is
//! HTTP's, so it lives with the carrier (ADR-0044).
//!
//! `x-amz-date`, the basic ISO 8601 `20260908T120000Z`, lived here beside
//! it until 2026-09-24; it is AWS's, and is written by the signer in
//! `xmip-core-transport-aws` that reads it.

use std::time::SystemTime;

use codec::civil::CivilTime;

/// `at` as RFC 1123 writes it: `Sun, 06 Nov 1994 08:49:37 GMT`.
#[must_use]
pub fn rfc1123(at: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let moment = CivilTime::from_system_time(at);
    let weekday = DAYS[moment.weekday() as usize % 7];
    let month = MONTHS[(moment.month as usize + 11) % 12];
    format!(
        "{weekday}, {:02} {month} {:04} {:02}:{:02}:{:02} GMT",
        moment.day, moment.year, moment.hour, moment.minute, moment.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn the_date_is_written_as_rfc_1123_writes_it() {
        assert_eq!(rfc1123(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        let at = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(rfc1123(at), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert!(rfc1123(SystemTime::now()).ends_with(" GMT"));
    }
}
