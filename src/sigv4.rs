//! Signature Version 4: what a request to an AWS service carries to prove
//! who sent it.
//!
//! The steps AWS documents, in order: a canonical form of the request, a
//! string to sign naming the moment and the scope, a signing key derived
//! from the secret through four HMACs, and the signature. Both sides are
//! here — a Location signs, a technology's session verifies — because
//! verifying is the same computation with a comparison at the end.
//!
//! One signer for every service: the scope names the service, and that is
//! the only place S3, SQS, SNS and Kinesis differ — except that S3 alone
//! asks for the payload hash in `x-amz-content-sha256`, and AWS's own
//! worked example for the Query API signs without it. s3 and aws-sqs each
//! carried this file until 2026-09-14, one with the service baked in and
//! one with it as a field; a signature over HTTP is shared through the
//! http technology (ADR-0044).

use std::time::SystemTime;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use transport::error::{Result, protocol_error};

use crate::date::amz_date;
use crate::message::Request;
use crate::percent::encode;
use crate::signature::{hex, same};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The header S3 alone asks the payload hash to travel in.
const PAYLOAD_HEADER: &str = "x-amz-content-sha256";

/// The service, region and credential a signature is made under.
#[derive(Clone, Debug)]
pub struct Signer {
    service: String,
    region: String,
    access_key: String,
    secret_key: String,
}

impl Signer {
    /// Sign for `service` — `s3`, `sqs`, `sns`, `kinesis` — in `region`
    /// as `access_key`.
    #[must_use]
    pub fn new(service: &str, region: &str, access_key: &str, secret_key: &str) -> Self {
        Self {
            service: service.to_string(),
            region: region.to_string(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
        }
    }

    /// Sign `request` as of `at`, an `x-amz-date` such as [`now`] gives,
    /// adding `x-amz-date`, `Authorization` and — for S3 —
    /// `x-amz-content-sha256`. Every header already on the request is
    /// signed, so `Host` goes on first.
    #[must_use]
    pub fn sign(&self, request: Request, at: &str) -> Request {
        let payload = hex(&Sha256::digest(&request.body));
        let mut request = request.header("x-amz-date", at);
        if self.hashes_in_a_header() {
            request = request.header(PAYLOAD_HEADER, &payload);
        }
        let signed = signed_headers(&request.headers);
        let scope = self.scope(at);
        let signature = self.signature(at, &scope, &canonical(&request, &signed, &payload));
        let authorization = format!(
            "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
            self.access_key
        );
        request.header("Authorization", &authorization)
    }

    /// Whether `request` carries the signature this signer would have made.
    ///
    /// # Errors
    /// Where the request has no usable `Authorization`, names another
    /// credential or scope, carries a payload hash its body does not match
    /// — or none where the service asks for one — or a signature that
    /// differs.
    pub fn verify(&self, request: &Request) -> Result<()> {
        let authorization = request
            .header_value("authorization")
            .ok_or_else(|| protocol_error("a request with no Authorization"))?;
        let (credential, signed, signature) = parts(authorization)?;
        let at = request
            .header_value("x-amz-date")
            .ok_or_else(|| protocol_error("a request with no x-amz-date"))?;
        let scope = self.scope(at);
        if credential != format!("{}/{scope}", self.access_key) {
            return Err(protocol_error("a credential this signer does not hold"));
        }
        let payload = hex(&Sha256::digest(&request.body));
        match request.header_value(PAYLOAD_HEADER) {
            Some(carried) if carried != payload => {
                return Err(protocol_error("a payload hash the body does not match"));
            }
            None if self.hashes_in_a_header() => {
                return Err(protocol_error("a request with no x-amz-content-sha256"));
            }
            _ => {}
        }
        let expected = self.signature(at, &scope, &canonical(request, signed, &payload));
        if same(&expected, signature) {
            Ok(())
        } else {
            Err(protocol_error("a signature that does not match"))
        }
    }

    /// S3 alone asks for the payload hash in a header of its own.
    fn hashes_in_a_header(&self) -> bool {
        self.service == "s3"
    }

    fn scope(&self, at: &str) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            date_of(at),
            self.region,
            self.service
        )
    }

    fn signature(&self, at: &str, scope: &str, canonical: &str) -> String {
        let to_sign = format!(
            "{ALGORITHM}\n{at}\n{scope}\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let key = [date_of(at), &self.region, &self.service, "aws4_request"]
            .iter()
            .fold(
                format!("AWS4{}", self.secret_key).into_bytes(),
                |key, step| hmac(&key, step.as_bytes()),
            );
        hex(&hmac(&key, to_sign.as_bytes()))
    }
}

/// The canonical request: method, path, sorted query, the signed headers
/// with their values, the list of their names, and the payload hash.
#[must_use]
pub fn canonical(request: &Request, signed: &str, payload_hash: &str) -> String {
    let mut query: Vec<String> = request
        .query
        .iter()
        .map(|(name, value)| format!("{}={}", encode(name, false), encode(value, false)))
        .collect();
    query.sort();
    let headers: Vec<String> = signed
        .split(';')
        .map(|name| {
            let value = request.header_value(name).unwrap_or("");
            format!(
                "{name}:{}\n",
                value.split_whitespace().collect::<Vec<_>>().join(" ")
            )
        })
        .collect();
    format!(
        "{}\n{}\n{}\n{}\n{signed}\n{payload_hash}",
        request.method,
        request.path,
        query.join("&"),
        headers.concat()
    )
}

/// The moment now, as `x-amz-date` writes it: `20260908T120000Z`.
#[must_use]
pub fn now() -> String {
    amz_date(SystemTime::now())
}

fn date_of(at: &str) -> &str {
    at.get(..8).unwrap_or(at)
}

fn signed_headers(headers: &[(String, String)]) -> String {
    let mut names: Vec<String> = headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect();
    names.sort();
    names.dedup();
    names.join(";")
}

fn parts(authorization: &str) -> Result<(&str, &str, &str)> {
    let rest = authorization
        .strip_prefix(ALGORITHM)
        .ok_or_else(|| protocol_error("an Authorization that is not Signature Version 4"))?;
    let mut credential = None;
    let mut signed = None;
    let mut signature = None;
    for part in rest.split(',') {
        match part.trim().split_once('=') {
            Some(("Credential", value)) => credential = Some(value),
            Some(("SignedHeaders", value)) => signed = Some(value),
            Some(("Signature", value)) => signature = Some(value),
            _ => {}
        }
    }
    match (credential, signed, signature) {
        (Some(credential), Some(signed), Some(signature)) => Ok((credential, signed, signature)),
        _ => Err(protocol_error(
            "an Authorization missing one of its three parts",
        )),
    }
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's own worked example, "GET Object" in the Signature Version 4
    /// signing examples for S3.
    #[test]
    fn the_documented_s3_example_signs_as_aws_says_it_does() {
        let signer = Signer::new(
            "s3",
            "us-east-1",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        let request = Request::new("GET", "/test.txt")
            .header("Host", "examplebucket.s3.amazonaws.com")
            .header("Range", "bytes=0-9");
        let sent = signer.sign(request, "20130524T000000Z");
        let authorization = sent.header_value("authorization").expect("signed");
        assert!(authorization.contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"));
        assert!(authorization.ends_with(
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        ));
        signer.verify(&sent).expect("its own signature");
        let mut bare = sent.clone();
        bare.headers.retain(|(name, _)| name != PAYLOAD_HEADER);
        assert!(
            signer.verify(&bare).is_err(),
            "S3 asks for the payload hash"
        );
    }

    /// AWS's own worked example for the Query API: IAM `ListUsers`, in
    /// "Create a signed AWS API request".
    #[test]
    fn the_documented_query_example_signs_as_aws_says_it_does() {
        let signer = Signer::new(
            "iam",
            "us-east-1",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        );
        let request = Request::new("GET", "/")
            .query("Action", "ListUsers")
            .query("Version", "2010-05-08")
            .header("Host", "iam.amazonaws.com")
            .header(
                "Content-Type",
                "application/x-www-form-urlencoded; charset=utf-8",
            );
        let sent = signer.sign(request, "20150830T123600Z");
        let authorization = sent.header_value("authorization").expect("signed");
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
        signer.verify(&sent).expect("its own signature");
    }

    #[test]
    fn a_tampered_request_another_secret_or_another_service_does_not_verify() {
        let signer = Signer::new("sqs", "eu-north-1", "AKID", "secret");
        let sent = signer.sign(
            Request::new("POST", "/123456789012/orders")
                .query("x", "1")
                .header("Host", "127.0.0.1:9000")
                .body(b"Action=SendMessage&MessageBody=UNA"),
            &now(),
        );
        signer.verify(&sent).expect("verifies");
        let mut tampered = sent.clone();
        tampered.body = b"Action=SendMessage&MessageBody=UNB".to_vec();
        assert!(signer.verify(&tampered).is_err(), "the payload is signed");
        let mut tampered = sent.clone();
        tampered.path = "/123456789012/other".to_string();
        assert!(signer.verify(&tampered).is_err(), "the path is signed");
        let mut tampered = sent.clone();
        tampered.query.push(("y".to_string(), "2".to_string()));
        assert!(signer.verify(&tampered).is_err(), "the query is signed");
        let other = Signer::new("sqs", "eu-north-1", "AKID", "other");
        assert!(other.verify(&sent).is_err());
        let other = Signer::new("sns", "eu-north-1", "AKID", "secret");
        assert!(other.verify(&sent).is_err(), "the scope names the service");
        let other = Signer::new("sqs", "eu-north-1", "OTHER", "secret");
        assert!(other.verify(&sent).is_err());
        assert!(signer.verify(&Request::new("GET", "/")).is_err());
        let bare = Request::new("GET", "/").header("Authorization", "Basic x");
        assert!(signer.verify(&bare).is_err());
        let carried = Signer::new("s3", "eu-north-1", "AKID", "secret")
            .sign(Request::new("PUT", "/b/k").body(b"UNA"), &now());
        let mut tampered = carried.clone();
        tampered.body = b"UNB".to_vec();
        assert!(
            Signer::new("s3", "eu-north-1", "AKID", "secret")
                .verify(&tampered)
                .is_err(),
            "the carried hash is checked against the body"
        );
    }
}
