//! Minimal AWS Signature Version 4 signer (header based).

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use sha2::{Digest, Sha256};

/// RFC 3986 unreserved characters are left alone, everything else encoded.
const AWS_ENCODE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

pub fn aws_encode(s: &str) -> String {
    utf8_percent_encode(s, AWS_ENCODE).to_string()
}

pub struct Credentials<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub session_token: Option<&'a str>,
    pub region: &'a str,
    pub service: &'a str,
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

/// Compute the headers to add to a request so that it is SigV4 signed.
///
/// `headers` must contain every header that will be sent (lower-cased names);
/// they are all signed. Returns `(name, value)` pairs to append.
pub fn sign(
    creds: &Credentials<'_>,
    method: &str,
    url: &reqwest::Url,
    headers: &[(String, String)],
    body: &[u8],
    now: DateTime<Utc>,
) -> Vec<(String, String)> {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let payload_hash = hex::encode(Sha256::digest(body));

    let mut signed: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.trim().to_string()))
        .filter(|(k, _)| k != "authorization")
        .collect();
    let host = match url.port() {
        Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_string(),
    };
    signed.push(("host".into(), host));
    signed.push(("x-amz-date".into(), amz_date.clone()));
    let mut extra = vec![("x-amz-date".to_string(), amz_date.clone())];
    if let Some(tok) = creds.session_token.filter(|t| !t.is_empty()) {
        signed.push(("x-amz-security-token".into(), tok.to_string()));
        extra.push(("x-amz-security-token".into(), tok.to_string()));
    }
    signed.sort();
    signed.dedup_by(|a, b| a.0 == b.0);

    let canonical_headers: String = signed.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = signed
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let mut query: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (aws_encode(&k), aws_encode(&v)))
        .collect();
    query.sort();
    let canonical_query = query
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path,
        canonical_query,
        canonical_headers,
        signed_headers,
        payload_hash
    );
    let scope = format!("{date}/{}/{}/aws4_request", creds.region, creds.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac(
        format!("AWS4{}", creds.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac(&k_date, creds.region.as_bytes());
    let k_service = hmac(&k_region, creds.service.as_bytes());
    let k_signing = hmac(&k_service, b"aws4_request");
    let signature = hex::encode(hmac(&k_signing, string_to_sign.as_bytes()));

    extra.push((
        "authorization".into(),
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            creds.access_key
        ),
    ));
    extra
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    /// `get-vanilla` from the official AWS SigV4 test suite.
    #[test]
    fn aws_test_suite_get_vanilla() {
        let creds = Credentials {
            access_key: "AKIDEXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            session_token: None,
            region: "us-east-1",
            service: "service",
        };
        let url = reqwest::Url::parse("https://example.amazonaws.com/").unwrap();
        let now = Utc.with_ymd_and_hms(2015, 8, 30, 12, 36, 0).unwrap();
        let out = sign(&creds, "GET", &url, &[], b"", now);
        let auth = &out.iter().find(|(k, _)| k == "authorization").unwrap().1;
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }
}
