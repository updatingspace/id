//! Restricted Steam OpenID 2.0 relying party. No arbitrary OP/discovery URLs.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::NaiveDateTime;
use quick_xml::{NsReader, events::Event, name::ResolveResult};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;

pub(crate) const ENDPOINT: &str = "https://steamcommunity.com/openid/login";
pub(crate) const DISCOVERY: &str = "https://steamcommunity.com/openid/id/";
const NS: &str = "http://specs.openid.net/auth/2.0";
const SELECT: &str = "http://specs.openid.net/auth/2.0/identifier_select";
const SIGNON: &str = "http://specs.openid.net/auth/2.0/signon";
const FIELDS: [&str; 6] = [
    "op_endpoint",
    "claimed_id",
    "identity",
    "return_to",
    "response_nonce",
    "assoc_handle",
];
const AGE: Duration = Duration::from_secs(300);
const SKEW: Duration = Duration::from_secs(30);

pub(crate) fn parameters(raw: &str) -> Option<BTreeMap<String, String>> {
    if raw.len() > 8192 || !raw.is_ascii() {
        return None;
    }
    let mut params = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if !matches!(
            key.as_ref(),
            "state"
                | "openid.ns"
                | "openid.mode"
                | "openid.op_endpoint"
                | "openid.claimed_id"
                | "openid.identity"
                | "openid.return_to"
                | "openid.response_nonce"
                | "openid.assoc_handle"
                | "openid.signed"
                | "openid.sig"
                | "openid.invalidate_handle"
        ) || !value.is_ascii()
            || value.bytes().any(|b| b.is_ascii_control())
            || params
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return None;
        }
    }
    Some(params)
}

fn return_to(callback: &str, state: &str) -> Result<String> {
    let mut url = Url::parse(callback)?;
    url.query_pairs_mut().append_pair("state", state);
    Ok(url.into())
}

pub(crate) fn authorize(endpoint: &str, callback: &str, state: &str) -> Result<Url> {
    let mut url = Url::parse(endpoint)?;
    let callback_url = Url::parse(callback)?;
    url.query_pairs_mut()
        .append_pair("openid.ns", NS)
        .append_pair("openid.mode", "checkid_setup")
        .append_pair("openid.claimed_id", SELECT)
        .append_pair("openid.identity", SELECT)
        .append_pair("openid.return_to", &return_to(callback, state)?)
        .append_pair(
            "openid.realm",
            &format!("{}/", callback_url.origin().ascii_serialization()),
        );
    Ok(url)
}

pub(crate) fn denied(params: &BTreeMap<String, String>) -> bool {
    params.get("openid.ns").map(String::as_str) == Some(NS)
        && params.get("openid.mode").map(String::as_str) == Some("cancel")
}

pub(crate) struct Assertion {
    pub subject: String,
    pub nonce: String,
    pub expires: SystemTime,
}

fn assertion(
    params: &BTreeMap<String, String>,
    endpoint: &str,
    callback: &str,
    state: &str,
    now: SystemTime,
) -> Result<Assertion> {
    let field = |name: &str| {
        params
            .get(name)
            .map(String::as_str)
            .context("missing OpenID field")
    };
    ensure!(
        field("openid.ns")? == NS && field("openid.mode")? == "id_res",
        "invalid OpenID assertion"
    );
    ensure!(
        field("openid.op_endpoint")? == endpoint,
        "unexpected OpenID provider"
    );
    ensure!(
        field("openid.return_to")? == return_to(callback, state)?,
        "unexpected OpenID return_to"
    );
    let claimed = field("openid.claimed_id")?;
    ensure!(
        claimed == field("openid.identity")?,
        "delegated Steam identity is not supported"
    );
    // Both spellings were used by Steam and the retired adapter. Neither is a fetch URL.
    let subject = claimed
        .strip_prefix(DISCOVERY)
        .or_else(|| claimed.strip_prefix("http://steamcommunity.com/openid/id/"))
        .context("invalid Steam claimed ID")?;
    let number = subject.parse::<u64>().context("invalid Steam64 ID")?;
    ensure!(
        number > 0 && number.to_string() == subject,
        "noncanonical Steam64 ID"
    );
    let signed: Vec<_> = field("openid.signed")?.split(',').collect();
    ensure!(
        signed.len() == signed.iter().collect::<BTreeSet<_>>().len()
            && FIELDS.iter().all(|field| signed.contains(field))
            && signed
                .iter()
                .all(|name| params.contains_key(&format!("openid.{name}"))),
        "unsigned OpenID identity fields"
    );
    ensure!(
        !field("openid.assoc_handle")?.is_empty() && field("openid.assoc_handle")?.len() <= 256,
        "invalid association handle"
    );
    let sig = STANDARD
        .decode(field("openid.sig")?)
        .context("invalid OpenID signature encoding")?;
    ensure!(
        matches!(sig.len(), 20 | 32),
        "invalid OpenID signature length"
    );
    let nonce = field("openid.response_nonce")?;
    ensure!(
        (20..=255).contains(&nonce.len())
            && nonce.is_ascii()
            && nonce.as_bytes()[20..]
                .iter()
                .all(|byte| (33..=126).contains(byte)),
        "invalid OpenID nonce"
    );
    let timestamp = &nonce[..20];
    let parsed = NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%dT%H:%M:%SZ")?;
    ensure!(
        parsed.format("%Y-%m-%dT%H:%M:%SZ").to_string() == timestamp,
        "noncanonical nonce time"
    );
    let seconds = u64::try_from(parsed.and_utc().timestamp())?;
    let issued = UNIX_EPOCH + Duration::from_secs(seconds);
    ensure!(
        issued <= now + SKEW && now < issued + AGE,
        "expired or future OpenID nonce"
    );
    Ok(Assertion {
        subject: subject.to_owned(),
        nonce: nonce.to_owned(),
        expires: issued + AGE,
    })
}

async fn body(mut response: reqwest::Response) -> Result<Vec<u8>> {
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "Steam rejected verification"
    );
    ensure!(
        response.content_length().is_none_or(|size| size <= 16_384),
        "oversize Steam response"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 16_384,
            "oversize Steam response"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn discovery(bytes: &[u8], endpoint: &str, claimed: &str) -> Result<()> {
    // Steam currently serves this single-service XRDS profile directly. Redirects,
    // HTML discovery, external entities and alternate OPs deliberately fail closed.
    let mut reader = NsReader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut path = Vec::<String>::new();
    let mut fields = BTreeMap::<String, String>::new();
    let mut services = 0;
    let mut root = false;
    loop {
        let (ns, event) = reader.read_resolved_event()?;
        match event {
            Event::Start(tag) => {
                let name = tag.local_name().as_ref().to_owned();
                let expected_ns = if path.is_empty() {
                    "xri://$xrds"
                } else {
                    "xri://$xrd*($v*2.0)"
                };
                ensure!(
                    matches!(ns, ResolveResult::Bound(namespace) if namespace.as_ref() == expected_ns),
                    "unexpected XRDS namespace"
                );
                let valid =
                    (path.is_empty() && name == "XRDS") || (path == ["XRDS"] && name == "XRD");
                // Explicit path validation avoids accepting a lookalike URI outside Service.
                let valid = valid
                    || (path == ["XRDS", "XRD"] && name == "Service")
                    || (path == ["XRDS", "XRD", "Service"]
                        && matches!(name.as_str(), "Type" | "URI" | "LocalID"));
                ensure!(valid, "unexpected XRDS structure");
                if path.is_empty() {
                    ensure!(!root, "multiple XRDS roots");
                    root = true;
                }
                if name == "Service" {
                    services += 1;
                }
                if path.len() == 3 {
                    ensure!(!fields.contains_key(&name), "duplicate XRDS field");
                    fields.insert(name.clone(), String::new());
                }
                path.push(name);
            }
            Event::Text(text) => {
                let value = text.xml10_content();
                if path.len() == 4 {
                    fields
                        .get_mut(path.last().context("XRDS path")?)
                        .context("XRDS field")?
                        .push_str(&value);
                } else {
                    ensure!(value.trim().is_empty(), "unexpected XRDS text");
                }
            }
            Event::End(_) => {
                path.pop().context("unbalanced XRDS")?;
            }
            Event::Decl(_) | Event::Comment(_) => {}
            Event::Eof => break,
            _ => anyhow::bail!("unsupported XRDS markup"),
        }
    }
    ensure!(
        root && path.is_empty()
            && services == 1
            && fields.get("Type").map(String::as_str) == Some(SIGNON)
            && fields.get("URI").map(String::as_str) == Some(endpoint)
            && fields
                .get("LocalID")
                .is_none_or(|identity| identity == claimed),
        "Steam identity discovery mismatch"
    );
    Ok(())
}

fn valid_response(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes)?;
    ensure!(
        text.is_ascii() && !text.contains('\r') && text.ends_with('\n'),
        "invalid OpenID verification response"
    );
    let mut fields = BTreeMap::new();
    for line in text.split_terminator('\n') {
        let (name, value) = line
            .split_once(':')
            .context("invalid OpenID key/value response")?;
        ensure!(
            matches!(name, "ns" | "is_valid" | "invalidate_handle")
                && !value.bytes().any(|byte| byte.is_ascii_control())
                && fields.insert(name, value).is_none(),
            "duplicate or unknown OpenID response field"
        );
    }
    ensure!(
        fields.get("ns") == Some(&NS) && fields.get("is_valid") == Some(&"true"),
        "Steam assertion is not valid"
    );
    Ok(())
}

pub(crate) async fn verify(
    http: &reqwest::Client,
    endpoint: &str,
    discovery_base: &str,
    callback: &str,
    state: &str,
    params: &BTreeMap<String, String>,
    now: SystemTime,
) -> Result<Assertion> {
    let assertion = assertion(params, endpoint, callback, state, now)?;
    let xrds = body(
        http.get(format!("{discovery_base}{}", assertion.subject))
            .header("accept", "application/xrds+xml")
            .send()
            .await?,
    )
    .await?;
    discovery(
        &xrds,
        endpoint,
        params.get("openid.claimed_id").context("claimed ID")?,
    )?;
    let mut form: BTreeMap<_, _> = params
        .iter()
        .filter(|(key, _)| key.starts_with("openid."))
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    form.insert("openid.mode", "check_authentication");
    let checked = body(http.post(endpoint).form(&form).send().await?).await?;
    valid_response(&checked)?;
    // Network time may have consumed the nonce's acceptance window.
    ensure!(
        SystemTime::now() < assertion.expires,
        "OpenID nonce expired during verification"
    );
    Ok(assertion)
}

#[cfg(test)]
mod tests {
    use super::*;
    const CALLBACK: &str = "https://id.example.invalid/api/v1/auth/oauth/callback/steam";
    const CLAIMED: &str = "https://steamcommunity.com/openid/id/76561198000000001";
    fn fixture() -> Result<(BTreeMap<String, String>, SystemTime)> {
        let now = UNIX_EPOCH + Duration::from_secs(1_790_000_000);
        let nonce = chrono::DateTime::<chrono::Utc>::from(now)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
            + "nonce";
        let params = [
            ("state", "state".into()),
            ("openid.ns", NS.into()),
            ("openid.mode", "id_res".into()),
            ("openid.op_endpoint", ENDPOINT.into()),
            ("openid.claimed_id", CLAIMED.into()),
            ("openid.identity", CLAIMED.into()),
            ("openid.return_to", return_to(CALLBACK, "state")?),
            ("openid.response_nonce", nonce),
            ("openid.assoc_handle", "opaque".into()),
            ("openid.signed", FIELDS.join(",")),
            ("openid.sig", STANDARD.encode([1u8; 32])),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
        Ok((params, now))
    }
    #[test]
    fn nonce_window_has_exact_expiry_and_bounded_future_skew() -> Result<()> {
        let (params, now) = fixture()?;
        assert!(
            assertion(
                &params,
                ENDPOINT,
                CALLBACK,
                "state",
                now + Duration::from_secs(299)
            )
            .is_ok()
        );
        assert!(
            assertion(
                &params,
                ENDPOINT,
                CALLBACK,
                "state",
                now + Duration::from_secs(300)
            )
            .is_err()
        );
        assert!(
            assertion(
                &params,
                ENDPOINT,
                CALLBACK,
                "state",
                now - Duration::from_secs(30)
            )
            .is_ok()
        );
        assert!(
            assertion(
                &params,
                ENDPOINT,
                CALLBACK,
                "state",
                now - Duration::from_secs(31)
            )
            .is_err()
        );
        assert!(assertion(&params, ENDPOINT, CALLBACK, "different", now).is_err());
        Ok(())
    }
    #[test]
    fn direct_verification_is_a_strict_key_value_response() {
        assert!(valid_response(format!("ns:{NS}\nis_valid:true\n").as_bytes()).is_ok());
        for bad in [
            format!("ns:{NS}\nis_valid:true\nis_valid:false\n"),
            format!("ns:{NS}\nerror:is_valid:true\n"),
            format!("ns:{NS}\nis_valid:truejunk\n"),
            "is_valid:true\n".into(),
            format!("ns:{NS}\nis_valid:true\r\n"),
        ] {
            assert!(valid_response(bad.as_bytes()).is_err());
        }
        assert!(parameters("state=x&openid.mode=id_res&openid%2Emode=cancel").is_none());
        assert!(parameters("state=x&openid.response_nonce=abc%00").is_none());
        assert!(parameters("state=x&openid.op_endpoint=https%3A%2F%2Fexample.invalid").is_some());
    }
    #[test]
    fn discovery_requires_the_pinned_service_in_the_expected_namespace() {
        let xrds = format!(
            "<xrds:XRDS xmlns:xrds=\"xri://$xrds\" xmlns=\"xri://$xrd*($v*2.0)\"><XRD><Service><Type>{SIGNON}</Type><URI>{ENDPOINT}</URI></Service></XRD></xrds:XRDS>"
        );
        assert!(discovery(xrds.as_bytes(), ENDPOINT, CLAIMED).is_ok());
        for bad in [
            xrds.replace(ENDPOINT, "http://169.254.169.254/"),
            xrds.replace("xri://$xrd*($v*2.0)", "urn:wrong"),
            xrds.replace(
                "</Service>",
                "<LocalID>https://attacker.invalid/</LocalID></Service>",
            ),
            format!("<!DOCTYPE xrds [<!ENTITY remote SYSTEM 'file:///etc/passwd'>]>{xrds}"),
            xrds.replace("</Service>", &format!("<URI>{ENDPOINT}</URI></Service>")),
        ] {
            assert!(discovery(bad.as_bytes(), ENDPOINT, CLAIMED).is_err());
        }
    }
}
