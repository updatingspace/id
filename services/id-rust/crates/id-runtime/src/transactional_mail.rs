//! Presentation shared by transactional mail. Delivery, recipients and token
//! lifetimes remain the responsibility of each durable mail workflow.

use anyhow::{Result, ensure};
use lettre::{
    Message,
    message::{
        Mailbox, MultiPart, SinglePart,
        header::{ContentTransferEncoding, ContentType},
    },
};
use url::Url;

const CONTACT: &str = "admin@updspace.com";

pub(crate) fn render(
    recipient: &str,
    from: &Mailbox,
    subject: &str,
    body: &str,
    action: Option<(&str, &Url)>,
) -> Result<Message> {
    let html = html(subject, body, action)?;
    let plain = format!(
        "{body}\n\nUpdSpace ID\nВопросы об аккаунте и данных: {CONTACT}\nНе сообщайте пароли и коды подтверждения в ответ на письмо."
    );
    Ok(Message::builder()
        .from(from.clone())
        .to(recipient.parse()?)
        .reply_to(CONTACT.parse()?)
        .subject(subject)
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .header(ContentTransferEncoding::QuotedPrintable)
                        .body(plain),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .header(ContentTransferEncoding::QuotedPrintable)
                        .body(html),
                ),
        )?)
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn html(subject: &str, body: &str, action: Option<(&str, &Url)>) -> Result<String> {
    let mut content = String::new();
    for paragraph in body.trim().split("\n\n") {
        content.push_str("<p style=\"margin:0 0 20px;overflow-wrap:anywhere\">");
        content.push_str(&escape(paragraph).replace('\n', "<br>"));
        content.push_str("</p>");
    }
    if let Some((label, link)) = action {
        ensure!(
            matches!(link.scheme(), "https" | "http")
                && link.host_str().is_some()
                && link.username().is_empty()
                && link.password().is_none(),
            "unsupported mail action URL"
        );
        content.push_str(&format!(
            "<p style=\"margin:28px 0\"><a href=\"{}\" style=\"display:inline-block;background:#254edb;color:#ffffff;text-decoration:none;padding:14px 22px;border-radius:8px;font-weight:bold\">{}</a></p>",
            escape(link.as_str()), escape(label),
        ));
    }
    Ok(format!(
        r#"<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title></head>
<body style="margin:0;background:#f5f6f8;color:#182230;font:16px/1.6 Arial,sans-serif">
<table role="presentation" style="width:100%;border-collapse:collapse"><tr><td style="padding:24px 16px">
<table role="presentation" style="width:100%;max-width:560px;margin:auto;background:#ffffff;border:1px solid #d8dce3;border-radius:16px"><tr><td style="padding:28px">
<p style="margin:0 0 24px;font-weight:bold;color:#254edb">UpdSpace ID</p>
<h1 style="margin:0 0 24px;font-size:24px;line-height:1.3">{title}</h1>
{content}
<hr style="border:0;border-top:1px solid #d8dce3;margin:28px 0">
<p style="margin:0 0 12px;font-size:14px;color:#465369">Вопросы об аккаунте и данных: <a href="mailto:{CONTACT}" style="color:#254edb">{CONTACT}</a></p>
<p style="margin:0;font-size:14px;color:#465369">Не сообщайте пароли и коды подтверждения в ответ на письмо.</p>
</td></tr></table></td></tr></table></body></html>"#,
        title = escape(subject)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multipart_keeps_plain_text_and_reply_contact() -> Result<()> {
        let message = render(
            "recipient@example.invalid",
            &"ID <sender@example.invalid>".parse()?,
            "Account notice",
            "A plain notice.",
            None,
        )?;
        let wire = String::from_utf8(message.formatted())?;
        assert!(wire.contains("multipart/alternative"));
        assert!(wire.contains("text/plain; charset=utf-8"));
        assert!(wire.contains("text/html; charset=utf-8"));
        assert!(wire.contains("Reply-To: admin@updspace.com"));
        assert!(wire.contains("A plain notice."));
        Ok(())
    }

    #[test]
    fn untrusted_details_and_action_are_escaped() -> Result<()> {
        let link = Url::parse("https://id.example.invalid/export#token=a&proof=b")?;
        let output = html(
            "<Notice>",
            "Device: <img src=x onerror='bad'>\n192.0.2.5",
            Some(("Get <copy>", &link)),
        )?;
        assert!(output.contains("&lt;img src=x onerror=&#39;bad&#39;&gt;<br>192.0.2.5"));
        assert!(output.contains("href=\"https://id.example.invalid/export#token=a&amp;proof=b\""));
        assert!(output.contains("Get &lt;copy&gt;"));
        assert!(!output.contains("<img"));
        assert!(!output.contains("<script"));
        for value in [
            "javascript:alert(1)",
            "data:text/html,bad",
            "https://user:secret@example.invalid/",
        ] {
            assert!(html("Notice", "Body", Some(("Open", &Url::parse(value)?))).is_err());
        }
        Ok(())
    }
}
