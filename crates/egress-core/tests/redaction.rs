//! Redaction (KTD11, R21). Every class runs before identity and truncation.

mod common;

use egress_core::destination::{self as d, TemplatePart};
use egress_core::escape::escape;
use egress_core::identity::{blind_spot_key, finalize, site_key};
use egress_core::json::to_json;
use egress_core::model::BlindSpotKind;
use egress_core::redact::{REDACTED, redact};

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn covers_ae14_userinfo_and_listed_query_key() {
    let dest = d::literal("https://bob:hunter2@api.example.com/x?token=abc&page=2");
    assert_eq!(
        dest.display,
        "https://<redacted>@api.example.com/x?token=<redacted>&page=2"
    );
    assert_eq!(dest.value, dest.display);

    let mut r = common::report(
        vec![common::site(
            "page.py",
            "fetch_page",
            "python:requests.get",
            dest,
            5,
        )],
        vec![],
    );
    finalize(&mut r);
    let key = site_key(&r.sites[0]);
    let json = to_json(&r);
    for secret in ["hunter2", "abc"] {
        assert!(!contains(&key, secret), "identity key holds {secret}");
        assert!(!json.contains(secret), "JSON holds {secret}");
    }
    common::validate(&json).unwrap();
}

#[test]
fn unlisted_key_keeps_value_and_parameter_order_is_kept() {
    assert_eq!(
        redact("https://h.example/x?page=2&TOKEN=abc&a=1&x_token=q"),
        "https://h.example/x?page=2&TOKEN=<redacted>&a=1&x_token=<redacted>"
    );
}

#[test]
fn every_listed_query_key_is_redacted() {
    for key in [
        "token",
        "key",
        "api_key",
        "apikey",
        "secret",
        "password",
        "passwd",
        "pwd",
        "auth",
        "sig",
        "signature",
        "access_token",
        "client_secret",
        "credential",
        "session",
    ] {
        let out = redact(&format!("https://h.example/x?{key}=SECRETVALUE&page=2"));
        assert_eq!(
            out,
            format!("https://h.example/x?{key}=<redacted>&page=2"),
            "key {key}"
        );
    }
}

#[test]
fn token_prefix_under_unlisted_key_is_redacted() {
    for prefix in [
        "ghp_",
        "github_pat_",
        "glpat-",
        "sk-",
        "sk_live_",
        "AKIA",
        "AIza",
        "xoxb-",
        "xoxp-",
        "npm_",
        "pypi-",
        "eyJ",
    ] {
        let secret = format!("{prefix}Zq9.x-_Y");
        let out = redact(&format!("https://h.example/x?id={secret}&page=1"));
        assert_eq!(
            out, "https://h.example/x?id=<redacted>&page=1",
            "prefix {prefix}"
        );
    }
}

#[test]
fn covers_ae23_token_run_in_every_text_position() {
    let path = d::literal("https://h.example/x/ghp_abc123");
    assert_eq!(path.display, "https://h.example/x/<redacted>");

    let env = d::env("REPO_TOKEN", Some("ghp_abc123"));
    assert_eq!(env.default.as_deref(), Some(REDACTED));

    let expr = d::expr("client.get(\"ghp_abc123\")");
    assert_eq!(expr.display, "expr:client.get(\"<redacted>\")");

    let construct = d::construct_text("exec(\"T = 'ghp_abc123'\")");
    assert_eq!(construct, "exec(\"T = '<redacted>'\")");

    let mut r = common::report(
        vec![
            common::site("repo.py", "fetch_repo", "python:requests.get", path, 5),
            common::site("repo.py", "<module>", "python:os.environ", env, 1),
            common::site("repo.py", "f", "python:requests.get", expr, 9),
        ],
        vec![common::blind(
            "repo.py",
            "<module>",
            BlindSpotKind::DynamicCode,
            &construct,
            2,
        )],
    );
    finalize(&mut r);
    let json = to_json(&r);
    assert!(!json.contains("ghp_abc123"));
    for s in &r.sites {
        assert!(!contains(&site_key(s), "ghp_abc123"));
    }
    assert!(!contains(&blind_spot_key(&r.blind_spots[0]), "ghp_abc123"));
}

#[test]
fn must_not_redact_prefixes_inside_words() {
    for text in [
        "https://h.example/offers/risk-free",
        "keyJar",
        "https://h.example/keyJar?page=1",
        "expr:mask-off",
        "TASKAKIAX",
    ] {
        assert_eq!(redact(text), text);
    }
}

#[test]
fn template_is_redacted_in_rendered_form() {
    let dest = d::template(&[
        TemplatePart::Literal("https://".into()),
        TemplatePart::Hole(d::env("U", None)),
        TemplatePart::Literal(":hunter2@h".into()),
    ]);
    assert_eq!(dest.display, "https://<redacted>@h");
    assert!(!dest.value.contains("hunter2"));
}

#[test]
fn template_holes_render_and_survive_when_clean() {
    let dest = d::template(&[
        TemplatePart::Hole(d::env("API_BASE", None)),
        TemplatePart::Literal("/v1/items".into()),
    ]);
    assert_eq!(dest.display, "{env:API_BASE}/v1/items");
    let dest = d::template(&[
        TemplatePart::Literal("https://api.example.com/users/".into()),
        TemplatePart::Hole(d::param(1, "get_user")),
    ]);
    assert_eq!(
        dest.display,
        "https://api.example.com/users/{param:1:get_user}"
    );
}

#[test]
fn template_with_host_hole_redacts_listed_query_key() {
    let dest = d::template(&[
        TemplatePart::Hole(d::env("API_BASE", None)),
        TemplatePart::Literal("/x?token=abc&page=2".into()),
    ]);
    assert_eq!(dest.display, "{env:API_BASE}/x?token=<redacted>&page=2");
}

#[test]
fn unparseable_url_fails_closed() {
    assert_eq!(redact("https://u:pw@[bad/x"), "https://<redacted>@[bad/x");
}

#[test]
fn fragment_parameter_is_redacted() {
    assert_eq!(
        redact("https://h.example/cb#access_token=x&state=1"),
        "https://h.example/cb#access_token=<redacted>&state=1"
    );
}

#[test]
fn provider_path_secrets_are_redacted() {
    assert_eq!(
        redact("https://api.telegram.org/bot123456:AAHfakeToken_x-9/sendMessage"),
        "https://api.telegram.org/bot<redacted>/sendMessage"
    );
    assert_eq!(
        redact("https://hooks.slack.com/services/T0/B0/secret"),
        "https://hooks.slack.com/services/<redacted>"
    );
    assert_eq!(
        redact("https://discord.com/api/webhooks/1/tok"),
        "https://discord.com/api/webhooks/1/<redacted>"
    );
    assert_eq!(
        redact("https://discord.com/api/v10/webhooks/42/tok?wait=true"),
        "https://discord.com/api/v10/webhooks/42/<redacted>?wait=true"
    );
}

#[test]
fn keyword_dsn_value_is_redacted() {
    assert_eq!(redact("host=db password=pw"), "host=db password=<redacted>");
    assert_eq!(
        redact("host=db password='a b c' dbname=app"),
        "host=db password=<redacted> dbname=app"
    );
    assert_eq!(redact("host=db user=app"), "host=db user=app");
}

#[test]
fn expr_secret_straddling_truncation_leaks_no_prefix() {
    let filler = "a".repeat(110);
    let source = format!("f({filler}, \"ghp_SECRETSECRETSECRETSECRET\")");
    let dest = d::expr(&source);
    assert!(dest.value.chars().count() <= d::MAX_TEXT_CHARS);
    assert!(!dest.display.contains("ghp"), "{}", dest.display);
    assert!(!dest.display.contains("SECRET"), "{}", dest.display);
}

#[test]
fn expr_is_whitespace_collapsed_and_truncated() {
    let dest = d::expr("{ host: \"api.example.com\",\n    path: \"/health\",\r\n  agent }");
    assert_eq!(
        dest.display,
        "expr:{ host: \"api.example.com\", path: \"/health\", agent }"
    );
    let long = d::expr(&"x".repeat(300));
    assert_eq!(long.value.chars().count(), d::MAX_TEXT_CHARS);
}

#[test]
fn construct_text_is_redacted_then_truncated_then_escaped() {
    let mut source = String::from("run(\u{1b}[31m, ");
    source.push_str("\"https://u:pw@h/x\", ");
    while source.chars().count() < 200 {
        source.push('z');
    }
    let construct = d::construct_text(&source);
    assert!(construct.chars().count() <= d::MAX_TEXT_CHARS);
    assert!(!construct.contains("pw"));
    assert!(construct.contains("https://<redacted>@h/x"));

    let mut r = common::report(
        vec![],
        vec![common::blind(
            "a.py",
            "<module>",
            BlindSpotKind::DynamicCode,
            &construct,
            1,
        )],
    );
    let json = to_json(&r);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let out = v["blind_spots"][0]["construct"].as_str().unwrap();
    assert!(!out.contains('\u{1b}'));
    assert!(!out.contains("pw"));
    assert_eq!(out, escape(&construct));
    finalize(&mut r);
    assert!(!contains(&blind_spot_key(&r.blind_spots[0]), "pw@"));
}

#[test]
fn must_not_change_a_url_without_credentials() {
    for url in [
        "https://api.example.com/v1/items",
        "https://Example.COM:443/a/../b?x=1&page=2#frag",
        "http://h.example",
        "wss://api.example.com/live",
        "https://h.example/path@segment",
    ] {
        assert_eq!(redact(url), url);
        assert_eq!(d::literal(url).display, url);
    }
}

#[test]
fn non_url_destinations_pass_through() {
    for text in ["api.example.com:443", "db.example.com:5432", "/users"] {
        assert_eq!(redact(text), text);
    }
    assert_eq!(d::exec("curl").display, "exec:curl");
    assert_eq!(d::lib("libc.so.6").display, "lib:libc.so.6");
    assert_eq!(d::env("API_URL", None).display, "env:API_URL");
    assert_eq!(
        d::param(1, "<impl Api>::get").display,
        "param:1:<impl Api>::get"
    );
}

#[test]
fn redaction_is_idempotent() {
    for text in [
        "https://bob:hunter2@api.example.com/x?token=abc&page=2",
        "https://u:pw@[bad/x",
        "host=db password=pw",
        "https://hooks.slack.com/services/T0/B0/secret",
        "ghp_abc123 and sk-live",
    ] {
        let once = redact(text);
        assert_eq!(redact(&once), once, "{text}");
    }
}
