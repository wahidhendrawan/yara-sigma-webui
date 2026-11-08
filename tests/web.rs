//! Tests of the HTTP API (`POST /api/convert`, `/healthz`, `/`).

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use yar2sig::emitter::DETECTION_RULES_ORDER;

const BASIC: &str = r#"
rule TestRule : malware {
  meta:
    author = "tester"
    description = "test desc"
    reference = "T1059.003"
  strings:
    $a = "cmd.exe /c"
    $url = "http://evil.example.com/x"
    $ip = "10.0.0.5"
    $h = "44d88612fea8a8f36de82e1278abb02f"
  condition:
    any of them
}
"#;
const WITH_TECHNIQUE: &str = r#"
rule Dropper : malware {
  meta:
    description = "drops a payload"
    reference = "https://attack.mitre.org/techniques/T1059/003/ T1059.003"
  strings:
    $a = "cmd.exe /c"
    $url = "http://evil.example.com/x"
  condition:
    all of them
}
"#;

async fn send(request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = yar2sig::web::app().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

async fn post_raw(body: Vec<u8>, content_length: Option<usize>) -> (StatusCode, HeaderMap, Value) {
    let mut builder = Request::post("/api/convert").header("content-type", "application/json");
    if let Some(n) = content_length {
        builder = builder.header("content-length", n.to_string());
    }
    let (status, headers, text) = send(builder.body(Body::from(body)).unwrap()).await;
    (
        status,
        headers,
        serde_json::from_str(&text).unwrap_or(Value::Null),
    )
}

async fn post(payload: Value) -> (StatusCode, HeaderMap, Value) {
    post_raw(serde_json::to_vec(&payload).unwrap(), None).await
}

fn sigma(payload: &Value) -> Value {
    serde_yaml_ng::from_str(payload["sigma"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn validates_backend_pipeline_layout_and_attack() {
    let (status, _, body) = post(json!({"rule": BASIC, "backend": "missing"})).await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "Unknown backend");
    assert!(body["available"]
        .as_array()
        .unwrap()
        .contains(&json!("splunk")));
    let (status, _, body) = post(json!({"rule": BASIC, "pipeline": "../sysmon"})).await;
    assert_eq!(
        (status.as_u16(), body["error"].as_str()),
        (400, Some("Unknown mapping pipeline"))
    );
    let (status, _, _) = post(json!({"rule": WITH_TECHNIQUE, "layout": "nope"})).await;
    assert_eq!(status, 400);
    let (status, _, _) = post(json!({"rule": WITH_TECHNIQUE, "attack": "T1"})).await;
    assert_eq!(status, 400);
    let (status, _, _) = post(json!({"rule": WITH_TECHNIQUE, "attack": vec!["T1"; 11]})).await;
    assert_eq!(status, 400);
    let (status, _, body) = post(json!({"rule": 123})).await;
    assert_eq!(
        (status.as_u16(), body["error"].as_str()),
        (400, Some("Rule must be a string"))
    );
    let (status, _, body) = post(json!({"rule": BASIC, "pipeline": 5})).await;
    assert_eq!(
        (status.as_u16(), body["error"].as_str()),
        (400, Some("Pipeline and backend must be strings"))
    );
    let (status, _, body) = post(json!({"rule": "   "})).await;
    assert_eq!(
        (status.as_u16(), body["error"].as_str()),
        (400, Some("No YARA rule provided"))
    );
    let (status, _, body) = post(json!({"rule": "rule R { strings: $a = \"x\" condition: $a }", "pipeline": null, "backend": null})).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn returns_quality_and_parsed_metadata() {
    let (status, headers, body) =
        post(json!({"rule": BASIC, "pipeline": "sysmon", "backend": "splunk"})).await;
    assert_eq!(status, 200);
    assert!(["high", "medium", "low"].contains(&body["quality"]["confidence"].as_str().unwrap()));
    assert_eq!(body["parsed"]["patterns"], 4);
    assert_eq!(body["parsed"]["name"], "TestRule");
    assert_eq!(body["parsed"]["condition"], "any of them");
    assert!(body["parsed"]["tags"]
        .as_array()
        .unwrap()
        .contains(&json!("attack.t1059.003")));
    assert!(!body["query"].as_str().unwrap().is_empty());
    assert_eq!(body["layout"], "default");
    assert!(body["report"].as_array().unwrap().len() >= 4);
    assert_eq!(sigma(&body)["title"], "test desc");
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn security_headers_and_static_pages() {
    let (status, headers, text) = send(Request::get("/healthz").body(Body::empty()).unwrap()).await;
    assert_eq!(status, 200);
    let health: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(health["status"], "ok");
    assert!(health["pipelines"]
        .as_array()
        .unwrap()
        .contains(&json!("sysmon")));
    assert_eq!(health["backends"].as_array().unwrap().len(), 7);
    let csp = headers
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        csp.contains("default-src 'self'")
            && csp.contains("frame-ancestors 'none'")
            && csp.contains("object-src 'none'")
    );
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        headers.get("referrer-policy").unwrap(),
        "strict-origin-when-cross-origin"
    );
    assert_eq!(
        headers.get("cross-origin-opener-policy").unwrap(),
        "same-origin"
    );
    assert!(headers.get("cache-control").is_none());

    let (status, headers, text) = send(Request::get("/").body(Body::empty()).unwrap()).await;
    assert_eq!(status, 200);
    assert!(headers
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("text/html"));
    assert!(text.contains("<html") && text.contains("/api/convert"));
    let (status, headers, _) = send(Request::get("/nope").body(Body::empty()).unwrap()).await;
    assert_eq!(status, 404);
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
}

#[tokio::test]
async fn rejects_malformed_bodies() {
    let (status, _, body) = post_raw(b"[1, 2, 3]".to_vec(), None).await;
    assert_eq!(
        (status.as_u16(), body["error"].as_str()),
        (400, Some("JSON object expected"))
    );
    for body_bytes in [
        b"not json".to_vec(),
        b"[]".to_vec(),
        b"null".to_vec(),
        Vec::new(),
    ] {
        let (status, _, body) = post_raw(body_bytes, None).await;
        assert_eq!(
            (status.as_u16(), body["error"].as_str()),
            (400, Some("No YARA rule provided"))
        );
    }
}

#[tokio::test]
async fn enforces_size_limits() {
    let huge = format!(
        "rule R {{\n  strings:\n    $a = \"{}\"\n  condition:\n    $a\n}}",
        "A".repeat(1_000_050)
    );
    let (status, _, body) =
        post(json!({"rule": huge, "pipeline": "sysmon", "backend": "splunk"})).await;
    assert_eq!(status, 413);
    assert!([
        "Request body is too large",
        "Rule text exceeds maximum size"
    ]
    .contains(&body["error"].as_str().unwrap()));

    let rule = format!(
        "rule R {{\n  strings:\n    $a = \"{}\"\n  condition:\n    $a\n}}",
        "é".repeat(500_000)
    );
    let (status, _, body) =
        post(json!({"rule": rule, "pipeline": "sysmon", "backend": "splunk"})).await;
    assert_eq!(status, 413);
    assert_eq!(body["error"], "Rule text exceeds maximum size");
    assert_eq!(body["limit"], 1_000_000);

    let (status, _, body) = post_raw(vec![b'x'; 1_200_000], None).await;
    assert_eq!(status, 413);
    assert_eq!(body["error"], "Request body is too large");
    let (status, _, body) = post_raw(b"{}".to_vec(), Some(1_200_000)).await;
    assert_eq!(status, 413);
    assert_eq!(body["error"], "Request body is too large");

    let lines: Vec<String> = (0..501).map(|i| format!("    $s{i} = \"v{i}\"")).collect();
    let rule = format!(
        "rule Big {{\n  strings:\n{}\n  condition:\n    any of them\n}}",
        lines.join("\n")
    );
    let (status, _, body) = post(json!({"rule": rule})).await;
    assert_eq!(status, 422);
    assert!(body["error"].as_str().unwrap().contains("pattern count"));
}

#[tokio::test]
async fn detection_rules_layout() {
    let (status, _, body) =
        post(json!({"rule": WITH_TECHNIQUE, "layout": "detection-rules"})).await;
    assert_eq!(status, 200);
    assert_eq!(body["layout"], "detection-rules");
    assert!(body["quality"]["confidence"].is_string());
    let rule = sigma(&body);
    let keys: Vec<&str> = rule
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: Vec<&str> = DETECTION_RULES_ORDER
        .iter()
        .copied()
        .filter(|k| rule.get(*k).is_some())
        .collect();
    assert_eq!(keys, expected);
    assert!(rule.get("x_yar2sig").is_none());
    assert!(rule["tags"]
        .as_array()
        .unwrap()
        .contains(&json!("attack.t1059.003")));

    let no_technique = WITH_TECHNIQUE.replace(
        "reference = \"https://attack.mitre.org/techniques/T1059/003/ T1059.003\"",
        "author = \"x\"",
    );
    let (status, _, body) = post(json!({"rule": no_technique, "layout": "detection-rules"})).await;
    assert_eq!(status, 422);
    assert!(body["error"].as_str().unwrap().contains("technique"));
    let (status, _, body) =
        post(json!({"rule": no_technique, "layout": "detection-rules", "attack": ["T1204.002"]}))
            .await;
    assert_eq!(status, 200);
    assert!(sigma(&body)["tags"]
        .as_array()
        .unwrap()
        .contains(&json!("attack.t1204.002")));

    let (_, _, body) = post(json!({"rule": WITH_TECHNIQUE})).await;
    assert_eq!(body["layout"], "default");
    assert!(sigma(&body).get("x_yar2sig").is_some());
}
