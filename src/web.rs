//! Web UI and JSON API: `GET /` serves the single-page converter, `GET /healthz` lists
//! pipelines and backends, `POST /api/convert` returns the Sigma rule (YAML), conversion
//! report, quality metadata, and a native SIEM query for the selected backend.

use axum::body::to_bytes;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Map, Value};

use crate::backends::{self, BackendBusy};
use crate::{available_pipelines, emitter, load_mapping, parser, truthy, Error};

pub const MAX_RULE_BYTES: usize = 1_000_000;
pub const MAX_REQUEST_BYTES: usize = 1_100_000; // Allow bounded JSON framing around the rule
pub const MAX_PATTERNS: usize = 500; // Bound worst-case detection blocks per request
pub const MAX_PATTERN_LENGTH: usize = 10_000; // Bound worst-case pattern size
const LAYOUTS: [&str; 2] = ["default", "detection-rules"];
const MAX_ATTACK_TAGS: usize = 10;

// SPA is self-contained with inline styles/scripts and no third-party resources
const CSP: &str =
    "default-src 'self'; base-uri 'none'; object-src 'none'; script-src 'self' 'unsafe-inline'; \
    style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; \
    form-action 'self'; frame-ancestors 'none'";
const SECURITY_HEADERS: [(&str, &str); 8] = [
    ("content-security-policy", CSP),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    (
        "permissions-policy",
        "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    ),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
    ("x-permitted-cross-domain-policies", "none"),
];

pub fn app() -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/api/convert", post(api_convert))
        .layer(middleware::from_fn(security_headers))
}

/// Bind and serve until the process exits.
pub fn serve(host: &str, port: u16) -> std::io::Result<()> {
    tokio::runtime::Runtime::new()?.block_on(async {
        let listener = tokio::net::TcpListener::bind((host, port)).await?;
        eprintln!(
            "yar2sig {} listening on http://{}",
            crate::VERSION,
            listener.local_addr()?
        );
        axum::serve(listener, app()).await
    })
}

async fn security_headers(request: Request, next: Next) -> Response {
    let no_store = request.uri().path() == "/api/convert";
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        headers.insert(name, HeaderValue::from_static(value));
    }
    if no_store {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn healthz() -> Json<Value> {
    Json(
        json!({"status": "ok", "pipelines": available_pipelines(), "backends": backends::backend_ids()}),
    )
}

fn error(message: &str, status: u16, extra: Value) -> Response {
    let mut payload = Map::new();
    payload.insert("error".into(), message.into());
    if let Value::Object(extra) = extra {
        payload.extend(extra);
    }
    (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Json(Value::Object(payload)),
    )
        .into_response()
}

enum ApiError {
    Busy,
    Invalid(Error),
}

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        ApiError::Invalid(e)
    }
}

fn convert_request(
    text: &str,
    pipeline: &str,
    backend: &str,
    layout: &str,
    attack: &[String],
) -> Result<Value, ApiError> {
    let parsed = parser::parse_yara_rule(text, MAX_PATTERNS, MAX_PATTERN_LENGTH)?;
    let (mut rule, report) = emitter::emit_sigma(&parsed, &load_mapping(pipeline)?);
    let quality = rule.get("x_yar2sig").cloned().unwrap_or_else(|| json!({}));
    if layout == "detection-rules" {
        rule = emitter::to_detection_rules(&rule, attack)?;
    }
    let sigma_yaml = serde_yaml_ng::to_string(&rule).map_err(|e| Error(e.to_string()))?;
    let query = backends::generate_query(backend, &rule, &parsed.values())
        .map_err(|BackendBusy| ApiError::Busy)?;
    Ok(json!({
        "sigma": sigma_yaml,
        "query": query,
        "report": report,
        "quality": quality,
        "layout": layout,
        "parsed": {
            "name": parsed.name,
            "patterns": parsed.strings.len(),
            "condition": parsed.condition_raw,
            "tags": rule.get("tags").cloned().unwrap_or_else(|| json!([])),
        },
    }))
}

async fn api_convert(request: Request) -> Response {
    let too_large = || {
        error(
            "Request body is too large",
            413,
            json!({"limit": MAX_RULE_BYTES}),
        )
    };
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<usize>().ok());
    if declared.is_some_and(|n| n > MAX_REQUEST_BYTES) {
        return too_large();
    }
    let Ok(bytes) = to_bytes(request.into_body(), MAX_REQUEST_BYTES).await else {
        return too_large();
    };

    // Unparseable or falsy JSON is an empty object, like Flask's get_json(silent=True) or {}.
    let data = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .filter(truthy)
        .unwrap_or_else(|| json!({}));
    let Value::Object(data) = data else {
        return error("JSON object expected", 400, json!({}));
    };

    let field = |key: &str, default: &str| {
        data.get(key)
            .filter(|v| !v.is_null())
            .cloned()
            .unwrap_or_else(|| default.into())
    };
    let raw_rule = field("rule", "");
    let pipeline = field("pipeline", "sysmon");
    let backend = field("backend", "splunk");
    let layout = data
        .get("layout")
        .filter(|v| truthy(v))
        .cloned()
        .unwrap_or_else(|| "default".into());
    let attack = data
        .get("attack")
        .filter(|v| truthy(v))
        .cloned()
        .unwrap_or_else(|| json!([]));

    let Some(layout) = layout
        .as_str()
        .filter(|l| LAYOUTS.contains(l))
        .map(str::to_string)
    else {
        return error("Unknown layout", 400, json!({"available": LAYOUTS}));
    };
    let attack: Option<Vec<String>> = attack
        .as_array()
        .filter(|items| items.len() <= MAX_ATTACK_TAGS)
        .and_then(|items| {
            items
                .iter()
                .map(|i| {
                    i.as_str()
                        .filter(|s| s.chars().count() <= 20)
                        .map(str::to_string)
                })
                .collect()
        });
    let Some(attack) = attack else {
        return error(
            "attack must be a list of up to 10 technique IDs",
            400,
            json!({}),
        );
    };
    let Value::String(raw_rule) = raw_rule else {
        return error("Rule must be a string", 400, json!({}));
    };
    let (Value::String(pipeline), Value::String(backend)) = (pipeline, backend) else {
        return error("Pipeline and backend must be strings", 400, json!({}));
    };

    let text = raw_rule.trim().to_string();
    if text.is_empty() {
        return error("No YARA rule provided", 400, json!({}));
    }
    if text.len() > MAX_RULE_BYTES {
        return error(
            "Rule text exceeds maximum size",
            413,
            json!({"limit": MAX_RULE_BYTES}),
        );
    }
    if !available_pipelines().contains(&pipeline.as_str()) {
        return error(
            "Unknown mapping pipeline",
            400,
            json!({"available": available_pipelines()}),
        );
    }
    if backends::backend(&backend).is_none() {
        return error(
            "Unknown backend",
            400,
            json!({"available": backends::backend_ids()}),
        );
    }

    let result = tokio::task::spawn_blocking(move || {
        convert_request(&text, &pipeline, &backend, &layout, &attack)
    })
    .await;
    match result {
        Ok(Ok(payload)) => Json(payload).into_response(),
        Ok(Err(ApiError::Invalid(e))) => error(&e.0, 422, json!({})),
        Ok(Err(ApiError::Busy)) => {
            let mut response = error(&BackendBusy.to_string(), 503, json!({}));
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
            response
        }
        Err(e) => {
            eprintln!("conversion failed: {e}");
            error("Conversion failed", 500, json!({}))
        }
    }
}
