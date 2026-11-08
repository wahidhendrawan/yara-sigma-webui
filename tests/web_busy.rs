//! Lives in its own test binary: holding every sigma-cli slot would starve the other API tests.

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use yar2sig::backends::{find_sigma, SlotGuard};

#[tokio::test]
async fn returns_503_with_retry_after_when_every_sigma_slot_is_busy() {
    let guards: Vec<SlotGuard> = std::iter::from_fn(SlotGuard::try_acquire).collect();
    assert!(!guards.is_empty());
    let payload =
        json!({"rule": "rule R { strings: $a = \"x\" condition: $a }", "backend": "splunk"});
    let request = Request::post("/api/convert")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    let response = yar2sig::web::app().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let body: Value = serde_json::from_slice(&body.collect().await.unwrap().to_bytes()).unwrap();
    if find_sigma().is_some() {
        assert_eq!(parts.status, 503);
        assert_eq!(parts.headers.get("retry-after").unwrap(), "5");
        assert!(body["error"].as_str().unwrap().contains("busy"));
    } else {
        // Without sigma-cli the native path is never attempted, so slots do not matter.
        assert_eq!(parts.status, 200, "{body}");
    }
    drop(guards);
    assert!(SlotGuard::try_acquire().is_some());
}
