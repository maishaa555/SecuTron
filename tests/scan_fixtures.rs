use serde_json::Value;
use std::{collections::HashSet, io::{BufRead, BufReader}, path::PathBuf, process::{Child, Command, Output, Stdio}};

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures").join("vulnerable-shop").join(name)
}

fn scan_fixture(name: &str) -> (Output, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_secutron"))
        .arg("scan")
        .arg(fixture_path(name))
        .args(["--format", "json"])
        .output()
        .expect("SecuTron CLI should start");
    let report = serde_json::from_slice(&output.stdout)
        .expect("JSON mode should emit a valid scan report");
    (output, report)
}

fn rule_ids(report: &Value) -> HashSet<String> {
    report["findings"].as_array().expect("findings should be an array")
        .iter()
        .map(|finding| finding["rule_id"].as_str().expect("finding should have a rule id").to_string())
        .collect()
}

#[test]
fn vulnerable_shop_exercises_the_implemented_source_to_sink_and_secret_rules() {
    let (output, report) = scan_fixture("vulnerable");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["complete"], true);
    assert_eq!(report["errors"].as_array().map(Vec::len), Some(0));

    let rules = rule_ids(&report);
    for expected in [
        "PY.SQL.UNTRUSTED",
        "PY.COMMAND.UNTRUSTED",
        "PY.PATH.UNTRUSTED",
        "PY.CODE.UNTRUSTED",
        "PY.SECRET.LITERAL",
        "PY.CRYPTO.WEAK",
        "PY.RANDOM.INSECURE",
    ] {
        assert!(rules.contains(expected), "expected {expected}; got {rules:?}");
    }
    let serialized = String::from_utf8(output.stdout).expect("JSON output should be UTF-8");
    assert!(!serialized.contains("shop-admin-hardcoded-value"), "secret values must stay out of findings");
}

#[test]
fn secure_shop_and_placeholder_env_are_negative_examples() {
    let (output, report) = scan_fixture("secure");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(report["complete"], true);
    assert_eq!(report["findings"].as_array().map(Vec::len), Some(0));
}

#[test]
fn env_parser_keeps_hashes_inside_values_and_rejects_invalid_keys() {
    let (output, report) = scan_fixture("edge-cases");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(report["complete"], true);
    let findings = report["findings"].as_array().expect("findings should be an array");
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().all(|finding| finding["rule_id"] == "GEN.SECRET.LITERAL"));
    let serialized = String::from_utf8(output.stdout).expect("JSON output should be UTF-8");
    assert!(!serialized.contains("changeme#suffix"));
    assert!(!serialized.contains("literal # trailing comment"));
}

#[test]
fn syntax_errors_mark_reports_incomplete_and_take_exit_code_precedence() {
    let (output, report) = scan_fixture("incomplete");
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(report["complete"], false);
    assert!(!report["errors"].as_array().expect("errors should be an array").is_empty());
}

#[test]
fn json_output_is_deterministic_for_the_same_fixture_tree() {
    let (first_output, first_report) = scan_fixture("vulnerable");
    let (second_output, second_report) = scan_fixture("vulnerable");
    assert_eq!(first_output.status.code(), second_output.status.code());
    assert_eq!(first_report, second_report);
}

#[test]
fn sarif_advertises_the_implemented_rules_and_reports_fixture_findings() {
    let output = Command::new(env!("CARGO_BIN_EXE_secutron"))
        .arg("scan")
        .arg(fixture_path("vulnerable"))
        .args(["--format", "sarif"])
        .output()
        .expect("SecuTron CLI should start");
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).expect("SARIF should be valid JSON");
    assert_eq!(report["version"], "2.1.0");
    let rules = report["runs"][0]["tool"]["driver"]["rules"].as_array().expect("SARIF rules should be listed");
    for expected in ["PY.CRYPTO.WEAK", "PY.RANDOM.INSECURE", "PY.SQL.UNTRUSTED"] {
        assert!(rules.iter().any(|rule| rule["id"] == expected), "SARIF catalog should contain {expected}");
    }
    let results = report["runs"][0]["results"].as_array().expect("SARIF results should be listed");
    assert!(results.iter().any(|result| result["ruleId"] == "PY.CRYPTO.WEAK"));
    assert!(results.iter().any(|result| result["ruleId"] == "PY.RANDOM.INSECURE"));
}

struct ServerChild(Child);

impl Drop for ServerChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn loopback_dashboard_serves_ui_and_authenticates_scan_api() {
    let child = Command::new(env!("CARGO_BIN_EXE_secutron"))
        .args(["serve", "--bind", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("SecuTron server should start");
    let mut child = ServerChild(child);
    let stdout = child.0.stdout.take().expect("server stdout should be piped");
    let mut lines = BufReader::new(stdout).lines();
    let dashboard_line = lines.next().expect("server should print its URL").expect("URL line should be readable");
    let token_line = lines.next().expect("server should print its token").expect("token line should be readable");
    let origin = dashboard_line.strip_prefix("SecuTron dashboard: ").and_then(|line| line.strip_suffix('/')).expect("server should announce its dashboard URL");
    let token = token_line.strip_prefix("Local API bearer token (shown once; enter it in the dashboard): ").expect("server should announce the API token");
    assert_eq!(token.len(), 64);
    let client = reqwest::blocking::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(5)).build().unwrap();

    let page = client.get(format!("{origin}/")).send().unwrap();
    assert_eq!(page.status(), reqwest::StatusCode::OK);
    assert!(page.text().unwrap().contains("SecuTron — Security Overview"));

    let endpoint = format!("{origin}/api/scan");
    let body = serde_json::json!({"path":fixture_path("secure").to_string_lossy()});
    let unauthorized = client.post(&endpoint).json(&body).send().unwrap();
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);

    let oversized = client.post(&endpoint)
        .header("Authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({"path":"x".repeat(9000)}))
        .send().unwrap();
    assert_eq!(oversized.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);

    let rejected_host = client.post(&endpoint).header("Authorization", format!("Bearer {token}")).header("Host", "evil.example").json(&body).send().unwrap();
    assert_eq!(rejected_host.status(), reqwest::StatusCode::FORBIDDEN);

    let rejected_origin = client.post(&endpoint).header("Authorization", format!("Bearer {token}")).header("Origin", "http://evil.example").json(&body).send().unwrap();
    assert_eq!(rejected_origin.status(), reqwest::StatusCode::FORBIDDEN);

    let response = client.post(&endpoint).header("Authorization", format!("Bearer {token}")).json(&body).send().unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers().get("cache-control").and_then(|value| value.to_str().ok()), Some("no-store"));
    let report: Value = response.json().unwrap();
    assert_eq!(report["complete"], true);
    assert_eq!(report["findings"].as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn websocket_scan_stream_authenticates_and_reports_completion_telemetry() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{connect_async, tungstenite::{client::IntoClientRequest, http::HeaderValue, Message}};

    let child = Command::new(env!("CARGO_BIN_EXE_secutron"))
        .args(["serve", "--bind", "127.0.0.1:0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("SecuTron server should start");
    let mut child = ServerChild(child);
    let stdout = child.0.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let dashboard_line = lines.next().unwrap().unwrap();
    let token_line = lines.next().unwrap().unwrap();
    let origin = dashboard_line.strip_prefix("SecuTron dashboard: ").and_then(|line| line.strip_suffix('/')).unwrap();
    let token = token_line.strip_prefix("Local API bearer token (shown once; enter it in the dashboard): ").unwrap();
    let endpoint = format!("ws{}/api/scan/stream", &origin[4..]);
    let mut request = endpoint.as_str().into_client_request().unwrap();
    request.headers_mut().insert("Origin", HeaderValue::from_str(origin).unwrap());
    let (mut socket, _) = connect_async(request).await.unwrap();
    let path = fixture_path("secure");
    socket.send(Message::Text(serde_json::json!({"token":"invalid","path":path.to_string_lossy()}).to_string().into())).await.unwrap();
    let invalid = socket.next().await.unwrap().unwrap().into_text().unwrap();
    let invalid: Value = serde_json::from_str(&invalid).unwrap();
    assert_eq!(invalid["type"], "error");
    assert_eq!(invalid["error"], "valid bearer token required");
    socket.close(None).await.unwrap();

    let mut request = endpoint.as_str().into_client_request().unwrap();
    request.headers_mut().insert("Origin", HeaderValue::from_str(origin).unwrap());
    let (mut socket, _) = connect_async(request).await.unwrap();
    socket.send(Message::Text(serde_json::json!({"token":token,"path":path.to_string_lossy()}).to_string().into())).await.unwrap();
    let started: Value = serde_json::from_str(&socket.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert_eq!(started["type"], "started");
    let complete: Value = loop {
        let event: Value = serde_json::from_str(&socket.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
        if event["type"] == "complete" { break event; }
        assert_eq!(event["type"], "running");
    };
    assert_eq!(complete["report"]["complete"], true);
    assert!(complete["elapsed_ms"].as_u64().is_some());
    socket.close(None).await.unwrap();
}

#[test]
fn server_refuses_non_loopback_bind_addresses() {
    let output = Command::new(env!("CARGO_BIN_EXE_secutron"))
        .args(["serve", "--bind", "0.0.0.0:0"])
        .output()
        .expect("SecuTron CLI should start");
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("public-origin"));
}

#[test]
fn server_requires_public_origin_to_be_loopback_and_same_port() {
    for origin in ["https://127.0.0.1:8765", "http://192.0.2.10:8765", "http://localhost:9000"] {
        let output = Command::new(env!("CARGO_BIN_EXE_secutron"))
            .args(["serve", "--bind", "0.0.0.0:8765", "--public-origin", origin])
            .output()
            .expect("SecuTron CLI should start");
        assert_eq!(output.status.code(), Some(2), "origin should be rejected: {origin}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("loopback origin"));
    }
}


