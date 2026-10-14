use crate::contracts::{Rule, validate_rule};
use serde_json::{Value, json};
use std::path::Path;
fn rule(kind: &str, fields: &[&str], arguments: Value) -> Rule {
    Rule {
        kind: kind.into(),
        fields: fields.iter().map(|v| (*v).into()).collect(),
        arguments,
    }
}
#[test]
fn numeric_semantics_reject_overflow_types_and_strict_boundary() {
    let root = Path::new("/tmp/contract-root");
    let scaled = rule(
        "integer-order",
        &["/left", "/right"],
        json!({"relation":"less-than","right_scale":1000}),
    );
    assert!(validate_rule(&scaled, &json!({"left":999,"right":1}), root).is_ok());
    for left in [Value::from(1000), Value::from(u64::MAX), Value::Bool(false)] {
        assert!(validate_rule(&scaled, &json!({"left":left,"right":1}), root).is_err());
    }
    let sum = rule(
        "integer-sum-order",
        &["/a", "/b", "/limit"],
        json!({"relation":"less-than"}),
    );
    assert!(validate_rule(&sum, &json!({"a":90,"b":10,"limit":101}), root).is_ok());
    for value in [
        json!({"a":90,"b":10,"limit":100}),
        json!({"a":u64::MAX,"b":1,"limit":u64::MAX}),
        json!({"a":false,"b":10,"limit":101}),
    ] {
        assert!(validate_rule(&sum, &value, root).is_err());
    }
    for args in [
        json!({"relation":"less-than","right_scale":0}),
        json!({"relation":"less-than","right_scale":true}),
        json!({"relation":"less-than","unknown":1}),
    ] {
        let bad = rule("integer-order", &["/left", "/right"], args);
        assert!(validate_rule(&bad, &json!({"left":0,"right":1}), root).is_err());
    }
}
#[test]
fn template_grammar_counts_literal_runs_adjacent_tokens_and_utf8() {
    let rule = rule(
        "token-template",
        &["/format"],
        json!({"maximum_bytes":4096,"maximum_tokens":128,"marker":"$","variables":["status","request"],"header_prefix":"http_","header_name_encoding":"ascii-lowercase-underscore-to-hyphen"}),
    );
    let root = Path::new("/tmp/contract-root");
    for value in [
        String::new(),
        "$status$request".into(),
        "$http_X_Request_ID".into(),
        "$status".repeat(128),
        "$status ".repeat(64),
        "文".repeat(1365),
    ] {
        assert!(validate_rule(&rule, &json!({"format":value}), root).is_ok());
    }
    for value in [
        "$removed$status".into(),
        "$$status".into(),
        "$http_".into(),
        "$http_文".into(),
        "$status".repeat(129),
        "$status ".repeat(65),
        "文".repeat(1366),
    ] {
        assert!(validate_rule(&rule, &json!({"format":value}), root).is_err());
    }
}
#[test]
fn untrusted_material_json_cannot_repeat_fields_or_append_values() {
    for input in [
        br#"{"root":1,"root":2}"#.as_slice(),
        br#"{"nested":{"id":1,"id":2}}"#.as_slice(),
        br#"{"root":1} true"#.as_slice(),
    ] {
        assert!(crate::strict_json::decode::<Value>(input).is_err());
    }
}
#[test]
fn distinct_socket_wildcards_conflict_with_specific_listeners() {
    let constraint = rule("distinct-sockets", &["/a", "/b"], json!({}));
    let root = Path::new("/tmp/contract-root");
    for b in ["127.0.0.1:1234", "[::1]:1234", "0.0.0.0:1234"] {
        assert!(validate_rule(&constraint, &json!({"a":"0.0.0.0:1234","b":b}), root).is_err());
    }
    assert!(
        validate_rule(
            &constraint,
            &json!({"a":"127.0.0.1:1234","b":"127.0.0.2:1234"}),
            root
        )
        .is_ok()
    );
}
