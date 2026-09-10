from fastapi.testclient import TestClient

import agentshield_api


client = TestClient(
    agentshield_api.app
)


# ============================================================
# Fake gateway results
# ============================================================

def fake_production_result():

    return {
        "scan_id":
            "ASG-test-production",

        "mode":
            "production",

        "timestamp":
            "2026-09-10T00:00:00+00:00",

        "canonicalization": {
            "representation":
                "base64",

            "changed":
                True,

            "method":
                "base64_decode",

            "error":
                None,
        },

        "decision": {
            "classification":
                "SAFE",

            "risk_score":
                "0",

            "action":
                "ALLOW",

            "attack_types":
                "",

            "explanation":
                "Benign test content.",

            "recommended_action":
                "ALLOW",
        },

        "execution": {
            "status":
                "SUCCESS",

            "request_id":
                "test-request-production",

            "attempts":
                1,

            "used_credits":
                0.0,

            "model_runtime":
                0.01,

            "gateway_runtime":
                0.02,
        },

        "input": {
            "raw_sha256":
                "raw-test-hash",

            "canonical_sha256":
                "canonical-test-hash",

            "raw_length":
                56,

            "canonical_length":
                40,
        },

        "_raw_text":
            "TEST_BASE64",

        "_canonical_text":
            "The museum opens at nine in the morning.",
    }


def fake_audit_result():

    return {
        "scan_id":
            "ASA-test-audit",

        "mode":
            "audit",

        "timestamp":
            "2026-09-10T00:00:00+00:00",

        "canonicalization": {
            "representation":
                "base64",

            "changed":
                True,

            "method":
                "base64_decode",

            "error":
                None,
        },

        "raw_view": {
            "classification":
                "MALICIOUS",

            "risk_score":
                "81",

            "action":
                "BLOCK",

            "status":
                "SUCCESS",

            "request_id":
                "test-request-raw",
        },

        "canonical_view": {
            "classification":
                "SAFE",

            "risk_score":
                "0",

            "action":
                "ALLOW",

            "status":
                "SUCCESS",

            "request_id":
                "test-request-canonical",
        },

        "comparison": {
            "disagreement":
                True,

            "direction":
                "RAW_MORE_DEFENSIVE",

            "finding":
                "RAW_CANONICAL_DISAGREEMENT",
        },

        "production_decision": {
            "classification":
                "SAFE",

            "action":
                "ALLOW",
        },

        "execution": {
            "used_credits":
                0.0,

            "gateway_runtime":
                0.03,
        },

        "input": {
            "raw_sha256":
                "raw-test-hash",

            "canonical_sha256":
                "canonical-test-hash",

            "raw_length":
                56,

            "canonical_length":
                40,
        },

        "_raw_text":
            "TEST_BASE64",

        "_canonical_text":
            "The museum opens at nine in the morning.",
    }


# ============================================================
# Health
# ============================================================

def test_health_endpoint():

    response = client.get(
        "/health"
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["service"]
        == "AgentShield Security Gateway"
    )

    assert (
        body["version"]
        == "1.0.0"
    )

    assert (
        body["canonicalizer"]
        == "V4"
    )

    assert (
        body["policy"]["SAFE"]
        == "ALLOW"
    )

    assert (
        body["policy"]["SUSPICIOUS"]
        == "REVIEW"
    )

    assert (
        body["policy"]["MALICIOUS"]
        == "BLOCK"
    )


# ============================================================
# Root
# ============================================================

def test_root_endpoint():

    response = client.get(
        "/"
    )

    assert response.status_code == 200

    body = response.json()

    assert (
        body["service"]
        == "AgentShield Security Gateway"
    )

    assert (
        body["endpoints"][
            "production_scan"
        ]
        == "/scan"
    )

    assert (
        body["endpoints"][
            "audit"
        ]
        == "/audit"
    )


# ============================================================
# Production scan
# ============================================================

def test_scan_success(
    monkeypatch
):

    monkeypatch.setattr(
        agentshield_api.gateway,
        "production_scan",
        lambda *args, **kwargs:
            fake_production_result(),
    )

    monkeypatch.setattr(
        agentshield_api,
        "persist_audit_record",
        lambda result:
            None,
    )

    response = client.post(
        "/scan",
        json={
            "text":
                "TEST_BASE64",

            "representation":
                "base64",

            "timeout":
                60,

            "include_content":
                False,
        },
    )


    assert response.status_code == 200

    body = response.json()


    assert (
        body["mode"]
        == "production"
    )

    assert (
        body[
            "canonicalization"
        ][
            "representation"
        ]
        == "base64"
    )

    assert (
        body[
            "canonicalization"
        ][
            "changed"
        ]
        is True
    )

    assert (
        body[
            "decision"
        ][
            "classification"
        ]
        == "SAFE"
    )

    assert (
        body[
            "decision"
        ][
            "action"
        ]
        == "ALLOW"
    )

    # Content must remain hidden
    # by default.
    assert (
        "content"
        not in body
    )


# ============================================================
# Content exposure control
# ============================================================

def test_scan_include_content(
    monkeypatch
):

    monkeypatch.setattr(
        agentshield_api.gateway,
        "production_scan",
        lambda *args, **kwargs:
            fake_production_result(),
    )

    monkeypatch.setattr(
        agentshield_api,
        "persist_audit_record",
        lambda result:
            None,
    )


    response = client.post(
        "/scan",
        json={
            "text":
                "TEST_BASE64",

            "representation":
                "base64",

            "timeout":
                60,

            "include_content":
                True,
        },
    )


    assert response.status_code == 200

    body = response.json()


    assert (
        body["content"][
            "raw_text"
        ]
        == "TEST_BASE64"
    )

    assert (
        body["content"][
            "canonical_text"
        ]
        ==
        "The museum opens at nine in the morning."
    )


# ============================================================
# Audit
# ============================================================

def test_audit_detects_disagreement(
    monkeypatch
):

    monkeypatch.setattr(
        agentshield_api.gateway,
        "audit_scan",
        lambda *args, **kwargs:
            fake_audit_result(),
    )

    monkeypatch.setattr(
        agentshield_api,
        "persist_audit_record",
        lambda result:
            None,
    )


    response = client.post(
        "/audit",
        json={
            "text":
                "TEST_BASE64",

            "representation":
                "base64",

            "timeout":
                60,

            "include_content":
                False,
        },
    )


    assert response.status_code == 200

    body = response.json()


    assert (
        body[
            "raw_view"
        ][
            "classification"
        ]
        == "MALICIOUS"
    )

    assert (
        body[
            "raw_view"
        ][
            "action"
        ]
        == "BLOCK"
    )


    assert (
        body[
            "canonical_view"
        ][
            "classification"
        ]
        == "SAFE"
    )

    assert (
        body[
            "canonical_view"
        ][
            "action"
        ]
        == "ALLOW"
    )


    assert (
        body[
            "comparison"
        ][
            "disagreement"
        ]
        is True
    )

    assert (
        body[
            "comparison"
        ][
            "direction"
        ]
        ==
        "RAW_MORE_DEFENSIVE"
    )

    assert (
        body[
            "production_decision"
        ][
            "action"
        ]
        == "ALLOW"
    )


# ============================================================
# Input validation
# ============================================================

def test_empty_input_rejected():

    response = client.post(
        "/scan",
        json={
            "text":
                " ",

            "representation":
                "auto",

            "timeout":
                60,

            "include_content":
                False,
        },
    )


    assert response.status_code == 400


def test_oversized_input_rejected():

    oversized = (
        "A"
        * (
            agentshield_api
            .MAX_INPUT_LENGTH
            + 1
        )
    )


    response = client.post(
        "/scan",
        json={
            "text":
                oversized,

            "representation":
                "auto",

            "timeout":
                60,

            "include_content":
                False,
        },
    )


    assert response.status_code == 413


# ============================================================
# Gateway failure handling
# ============================================================

def test_classifier_failure_returns_502(
    monkeypatch
):

    failed_result = (
        fake_production_result()
    )

    failed_result[
        "execution"
    ][
        "status"
    ] = "FAILED"

    failed_result[
        "decision"
    ][
        "classification"
    ] = None

    failed_result[
        "decision"
    ][
        "action"
    ] = "ERROR"


    monkeypatch.setattr(
        agentshield_api.gateway,
        "production_scan",
        lambda *args, **kwargs:
            failed_result,
    )

    monkeypatch.setattr(
        agentshield_api,
        "persist_audit_record",
        lambda result:
            None,
    )


    response = client.post(
        "/scan",
        json={
            "text":
                "TEST_INPUT",

            "representation":
                "auto",

            "timeout":
                60,

            "include_content":
                False,
        },
    )


    assert response.status_code == 502