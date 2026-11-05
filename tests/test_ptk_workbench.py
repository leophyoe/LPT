"""Unit and GUI tests for OWASP PTK (Penetration Testing Kit) integration."""

import os
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import pytest
from PySide6.QtCore import Qt
from desktop.views.web_scan_view import WebScanView
from modules.web.ptk_engine import (
    PTKEncoder,
    PTKJWTAnalyzer,
    PTKPayloads,
    PTKRequestBuilder,
    PTKSCAAnalyzer,
)
from storage.db import Database
from storage.models import Project, TargetScope, TargetType


@pytest.fixture
def test_db():
    return Database(":memory:")


# -------------------------------------------------------------------------
# 1. PTK Engine Tests
# -------------------------------------------------------------------------

def test_ptk_encoder_all_transforms():
    """Verify all text transformations, URL, Base64, Hex, HTML, and hash routines."""
    raw = "admin' OR 1=1; <test>&\""
    
    # URL
    url_enc = PTKEncoder.url_encode(raw)
    assert "%20" in url_enc or "%27" in url_enc
    assert PTKEncoder.url_decode(url_enc) == raw

    # Base64
    b64 = PTKEncoder.base64_encode(raw)
    assert PTKEncoder.base64_decode(b64) == raw

    # Hex
    hex_str = PTKEncoder.hex_encode("ABC")
    assert hex_str.lower() == "414243"
    assert PTKEncoder.hex_decode(hex_str) == "ABC"

    # HTML
    html_enc = PTKEncoder.html_encode("<script>alert(1)</script>")
    assert "&lt;script&gt;" in html_enc
    assert PTKEncoder.html_decode(html_enc) == "<script>alert(1)</script>"

    # Hashes
    assert len(PTKEncoder.hash_md5("test")) == 32
    assert len(PTKEncoder.hash_sha1("test")) == 40
    assert len(PTKEncoder.hash_sha256("test")) == 64


def test_ptk_jwt_analyzer_and_forge():
    """Verify JWT decoding, claim validation, weak secret detection, and 'none' alg forge."""
    # 1. Forge valid token with weak key "secret"
    token = PTKJWTAnalyzer.forge_hmac_token(
        header={"alg": "HS256", "typ": "JWT"},
        payload={"sub": "1001", "role": "user", "exp": 2000000000},
        secret="secret",
    )
    res = PTKJWTAnalyzer.analyze_token(token)
    assert res.is_valid_format is True
    assert res.algorithm == "HS256"
    assert res.payload.get("sub") == "1001"
    assert res.is_expired is False
    assert any("Weak HMAC Secret" in v["title"] for v in res.vulnerabilities)

    # 2. Test expired token
    exp_token = PTKJWTAnalyzer.forge_hmac_token(
        header={"alg": "HS256"},
        payload={"sub": "user", "exp": 1000000000},  # year 2001
        secret="my_long_random_strong_key_12345",
    )
    exp_res = PTKJWTAnalyzer.analyze_token(exp_token)
    assert exp_res.is_expired is True
    assert any("Expired Token" in v["title"] for v in exp_res.vulnerabilities)

    # 3. Test 'alg: none' token forging
    none_forged = PTKJWTAnalyzer.forge_none_token(token, {"role": "admin"})
    none_res = PTKJWTAnalyzer.analyze_token(none_forged)
    assert none_res.is_valid_format is True
    assert none_res.algorithm.lower() == "none"
    assert none_res.payload.get("role") == "admin"
    assert any("Insecure 'none' Algorithm" in v["title"] for v in none_res.vulnerabilities)


def test_ptk_curl_parser_and_builder():
    """Verify cURL command bidirectional conversion."""
    curl_in = "curl -X POST https://targetlab.corp/api/login -H 'Content-Type: application/json' -H 'Authorization: Bearer test' --data-raw '{\"user\":\"admin\"}'"
    parsed = PTKRequestBuilder.parse_curl(curl_in)
    assert parsed["method"] == "POST"
    assert parsed["url"] == "https://targetlab.corp/api/login"
    assert parsed["headers"]["Content-Type"] == "application/json"
    assert parsed["headers"]["Authorization"] == "Bearer test"
    assert "user" in parsed["body"]

    # Re-export
    curl_out = PTKRequestBuilder.to_curl(parsed["method"], parsed["url"], parsed["headers"], parsed["body"])
    assert "curl" in curl_out
    assert "POST" in curl_out
    assert "targetlab.corp" in curl_out


def test_ptk_payloads_catalog():
    """Verify categorized pentest attack payloads."""
    cats = PTKPayloads.get_categories()
    assert "Cross-Site Scripting (XSS)" in cats
    assert "SQL Injection (SQLi)" in cats
    assert "Server-Side Request Forgery (SSRF)" in cats
    assert "Path Traversal / Local File Inclusion (LFI)" in cats

    xss_payloads = PTKPayloads.get_payloads("Cross-Site Scripting (XSS)")
    assert len(xss_payloads) >= 4
    assert any("<script>" in p["payload"] for p in xss_payloads)


def test_ptk_sca_analyzer():
    """Verify header compliance and client-side JS library component identification."""
    # Test missing headers
    findings = PTKSCAAnalyzer.audit_headers({"Server": "Apache/2.4.41 (Ubuntu)"})
    assert any("Missing Security Header: Content-Security-Policy" in f["title"] for f in findings)
    assert any("Server Information Disclosure" in f["title"] for f in findings)

    # Test library detection
    html_code = '<html><head><script src="/assets/jquery-3.2.1.min.js"></script></head><body></body></html>'
    comps = PTKSCAAnalyzer.detect_components(html_code)
    assert len(comps) == 1
    assert comps[0]["name"] == "jQuery"
    assert comps[0]["version"] == "3.2.1"
    assert comps[0]["has_cve"] is True


def test_ptk_rbuilder_scope_guard(test_db):
    """Verify PTKRequestBuilder strictly blocks out-of-scope destinations."""
    project = test_db.create_project(Project(name="Scope Guarded Project"))
    test_db.add_scope(
        TargetScope(
            project_id=project.id,
            target="targetlab.corp",
            target_type=TargetType.HOSTNAME,
            is_authorized=True,
        )
    )

    # 1. Out-of-scope URL blocked
    res_blocked = PTKRequestBuilder.send_request(
        method="GET",
        url="https://unauthorized-domain.com/secret",
        project=project,
        db=test_db,
    )
    assert res_blocked.is_authorized is False
    assert "Scope Guard" in res_blocked.error


def test_ptk_rbuilder_requires_project_scope(test_db, monkeypatch):
    def unexpected_request(**kwargs):
        raise AssertionError("network request should not be sent without an authorized project")

    monkeypatch.setattr("modules.web.ptk_engine.requests.request", unexpected_request)
    result = PTKRequestBuilder.send_request("GET", "https://example.com")
    assert not result.is_authorized
    assert "project and database are required" in result.error


# -------------------------------------------------------------------------
# 2. PTK GUI Workbench Tests
# -------------------------------------------------------------------------

def test_ptk_ui_tab_rendering(qtbot, test_db):
    """Verify OWASP PTK Workbench tab renders inside WebScanView with all 4 subtabs."""
    view = WebScanView(db=test_db)
    qtbot.addWidget(view)
    view.show()

    # Verify Tab exists and has title
    assert view.results_tabs.count() >= 5
    ptk_indices = [i for i in range(view.results_tabs.count()) if "OWASP PTK Workbench" in view.results_tabs.tabText(i)]
    assert len(ptk_indices) > 0
    ptk_idx = ptk_indices[0]

    # Switch to PTK tab
    view.results_tabs.setCurrentIndex(ptk_idx)
    assert hasattr(view, "rbuilder_subtab")
    assert hasattr(view, "jwt_subtab")
    assert hasattr(view, "encoder_subtab")
    assert hasattr(view, "sca_subtab")

    # Verify R-Builder widgets
    assert view.ptk_r_method.count() >= 6
    assert view.btn_ptk_send.isEnabled()

    # Test Encoder Live Transformation
    view.ptk_enc_input.setPlainText("admin 123")
    view._on_ptk_transform("url_enc")
    assert "admin%20123" in view.ptk_enc_output.toPlainText()

    view._on_ptk_transform("b64_enc")
    assert len(view.ptk_enc_output.toPlainText()) > 0

    # Test Payloads Category Switch
    view.ptk_payload_cat_combo.setCurrentText("SQL Injection (SQLi)")
    assert view.ptk_payload_table.rowCount() >= 4

    # Test JWT Analysis
    sample_jwt = PTKJWTAnalyzer.forge_none_token("eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdCJ9.sig", {"admin": True})
    view.ptk_jwt_input.setPlainText(sample_jwt)
    view._on_ptk_analyze_jwt()
    assert "none" in view.ptk_jwt_meta_label.text().lower()
    assert view.ptk_jwt_vulns_table.rowCount() >= 1

