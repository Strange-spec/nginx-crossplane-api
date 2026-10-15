# -*- coding: utf-8 -*-
"""
Unit & API integration tests for NGINX Crossplane Config Checker API v1.2.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app
from app.checker import check_nginx_config, format_nginx_config

client = TestClient(app)


def test_missing_semicolon_swallows_sticky_in_upstream():
    """Original NIM 2.23.1 bug: server missing semicolon swallows sticky on next line."""
    cfg = (
        "upstream upstream_cmp-test123.carizon.work {\n"
        "    zone upstream_cmp-test123.carizon.work 64k;\n"
        "    server 10.21.123.12:443\n"
        "    sticky cookie srv_id expires=1h path=/;\n"
        "}"
    )
    res = check_nginx_config(cfg, context="auto", strict=True)
    assert res["valid"] is False
    rules = [e["rule"] for e in res["errors"]]
    assert "missing_semicolon" in rules
    assert "upstream_server_parameter" in rules
    assert any(e["line"] == 3 for e in res["errors"])


def test_missing_semicolon_swallows_zero_arg_directive():
    """Bug fix: missing semicolon before a 0-arg directive like `internal;` or `ip_hash;`."""
    cfg = (
        "server {\n"
        "    listen 80;\n"
        "    location /private {\n"
        "        proxy_pass http://backend\n"
        "        internal;\n"
        "    }\n"
        "}"
    )
    res = check_nginx_config(cfg, context="auto", strict=True)
    assert res["valid"] is False
    assert any(e["rule"] == "missing_semicolon" and e["line"] == 4 for e in res["errors"])


def test_upstream_server_compound_duration_and_plus_params():
    """Bug fix: compound duration like fail_timeout=1m30s and slow_start=2m10s should be valid."""
    cfg = (
        "upstream backend_pool {\n"
        "    zone backend_pool 64k;\n"
        "    server 10.0.0.10:8080 weight=5 max_fails=3 fail_timeout=1m30s slow_start=30s resolve backup;\n"
        "    keepalive 32;\n"
        "}"
    )
    res = check_nginx_config(cfg, context="auto", strict=True)
    assert res["valid"] is True, f"Unexpected errors: {res['errors']}"


def test_nginx_plus_r37_directives_supported():
    """NGINX Plus R37 directives like health_check, status_zone, api, sticky should pass strict check."""
    cfg = (
        "upstream backend {\n"
        "    zone backend 64k;\n"
        "    server 10.0.0.1:8080;\n"
        "    sticky cookie srv_id expires=1h path=/;\n"
        "}\n"
        "server {\n"
        "    listen 443 ssl;\n"
        "    http2 on;\n"
        "    status_zone my_server_zone;\n"
        "    location / {\n"
        "        proxy_pass http://backend;\n"
        "        health_check interval=5s fails=3 passes=2;\n"
        "    }\n"
        "    location /api {\n"
        "        api write=on;\n"
        "    }\n"
        "}"
    )
    res = check_nginx_config(cfg, context="auto", strict=True)
    assert res["valid"] is True, f"Unexpected errors: {res['errors']}"


def test_multi_file_include_check():
    """Multi-file check with `include conf.d/*.conf;` propagating `http` context and detecting errors in child files."""
    files = [
        {
            "filename": "nginx.conf",
            "content": (
                "events {\n"
                "    worker_connections 1024;\n"
                "}\n"
                "http {\n"
                "    include mime.types;\n"
                "    include conf.d/*.conf;\n"
                "}\n"
            ),
        },
        {
            "filename": "conf.d/upstream.conf",
            "content": (
                "upstream app_backend {\n"
                "    server 10.0.0.1:8080\n"
                "    keepalive 16;\n"
                "}\n"
            ),
        },
        {
            "filename": "conf.d/server.conf",
            "content": (
                "server {\n"
                "    listen 80;\n"
                "    server_name example.com;\n"
                "    location / {\n"
                "        proxy_pass http://app_backend;\n"
                "    }\n"
                "}\n"
            ),
        },
    ]
    resp = client.post(
        "/api/v1/check",
        json={
            "filename": "nginx.conf",
            "files": files,
            "strict": True,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert any(
        e["file"] == "conf.d/upstream.conf" and e["line"] == 2 and e["rule"] == "missing_semicolon"
        for e in data["errors"]
    )
    analyzed_files = [c["file"] for c in data["config"]]
    assert "nginx.conf" in analyzed_files
    assert "conf.d/upstream.conf" in analyzed_files
    assert "conf.d/server.conf" in analyzed_files


def test_format_endpoint():
    """Direct `/api/v1/format` endpoint formats messy NGINX config in one request."""
    messy = "upstream backend { server 10.0.0.1:8080 weight=5; keepalive 16; }\nserver { listen 80; location / { proxy_pass http://backend; } }"
    resp = client.post(
        "/api/v1/format",
        json={"config": messy, "indent": 4},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "    server 10.0.0.1:8080 weight=5;" in data["formatted"]
    assert "        proxy_pass http://backend;" in data["formatted"]


def test_runtime_check_with_auto_mock():
    """Runtime check with auto-mocked SSL certificates, logs, undefined upstream, and Plus directives."""
    cfg = (
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_name test.carizon.work;\n"
        "    ssl_certificate /etc/nginx/ssl/nonexistent_prod.crt;\n"
        "    ssl_certificate_key /etc/nginx/ssl/nonexistent_prod.key;\n"
        "    access_log /var/log/nginx/custom_dir/access.log;\n"
        "    status_zone test_zone;\n"
        "    location / {\n"
        "        proxy_pass https://external_unlisted_upstream;\n"
        "    }\n"
        "}"
    )
    res = check_nginx_config(
        config_text=cfg,
        context="auto",
        strict=True,
        check_runtime=True,
        mock_externals=True,
    )
    assert res["valid"] is True, f"Errors: {res['errors']}"
    assert "runtime_check" in res
    rt = res["runtime_check"]
    if rt["available"]:
        assert rt["passed"] is True, f"nginx -t failed: {rt['output']}"
        assert len(rt.get("mocked_items", [])) > 0


def test_runtime_check_on_fixed_sticky_upstream_preset():
    """
    Regression test: when `server 10.21.123.12:443;` has no extra parameters and is followed
    by `sticky cookie ...;`, sandbox transformation must NOT split `:443` into `:44 3;`.
    And when the semicolon IS missing on line 3, `nginx -t` should not comment out line 4's
    `sticky`, so `nginx -t` reports `invalid parameter "sticky" in nginx.conf:4`.
    """
    fixed_cfg = (
        "upstream upstream_cmp-test123.carizon.work {\n"
        "    zone upstream_cmp-test123.carizon.work 64k;\n"
        "    server 10.21.123.12:443;\n"
        "    sticky cookie srv_id expires=1h path=/;\n"
        "}"
    )
    res_fixed = check_nginx_config(
        config_text=fixed_cfg,
        context="auto",
        strict=True,
        check_runtime=True,
        mock_externals=True,
    )
    assert res_fixed["valid"] is True, f"Unexpected errors: {res_fixed['errors']}"
    if res_fixed["runtime_check"]["available"]:
        assert res_fixed["runtime_check"]["passed"] is True, res_fixed["runtime_check"]["output"]

    broken_cfg = (
        "upstream upstream_cmp-test123.carizon.work {\n"
        "    zone upstream_cmp-test123.carizon.work 64k;\n"
        "    server 10.21.123.12:443\n"
        "    sticky cookie srv_id expires=1h path=/;\n"
        "}"
    )
    res_broken = check_nginx_config(
        config_text=broken_cfg,
        context="auto",
        strict=True,
        check_runtime=True,
        mock_externals=True,
    )
    assert res_broken["valid"] is False
    if res_broken["runtime_check"]["available"]:
        assert res_broken["runtime_check"]["passed"] is False
        assert 'invalid parameter "sticky" in nginx.conf:4' in res_broken["runtime_check"]["output"]


def test_upstream_server_address_and_fullwidth_punctuation():
    """
    Regression test for user-reported issue:
    `server 10.21.123.12:443);`, `server 10.21.123.12:443）;`, `server 10.21.123.12:443）；`,
    and `server 10.21.123.12:443）` must ALL fail static analysis immediately even with check_runtime=False.
    """
    bad_variants = [
        "server 10.21.123.12:443);",
        "server 10.21.123.12:443）;",
        "server 10.21.123.12:443）；",
        "server 10.21.123.12:443）",
    ]
    for variant in bad_variants:
        cfg = (
            "upstream upstream_cmp-test123.carizon.work {\n"
            "    zone upstream_cmp-test123.carizon.work 64k;\n"
            f"    {variant}\n"
            "    sticky cookie srv_id expires=1h path=/;\n"
            "}"
        )
        res = check_nginx_config(config_text=cfg, context="auto", strict=True, check_runtime=False)
        assert res["valid"] is False, f"Expected variant `{variant}` to fail static check, but it passed!"
        assert any(e["line"] == 3 for e in res["errors"]), f"Expected error on line 3 for `{variant}`, got: {res['errors']}"

