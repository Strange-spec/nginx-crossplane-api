# -*- coding: utf-8 -*-
"""
FastAPI HTTP Service for NGINX Crossplane Config Checking & Analysis (v1.2).
"""

import shutil
from typing import Any, Dict, List, Optional
import crossplane
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from .checker import check_nginx_config, format_nginx_config, lex_string_with_lines


app = FastAPI(
    title="NGINX Crossplane Config Checker API",
    description=(
        "REST API for checking, parsing, lexing, formatting, and runtime-verifying NGINX / NGINX Plus "
        "configurations powered by Crossplane + Deep Semantic Analyzer + Auto-Mocked `nginx -t`."
    ),
    version="1.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConfigFileItem(BaseModel):
    filename: str = Field(..., description="Relative path or filename (e.g. 'nginx.conf' or 'conf.d/app.conf').")
    content: str = Field(..., description="Configuration file content.")


class CheckRequest(BaseModel):
    config: Optional[str] = Field(
        default=None,
        description="Raw NGINX configuration text or snippet to analyze (optional if `files` is provided).",
        json_schema_extra={
            "example": (
                "upstream upstream_cmp-test123.carizon.work {\n"
                "    zone upstream_cmp-test123.carizon.work 64k;\n"
                "    server 10.21.123.12:443\n"
                "    sticky cookie srv_id expires=1h path=/;\n"
                "}"
            )
        },
    )
    filename: str = Field(default="nginx.conf", description="Main entry filename.")
    files: Optional[List[ConfigFileItem]] = Field(
        default=None,
        description="Optional multi-file configuration array supporting `include conf.d/*.conf`.",
    )
    context: str = Field(
        default="auto",
        description="Starting context: 'auto' (detects snippets like upstream/server), 'main', 'http', 'stream', 'server', 'upstream', or 'location'.",
    )
    strict: bool = Field(default=True, description="Fail on unknown directives.")
    comments: bool = Field(default=False, description="Include comments in parsed AST output.")
    check_runtime: bool = Field(
        default=False,
        description="Also run real `nginx -t` binary verification in an isolated sandbox.",
    )
    mock_externals: bool = Field(
        default=True,
        description="Automatically mock missing SSL certificates, keys, log directories, undefined upstreams, and NGINX Plus directives during `nginx -t`.",
    )


class BuildRequest(BaseModel):
    parsed: List[Dict[str, Any]] = Field(..., description="Crossplane parsed AST array (`config[0].parsed`).")
    indent: int = Field(default=4, description="Indentation spaces.")
    tabs: bool = Field(default=False, description="Use tabs instead of spaces.")


class FormatRequest(BaseModel):
    config: str = Field(..., description="Raw NGINX configuration text to format.")
    filename: str = Field(default="nginx.conf", description="Virtual filename.")
    indent: int = Field(default=4, description="Indentation spaces.")
    tabs: bool = Field(default=False, description="Use tabs instead of spaces.")
    comments: bool = Field(default=True, description="Preserve comments when formatting.")


@app.get("/health", summary="Health Check")
async def health() -> Dict[str, Any]:
    nginx_bin = shutil.which("nginx")
    return {
        "status": "healthy",
        "service": "nginx-crossplane-api",
        "version": "1.2.0",
        "crossplane_version": getattr(crossplane, "__version__", "0.5.8"),
        "nginx_binary_available": bool(nginx_bin),
        "features": [
            "crossplane_lex_parse_build_format",
            "multi_file_include_resolution",
            "nginx_plus_r37_directives",
            "upstream_server_parameter_validation",
            "multiline_missing_semicolon_detection",
            "auto_snippet_context_detection",
            "nginx_t_runtime_sandbox_with_auto_mock",
        ],
    }


@app.post("/api/v1/check", summary="Check & Analyze NGINX Config (Single-File, Multi-File, or text/plain)")
@app.post("/api/v1/analyze", summary="Alias for /api/v1/check")
async def api_check_config(
    request: Request,
    filename: str = Query(default="nginx.conf", description="Filename when sending text/plain body"),
    context: str = Query(default="auto", description="Context when sending text/plain body"),
    strict: bool = Query(default=True, description="Strict directive checking"),
    comments: bool = Query(default=False, description="Include comments in AST"),
    check_runtime: bool = Query(default=False, description="Run nginx -t runtime test"),
    mock_externals: bool = Query(default=True, description="Auto-mock certs/dirs during nginx -t"),
) -> JSONResponse:
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {e}")
        req = CheckRequest(**body)
        if req.config is None and not req.files:
            raise HTTPException(status_code=400, detail="Either 'config' or 'files' must be provided.")
        files_dicts = [f.model_dump() for f in req.files] if req.files else None
        res = check_nginx_config(
            config_text=req.config,
            filename=req.filename,
            context=req.context,
            strict=req.strict,
            comments=req.comments,
            check_runtime=req.check_runtime,
            mock_externals=req.mock_externals,
            files=files_dicts,
        )
    else:
        raw_bytes = await request.body()
        config_text = raw_bytes.decode("utf-8", errors="replace")
        if not config_text.strip():
            raise HTTPException(status_code=400, detail="Empty configuration payload.")
        res = check_nginx_config(
            config_text=config_text,
            filename=filename,
            context=context,
            strict=strict,
            comments=comments,
            check_runtime=check_runtime,
            mock_externals=mock_externals,
        )

    return JSONResponse(content=res)


@app.post("/api/v1/lex", summary="Tokenize NGINX Config into Tokens with Line Numbers")
async def api_lex_config(req: CheckRequest) -> Dict[str, Any]:
    target_text = req.config or (req.files[0].content if req.files else "")
    target_name = req.filename or (req.files[0].filename if req.files else "nginx.conf")
    tokens, errors = lex_string_with_lines(target_text, filename=target_name)
    return {
        "status": "ok" if not errors else "failed",
        "errors": errors,
        "tokens": [
            {"token": tok, "line": line, "quoted": quoted}
            for tok, line, quoted in tokens
        ],
    }


@app.post("/api/v1/build", summary="Format / Rebuild NGINX Config from Crossplane AST")
async def api_build_config(req: BuildRequest) -> Dict[str, Any]:
    try:
        formatted = crossplane.build(req.parsed, indent=req.indent, tabs=req.tabs)
        return {
            "status": "ok",
            "config": formatted,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to build config from AST: {e}")


@app.post("/api/v1/format", summary="Directly Format / Prettify Raw NGINX Config Text")
async def api_format_config(req: FormatRequest) -> Dict[str, Any]:
    try:
        res = format_nginx_config(
            config_text=req.config,
            filename=req.filename,
            indent=req.indent,
            tabs=req.tabs,
            comments=req.comments,
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to format configuration: {e}")


INDEX_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>NGINX Crossplane Studio v1.2 — 配置静态分析、多文件 Include 与 nginx -t 诊断平台</title>
  <style>
    :root {
      --bg-base: #070b14;
      --bg-surface: #0f1626;
      --bg-elevated: #162033;
      --bg-editor: #0a0f1d;
      --border: #1e2d45;
      --border-light: #2b3f5c;
      --text-main: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --nginx-green: #009639;
      --emerald: #10b981;
      --emerald-glow: rgba(16, 185, 129, 0.16);
      --danger: #ef4444;
      --danger-glow: rgba(239, 68, 68, 0.16);
      --warn: #f59e0b;
      --warn-glow: rgba(245, 158, 11, 0.16);
      --blue: #38bdf8;
      --purple: #a78bfa;
      --radius-lg: 14px;
      --radius-md: 10px;
      --radius-sm: 6px;
      --font-sans: "Inter", -apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", sans-serif;
      --font-mono: "JetBrains Mono", "SFMono-Regular", Menlo, Monaco, Consolas, monospace;
    }

    * { box-sizing: border-box; }
    html, body {
      margin: 0;
      padding: 0;
      height: 100%;
      background-color: var(--bg-base);
      background-image:
        radial-gradient(at 0% 0%, rgba(16, 185, 129, 0.08) 0px, transparent 45%),
        radial-gradient(at 100% 0%, rgba(56, 189, 248, 0.07) 0px, transparent 45%);
      color: var(--text-main);
      font-family: var(--font-sans);
      -webkit-font-smoothing: antialiased;
    }

    .top-ribbon {
      height: 3px;
      background: linear-gradient(90deg, #009639 0%, #10b981 50%, #38bdf8 100%);
    }

    .app-shell {
      max-width: 1540px;
      margin: 0 auto;
      padding: 18px 28px 28px;
      display: flex;
      flex-direction: column;
      gap: 16px;
      min-height: calc(100vh - 3px);
    }

    .navbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: rgba(15, 22, 38, 0.85);
      backdrop-filter: blur(12px);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 14px 22px;
      box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .brand-logo {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: linear-gradient(135deg, #009639 0%, #059669 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 4px 14px rgba(0, 150, 57, 0.4);
      font-weight: 800;
      font-size: 20px;
      color: #fff;
      font-family: var(--font-mono);
    }

    .brand-title {
      font-size: 18px;
      font-weight: 700;
      letter-spacing: -0.01em;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .brand-sub {
      font-size: 12.5px;
      color: var(--text-secondary);
      margin-top: 2px;
    }

    .engine-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 11.5px;
      font-weight: 600;
      padding: 3px 10px;
      border-radius: 999px;
      background: var(--emerald-glow);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.35);
    }

    .pulse-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: #10b981;
      box-shadow: 0 0 8px #10b981;
    }

    .nav-actions {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .nav-link {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 8px 14px;
      border-radius: var(--radius-sm);
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      color: var(--text-main);
      text-decoration: none;
      font-size: 13px;
      font-weight: 500;
      transition: all 0.15s ease;
    }

    .nav-link:hover {
      border-color: var(--blue);
      color: var(--blue);
      transform: translateY(-1px);
    }

    .preset-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 10px 16px;
    }

    .preset-group {
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }

    .preset-label {
      font-size: 12.5px;
      font-weight: 600;
      color: var(--text-secondary);
      margin-right: 4px;
    }

    .preset-btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--bg-elevated);
      color: var(--text-main);
      border: 1px solid var(--border);
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 12.5px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
    }

    .preset-btn:hover, .preset-btn.active {
      border-color: var(--emerald);
      background: rgba(16, 185, 129, 0.12);
      color: #fff;
    }

    .dot-red { width: 8px; height: 8px; border-radius: 50%; background: var(--danger); }
    .dot-amber { width: 8px; height: 8px; border-radius: 50%; background: var(--warn); }
    .dot-green { width: 8px; height: 8px; border-radius: 50%; background: var(--emerald); }
    .dot-blue { width: 8px; height: 8px; border-radius: 50%; background: var(--blue); }

    .workspace {
      display: grid;
      grid-template-columns: 1.05fr 1fr;
      gap: 20px;
      flex: 1;
      min-height: 620px;
    }

    @media (max-width: 1100px) {
      .workspace { grid-template-columns: 1fr; }
    }

    .pane {
      background: var(--bg-surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      display: flex;
      flex-direction: column;
      overflow: hidden;
      box-shadow: 0 12px 32px -12px rgba(0, 0, 0, 0.55);
    }

    .pane-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 16px;
      background: rgba(22, 32, 51, 0.65);
      border-bottom: 1px solid var(--border);
      gap: 8px;
      flex-wrap: wrap;
    }

    .file-tabs-bar {
      display: flex;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }

    .file-tab {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--bg-editor);
      border: 1px solid var(--border);
      padding: 5px 11px;
      border-radius: var(--radius-sm);
      font-family: var(--font-mono);
      font-size: 12px;
      color: var(--text-secondary);
      cursor: pointer;
      transition: all 0.15s;
    }

    .file-tab.active {
      border-color: var(--emerald);
      color: #fff;
      background: rgba(16, 185, 129, 0.14);
    }

    .file-tab .del-file {
      color: var(--text-muted);
      font-weight: bold;
      margin-left: 2px;
    }
    .file-tab .del-file:hover { color: var(--danger); }

    .toolbar-btns {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .btn-tool {
      background: var(--bg-elevated);
      color: var(--text-secondary);
      border: 1px solid var(--border);
      padding: 5px 11px;
      border-radius: var(--radius-sm);
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s;
    }

    .btn-tool:hover {
      color: var(--text-main);
      border-color: var(--border-light);
      background: #1e293b;
    }

    .editor-wrapper {
      position: relative;
      flex: 1;
      display: flex;
      background: var(--bg-editor);
      overflow: hidden;
      min-height: 450px;
    }

    .gutter {
      width: 58px;
      padding: 16px 0;
      background: #080c17;
      border-right: 1px solid var(--border);
      font-family: var(--font-mono);
      font-size: 13.5px;
      line-height: 22px;
      color: var(--text-muted);
      user-select: none;
      overflow: hidden;
      text-align: right;
      flex-shrink: 0;
    }

    .gutter-line {
      height: 22px;
      padding-right: 12px;
      display: flex;
      align-items: center;
      justify-content: flex-end;
      gap: 5px;
    }

    .gutter-line.err {
      color: #f87171;
      background: rgba(239, 68, 68, 0.16);
      font-weight: 700;
    }

    .gutter-line.warn {
      color: #fbbf24;
      background: rgba(245, 158, 11, 0.14);
      font-weight: 700;
    }

    .editor-stage {
      position: relative;
      flex: 1;
      overflow: hidden;
    }

    .highlight-backdrop {
      position: absolute;
      inset: 0;
      padding: 16px 0;
      pointer-events: none;
      overflow: hidden;
      font-family: var(--font-mono);
      font-size: 13.5px;
      line-height: 22px;
    }

    .hl-row {
      height: 22px;
      width: 100%;
    }

    .hl-row.err {
      background: rgba(239, 68, 68, 0.15);
      border-left: 3px solid var(--danger);
    }

    .hl-row.warn {
      background: rgba(245, 158, 11, 0.12);
      border-left: 3px solid var(--warn);
    }

    #configInput {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      background: transparent;
      color: #e2e8f0;
      border: none;
      outline: none;
      padding: 16px 18px;
      font-family: var(--font-mono);
      font-size: 13.5px;
      line-height: 22px;
      resize: none;
      white-space: pre;
      overflow: auto;
      tab-size: 4;
    }

    .editor-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 12px 18px;
      background: rgba(22, 32, 51, 0.75);
      border-top: 1px solid var(--border);
      flex-wrap: wrap;
      gap: 12px;
    }

    .control-options {
      display: flex;
      align-items: center;
      gap: 14px;
      flex-wrap: wrap;
    }

    .ctrl-label {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 12.5px;
      color: var(--text-secondary);
      cursor: pointer;
    }

    select.ctrl-select {
      background: var(--bg-editor);
      color: var(--text-main);
      border: 1px solid var(--border-light);
      padding: 5px 9px;
      border-radius: var(--radius-sm);
      font-size: 12px;
      outline: none;
    }

    .btn-primary {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: linear-gradient(135deg, #009639 0%, #10b981 100%);
      color: #ffffff;
      font-weight: 600;
      font-size: 13.5px;
      border: none;
      padding: 9px 18px;
      border-radius: var(--radius-sm);
      cursor: pointer;
      box-shadow: 0 4px 15px rgba(16, 185, 129, 0.35);
      transition: all 0.15s ease;
    }

    .btn-primary:hover {
      transform: translateY(-1px);
      box-shadow: 0 6px 20px rgba(16, 185, 129, 0.5);
    }

    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      padding: 14px 18px;
      border-bottom: 1px solid var(--border);
      background: rgba(10, 15, 29, 0.45);
    }

    .kpi-card {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 10px 14px;
    }

    .kpi-label {
      font-size: 11.5px;
      color: var(--text-secondary);
      margin-bottom: 4px;
    }

    .kpi-val {
      font-size: 17px;
      font-weight: 700;
      font-family: var(--font-mono);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .kpi-val.ok { color: #34d399; }
    .kpi-val.fail { color: #f87171; }
    .kpi-val.warn { color: #fbbf24; }
    .kpi-val.ctx { color: var(--blue); font-size: 14px; }

    .tabs-nav {
      display: flex;
      gap: 4px;
      padding: 10px 18px 0;
      border-bottom: 1px solid var(--border);
      background: rgba(22, 32, 51, 0.4);
    }

    .tab-btn {
      background: transparent;
      color: var(--text-secondary);
      border: none;
      border-bottom: 2px solid transparent;
      padding: 9px 14px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.15s;
    }

    .tab-btn:hover { color: var(--text-main); }
    .tab-btn.active {
      color: var(--emerald);
      border-bottom-color: var(--emerald);
    }

    .tab-count {
      font-size: 11px;
      padding: 1px 7px;
      border-radius: 999px;
      background: var(--bg-elevated);
      font-family: var(--font-mono);
    }

    .tab-content {
      flex: 1;
      padding: 18px;
      overflow-y: auto;
      max-height: 500px;
    }

    .tab-pane { display: none; }
    .tab-pane.active { display: block; }

    .empty-pass {
      text-align: center;
      padding: 36px 20px;
      background: rgba(16, 185, 129, 0.06);
      border: 1px dashed rgba(16, 185, 129, 0.35);
      border-radius: var(--radius-md);
      margin-bottom: 14px;
    }

    .empty-pass h3 {
      margin: 10px 0 6px;
      color: #34d399;
      font-size: 16px;
    }

    .empty-pass p {
      margin: 0;
      color: var(--text-secondary);
      font-size: 13px;
    }

    .runtime-box {
      background: var(--bg-elevated);
      border: 1px solid var(--border-light);
      border-radius: var(--radius-md);
      padding: 12px 15px;
      margin-bottom: 14px;
    }

    .diag-card {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-left: 4px solid var(--danger);
      border-radius: var(--radius-md);
      padding: 14px 16px;
      margin-bottom: 14px;
    }

    .diag-card.warning { border-left-color: var(--warn); }

    .diag-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
      gap: 8px;
      flex-wrap: wrap;
    }

    .diag-badges {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .badge-sev {
      font-size: 11px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      text-transform: uppercase;
      font-family: var(--font-mono);
    }

    .badge-sev.err {
      background: var(--danger-glow);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.35);
    }

    .badge-sev.warn {
      background: var(--warn-glow);
      color: #fbbf24;
      border: 1px solid rgba(245, 158, 11, 0.35);
    }

    .badge-line {
      font-size: 12px;
      font-family: var(--font-mono);
      background: #0b1120;
      color: var(--blue);
      border: 1px solid var(--border-light);
      padding: 2px 9px;
      border-radius: 4px;
      cursor: pointer;
    }

    .badge-rule {
      font-size: 11.5px;
      font-family: var(--font-mono);
      color: var(--purple);
      background: rgba(167, 139, 250, 0.12);
      padding: 2px 8px;
      border-radius: 4px;
    }

    .diag-msg {
      font-size: 14px;
      font-weight: 600;
      color: var(--text-main);
      margin-bottom: 10px;
      line-height: 1.45;
    }

    .code-preview {
      background: #080c17;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 8px 12px;
      font-family: var(--font-mono);
      font-size: 12.5px;
      color: #cbd5e1;
      margin-bottom: 10px;
      overflow-x: auto;
      display: flex;
      gap: 12px;
    }

    .code-preview-ln {
      color: var(--text-muted);
      user-select: none;
    }

    .diag-Suggest {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      background: rgba(56, 189, 248, 0.08);
      border: 1px solid rgba(56, 189, 248, 0.22);
      border-radius: var(--radius-sm);
      padding: 8px 12px;
      font-size: 12.5px;
      color: #bae6fd;
    }

    .btn-autofix {
      background: var(--blue);
      color: #082f49;
      border: none;
      padding: 5px 11px;
      border-radius: 5px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      white-space: nowrap;
      flex-shrink: 0;
    }

    .ast-node {
      font-family: var(--font-mono);
      font-size: 13px;
      margin-left: 16px;
      border-left: 1px dashed var(--border-light);
      padding-left: 12px;
      margin-top: 6px;
    }

    .ast-dir { color: #34d399; font-weight: 700; }
    .ast-arg { color: #fde047; }
    .ast-ln { color: var(--text-muted); font-size: 11.5px; }

    pre.code-box {
      background: #080c17;
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      padding: 14px;
      font-family: var(--font-mono);
      font-size: 12.5px;
      line-height: 1.55;
      color: #e2e8f0;
      overflow: auto;
      margin: 0;
    }

    .token-row {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 7px 10px;
      border-bottom: 1px solid var(--border);
      font-family: var(--font-mono);
      font-size: 12.5px;
      flex-wrap: wrap;
    }

    .token-ln {
      width: 58px;
      color: var(--text-muted);
      font-size: 11.5px;
      flex-shrink: 0;
    }

    .tok-chip {
      padding: 2px 8px;
      border-radius: 4px;
      background: var(--bg-elevated);
      border: 1px solid var(--border-light);
      color: #e2e8f0;
    }

    .tok-chip.delim {
      color: var(--emerald);
      border-color: rgba(16, 185, 129, 0.4);
      font-weight: 700;
    }

    .tok-chip.quoted { color: #fde047; }
  </style>
</head>
<body>
  <div class="top-ribbon"></div>

  <div class="app-shell">
    <nav class="navbar">
      <div class="brand">
        <div class="brand-logo">N</div>
        <div>
          <div class="brand-title">
            NGINX Crossplane Studio
            <span class="engine-pill"><span class="pulse-dot"></span> v1.2 • Crossplane + R37 Semantic + Auto-Mock nginx -t</span>
          </div>
          <div class="brand-sub">支持多文件 Include 解析、跨行漏分号检测、Upstream 参数校验、外部证书/日志自动 Mock 与真实 nginx -t 双重验证</div>
        </div>
      </div>
      <div class="nav-actions">
        <a href="/docs" target="_blank" class="nav-link">📘 Swagger API (/docs)</a>
        <a href="/health" target="_blank" class="nav-link">💚 Health (/health)</a>
      </div>
    </nav>

    <div class="preset-bar">
      <div class="preset-group">
        <span class="preset-label">快速测试场景：</span>
        <button class="preset-btn active" onclick="loadPreset('bug', this)">
          <span class="dot-red"></span> 缺陷复现：漏分号吞并 sticky
        </button>
        <button class="preset-btn" onclick="loadPreset('multifile', this)">
          <span class="dot-blue"></span> 多文件：nginx.conf + include conf.d/*.conf
        </button>
        <button class="preset-btn" onclick="loadPreset('ssl_mock', this)">
          <span class="dot-green"></span> 证书/依赖自动 Mock + nginx -t
        </button>
        <button class="preset-btn" onclick="loadPreset('valid', this)">
          <span class="dot-green"></span> 标准配置：NGINX Plus R37
        </button>
      </div>
      <div class="toolbar-btns">
        <input type="file" id="fileInput" accept=".conf,.txt" style="display:none" onchange="handleFileUpload(event)" />
        <button class="btn-tool" onclick="addNewFileTab()">➕ 新增子文件</button>
        <button class="btn-tool" onclick="document.getElementById('fileInput').click()">📂 导入文件</button>
        <button class="btn-tool" onclick="formatConfig()">✨ 一键美化 (/format)</button>
        <button class="btn-tool" onclick="copyConfig()">📋 复制</button>
      </div>
    </div>

    <div class="workspace">
      <div class="pane">
        <div class="pane-header">
          <div class="file-tabs-bar" id="fileTabsBar"></div>
          <div class="toolbar-btns">
            <span style="font-size:12px;color:var(--text-muted);" id="editorStats"></span>
          </div>
        </div>

        <div class="editor-wrapper">
          <div class="gutter" id="lineGutter"></div>
          <div class="editor-stage">
            <div class="highlight-backdrop" id="hlBackdrop"></div>
            <textarea id="configInput" spellcheck="false" oninput="onEditorInput()" onscroll="syncScroll()"></textarea>
          </div>
        </div>

        <div class="editor-footer">
          <div class="control-options">
            <label class="ctrl-label">
              上下文:
              <select id="ctxSelect" class="ctrl-select" onchange="runCheck()">
                <option value="auto" selected>auto (智能识别)</option>
                <option value="main">main (完整配置)</option>
                <option value="http">http (conf.d)</option>
                <option value="stream">stream</option>
                <option value="server">server</option>
                <option value="upstream">upstream</option>
              </select>
            </label>
            <label class="ctrl-label">
              <input type="checkbox" id="strictCheck" checked onchange="runCheck()" />
              Strict 严格校验
            </label>
            <label class="ctrl-label">
              <input type="checkbox" id="runtimeCheck" checked onchange="runCheck()" />
              执行真实 <code>nginx -t</code>
            </label>
            <label class="ctrl-label">
              <input type="checkbox" id="mockExternals" checked onchange="runCheck()" />
              自动 Mock 证书/外部依赖
            </label>
          </div>
          <button class="btn-primary" onclick="runCheck()">
            ⚡ 立即执行检查
          </button>
        </div>
      </div>

      <div class="pane">
        <div class="kpi-grid">
          <div class="kpi-card">
            <div class="kpi-label">综合结论 (Status)</div>
            <div class="kpi-val fail" id="kpiStatus">FAILED</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">静态错误 (Errors)</div>
            <div class="kpi-val fail" id="kpiErrors">0</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">nginx -t 运行时</div>
            <div class="kpi-val ok" id="kpiRuntime">--</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">识别上下文 (Context)</div>
            <div class="kpi-val ctx" id="kpiContext">http</div>
          </div>
        </div>

        <div class="tabs-nav">
          <button class="tab-btn active" onclick="switchTab('diag', this)">
            🛡️ 诊断与 nginx -t <span class="tab-count" id="badgeDiagCount">0</span>
          </button>
          <button class="tab-btn" onclick="switchTab('ast', this)">
            🌳 Crossplane AST
          </button>
          <button class="tab-btn" onclick="switchTab('tokens', this)">
            🔤 词法 Token 流 <span class="tab-count" id="badgeTokenCount">0</span>
          </button>
          <button class="tab-btn" onclick="switchTab('api', this)">
            🚀 API 调用代码
          </button>
        </div>

        <div class="tab-content">
          <div class="tab-pane active" id="tab-diag">
            <div id="diagContainer"></div>
          </div>

          <div class="tab-pane" id="tab-ast">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
              <span style="font-size:12.5px;color:var(--text-secondary);">Crossplane 多文件 AST 树与完整响应 JSON</span>
              <button class="btn-tool" onclick="copyText(document.getElementById('jsonOutput').textContent)">复制 JSON</button>
            </div>
            <div id="astTreeContainer" style="margin-bottom:14px;"></div>
            <pre class="code-box" id="jsonOutput"></pre>
          </div>

          <div class="tab-pane" id="tab-tokens">
            <div id="tokenContainer"></div>
          </div>

          <div class="tab-pane" id="tab-api">
            <div style="margin-bottom:8px;font-size:12.5px;color:var(--text-secondary);display:flex;justify-content:space-between;">
              <span>1. cURL 命令行调用（支持单文件与多文件 JSON）</span>
              <button class="btn-tool" onclick="copyText(document.getElementById('curlSnippet').textContent)">复制 cURL</button>
            </div>
            <pre class="code-box" id="curlSnippet" style="margin-bottom:16px;"></pre>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    const PRESETS = {
      bug: [
        {
          filename: 'nginx.conf',
          content: `upstream upstream_cmp-test123.carizon.work {\\n    zone upstream_cmp-test123.carizon.work 64k;\\n    server 10.21.123.12:443\\n    sticky cookie srv_id expires=1h path=/;\\n}`
        }
      ],
      multifile: [
        {
          filename: 'nginx.conf',
          content: `events {\\n    worker_connections 1024;\\n}\\n\\nhttp {\\n    include mime.types;\\n    include conf.d/*.conf;\\n}`
        },
        {
          filename: 'conf.d/upstream.conf',
          content: `upstream carizon_backend {\\n    zone carizon_backend 64k;\\n    server 10.21.123.12:443 weight=5 fail_timeout=1m30s\\n    keepalive 32;\\n}`
        },
        {
          filename: 'conf.d/server.conf',
          content: `server {\\n    listen 443 ssl;\\n    http2 on;\\n    server_name cmp.carizon.work;\\n    ssl_certificate /etc/nginx/ssl/prod_carizon.crt;\\n    ssl_certificate_key /etc/nginx/ssl/prod_carizon.key;\\n    location / {\\n        proxy_pass https://carizon_backend;\\n    }\\n}`
        }
      ],
      ssl_mock: [
        {
          filename: 'conf.d/ssl_app.conf',
          content: `server {\\n    listen 443 ssl;\\n    http2 on;\\n    server_name gateway.carizon.work;\\n    ssl_certificate /etc/nginx/ssl/missing_cert.pem;\\n    ssl_certificate_key /etc/nginx/ssl/missing_key.key;\\n    access_log /var/log/nginx/gateway/access.log;\\n    status_zone gw_zone;\\n\\n    location / {\\n        proxy_pass https://unlisted_external_pool;\\n        health_check interval=5s fails=3 passes=2;\\n    }\\n}`
        }
      ],
      valid: [
        {
          filename: 'nginx.conf',
          content: `upstream upstream_cmp-test123.carizon.work {\\n    zone upstream_cmp-test123.carizon.work 64k;\\n    server 10.21.123.12:443 weight=5 max_fails=3 fail_timeout=1m30s;\\n    sticky cookie srv_id expires=1h path=/;\\n}\\n\\nserver {\\n    listen 443 ssl;\\n    http2 on;\\n    server_name cmp-test123.carizon.work;\\n    ssl_certificate /etc/nginx/ssl/cmp.crt;\\n    ssl_certificate_key /etc/nginx/ssl/cmp.key;\\n\\n    location / {\\n        proxy_pass https://upstream_cmp-test123.carizon.work;\\n        status_zone cmp_backend_zone;\\n    }\\n}`
        }
      ]
    };

    let filesState = JSON.parse(JSON.stringify(PRESETS.bug));
    let activeFileIdx = 0;
    let lastCheckData = null;
    let errorLinesMap = new Map();
    let warnLinesMap = new Map();

    function escapeHtml(str) {
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function renderFileTabs() {
      const bar = document.getElementById('fileTabsBar');
      bar.innerHTML = filesState.map((f, idx) => {
        const activeCls = idx === activeFileIdx ? 'active' : '';
        const delBtn = filesState.length > 1
          ? `<span class="del-file" onclick="deleteFileTab(event, ${idx})" title="删除文件">×</span>`
          : '';
        return `<div class="file-tab ${activeCls}" onclick="selectFileTab(${idx})">📄 ${escapeHtml(f.filename)} ${delBtn}</div>`;
      }).join('');
    }

    function selectFileTab(idx) {
      filesState[activeFileIdx].content = document.getElementById('configInput').value;
      activeFileIdx = idx;
      document.getElementById('configInput').value = filesState[activeFileIdx].content;
      renderFileTabs();
      updateCurrentFileMarkers();
      renderGutterAndHighlights();
    }

    function addNewFileTab() {
      filesState[activeFileIdx].content = document.getElementById('configInput').value;
      const name = prompt('请输入新配置文件的相对路径（例如 conf.d/app.conf）：', `conf.d/sub_${filesState.length}.conf`);
      if (!name || !name.trim()) return;
      filesState.push({
        filename: name.trim(),
        content: `server {\\n    listen 80;\\n    server_name example.com;\\n}`
      });
      activeFileIdx = filesState.length - 1;
      document.getElementById('configInput').value = filesState[activeFileIdx].content;
      renderFileTabs();
      runCheck();
    }

    function deleteFileTab(ev, idx) {
      ev.stopPropagation();
      if (filesState.length <= 1) return;
      filesState.splice(idx, 1);
      if (activeFileIdx >= filesState.length) activeFileIdx = filesState.length - 1;
      document.getElementById('configInput').value = filesState[activeFileIdx].content;
      renderFileTabs();
      runCheck();
    }

    function syncScroll() {
      const ta = document.getElementById('configInput');
      document.getElementById('lineGutter').scrollTop = ta.scrollTop;
      document.getElementById('hlBackdrop').scrollTop = ta.scrollTop;
    }

    function updateCurrentFileMarkers() {
      errorLinesMap.clear();
      warnLinesMap.clear();
      if (!lastCheckData) return;
      const curFile = filesState[activeFileIdx].filename;
      (lastCheckData.errors || []).forEach(e => {
        if ((!e.file || e.file === curFile) && e.line) errorLinesMap.set(e.line, e);
      });
      (lastCheckData.warnings || []).forEach(w => {
        if ((!w.file || w.file === curFile) && w.line) warnLinesMap.set(w.line, w);
      });
    }

    function renderGutterAndHighlights() {
      const text = document.getElementById('configInput').value;
      const lines = text.split('\\n');
      document.getElementById('editorStats').textContent = `${filesState.length} 个文件 | 当前 ${lines.length} 行`;

      let gutterHtml = '';
      let hlHtml = '';

      for (let i = 1; i <= lines.length; i++) {
        const isErr = errorLinesMap.has(i);
        const isWarn = !isErr && warnLinesMap.has(i);
        const cls = isErr ? 'err' : (isWarn ? 'warn' : '');
        const marker = isErr ? '●' : (isWarn ? '▲' : '');
        gutterHtml += `<div class="gutter-line ${cls}"><span>${marker}</span><span>${i}</span></div>`;
        hlHtml += `<div class="hl-row ${cls}"></div>`;
      }

      document.getElementById('lineGutter').innerHTML = gutterHtml;
      document.getElementById('hlBackdrop').innerHTML = hlHtml;
      syncScroll();
    }

    let editorCheckTimer = null;

    function onEditorInput() {
      filesState[activeFileIdx].content = document.getElementById('configInput').value;
      renderGutterAndHighlights();
      if (editorCheckTimer) clearTimeout(editorCheckTimer);
      editorCheckTimer = setTimeout(() => {
        runCheck();
      }, 300);
    }

    function loadPreset(name, btnEl) {
      document.querySelectorAll('.preset-btn').forEach(b => b.classList.remove('active'));
      if (btnEl) btnEl.classList.add('active');
      filesState = JSON.parse(JSON.stringify(PRESETS[name]));
      activeFileIdx = 0;
      document.getElementById('configInput').value = filesState[0].content;
      renderFileTabs();
      runCheck();
    }

    function switchTab(tabId, btnEl) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
      btnEl.classList.add('active');
      document.getElementById('tab-' + tabId).classList.add('active');
    }

    function jumpToFileLine(fileName, lineNo) {
      const targetIdx = filesState.findIndex(f => f.filename === fileName);
      if (targetIdx !== -1 && targetIdx !== activeFileIdx) {
        selectFileTab(targetIdx);
      }
      const ta = document.getElementById('configInput');
      const lines = ta.value.split('\\n');
      let pos = 0;
      for (let i = 0; i < Math.min(lineNo - 1, lines.length); i++) {
        pos += lines[i].length + 1;
      }
      const lineLen = (lines[lineNo - 1] || '').length;
      ta.focus();
      ta.setSelectionRange(pos, pos + lineLen);
    }

    function autoFixMissingSemicolon(fileName, lineNo) {
      const targetIdx = filesState.findIndex(f => f.filename === fileName);
      if (targetIdx !== -1 && targetIdx !== activeFileIdx) {
        selectFileTab(targetIdx);
      }
      const ta = document.getElementById('configInput');
      const lines = ta.value.split('\\n');
      if (lineNo >= 1 && lineNo <= lines.length) {
        let cleaned = lines[lineNo - 1].replace(/\\s+$/, '');
        cleaned = cleaned.replace(/[；;）)（(]+$/, '').replace(/\\s+$/, '');
        lines[lineNo - 1] = cleaned + ';';
        ta.value = lines.join('\\n');
        filesState[activeFileIdx].content = ta.value;
        runCheck();
      }
    }

    function renderAstTree(nodes) {
      if (!nodes || !nodes.length) return '<div style="color:var(--text-muted);font-size:13px;">暂无 AST 节点</div>';
      return nodes.map(n => {
        const args = (n.args || []).map(a => `<span class="ast-arg">${escapeHtml(a)}</span>`).join(' ');
        const children = n.block ? renderAstTree(n.block) : '';
        return `<div class="ast-node">
          <span class="ast-dir">${escapeHtml(n.directive)}</span> ${args} <span class="ast-ln">(line ${n.line})</span>
          ${children}
        </div>`;
      }).join('');
    }

    async function runCheck() {
      filesState[activeFileIdx].content = document.getElementById('configInput').value;
      const context = document.getElementById('ctxSelect').value;
      const strict = document.getElementById('strictCheck').checked;
      const check_runtime = document.getElementById('runtimeCheck').checked;
      const mock_externals = document.getElementById('mockExternals').checked;

      const reqBody = filesState.length === 1
        ? {
            config: filesState[0].content,
            filename: filesState[0].filename,
            context,
            strict,
            check_runtime,
            mock_externals
          }
        : {
            filename: filesState[0].filename,
            files: filesState,
            context,
            strict,
            check_runtime,
            mock_externals
          };

      const [checkResp, lexResp] = await Promise.all([
        fetch('/api/v1/check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(reqBody)
        }),
        fetch('/api/v1/lex', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            config: filesState[activeFileIdx].content,
            filename: filesState[activeFileIdx].filename
          })
        })
      ]);

      const data = await checkResp.json();
      const lexData = await lexResp.json();
      lastCheckData = data;

      updateCurrentFileMarkers();
      renderGutterAndHighlights();

      // KPIs
      const kpiStatus = document.getElementById('kpiStatus');
      if (data.valid) {
        kpiStatus.textContent = '✅ PASSED';
        kpiStatus.className = 'kpi-val ok';
      } else {
        kpiStatus.textContent = '❌ FAILED';
        kpiStatus.className = 'kpi-val fail';
      }
      document.getElementById('kpiErrors').textContent = data.error_count;
      document.getElementById('kpiContext').textContent = data.detected_context;
      document.getElementById('badgeDiagCount').textContent = data.error_count + data.warning_count;

      const kpiRuntime = document.getElementById('kpiRuntime');
      if (data.runtime_check) {
        if (!data.runtime_check.available) {
          kpiRuntime.textContent = 'N/A (无二进制)';
          kpiRuntime.className = 'kpi-val warn';
        } else if (data.runtime_check.passed) {
          kpiRuntime.textContent = '✅ PASS';
          kpiRuntime.className = 'kpi-val ok';
        } else {
          kpiRuntime.textContent = '❌ FAIL';
          kpiRuntime.className = 'kpi-val fail';
        }
      } else {
        kpiRuntime.textContent = '未开启';
        kpiRuntime.className = 'kpi-val ctx';
      }

      // Render Diagnostics Tab
      const diagContainer = document.getElementById('diagContainer');
      let html = '';

      if (data.runtime_check) {
        const rt = data.runtime_check;
        const badgeColor = rt.passed ? '#34d399' : (rt.available ? '#f87171' : '#fbbf24');
        const mockedList = (rt.mocked_items || []).map(m => `<li>${escapeHtml(m)}</li>`).join('');
        html += `
          <div class="runtime-box">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
              <strong style="font-size:13px;color:${badgeColor};">🛠️ 真实二进制 <code>nginx -t</code> 沙盒验证：${rt.passed ? '通过 (Syntax is ok & test is successful)' : (rt.available ? '未通过' : '当前宿主未安装 nginx')}</strong>
            </div>
            ${rt.output ? `<pre class="code-box" style="padding:8px 10px;font-size:12px;margin-bottom:6px;">${escapeHtml(rt.output)}</pre>` : ''}
            ${mockedList ? `<div style="font-size:12px;color:var(--text-secondary);"><strong>自动 Mock 的外部依赖 (${rt.mocked_items.length} 项)：</strong><ul style="margin:4px 0 0 18px;padding:0;">${mockedList}</ul></div>` : ''}
          </div>`;
      }

      if (data.error_count === 0 && data.warning_count === 0) {
        html += `
          <div class="empty-pass">
            <div style="font-size:34px;">🎉</div>
            <h3>语法、参数与跨文件校验全部通过</h3>
            <p>未发现漏写分号、上下文错误或非法的 Upstream Server 参数。</p>
          </div>`;
      } else {
        (data.errors || []).forEach(err => {
          const fObj = filesState.find(f => f.filename === err.file) || filesState[activeFileIdx];
          const fLines = fObj ? fObj.content.split('\\n') : [];
          const codeLine = err.line && fLines[err.line - 1] !== undefined ? fLines[err.line - 1] : '';
          const canAutoFix = ['missing_semicolon', 'upstream_server_address', 'invalid_character'].includes(err.rule) && err.line;
          const fixLabel = err.rule === 'missing_semicolon' ? '🔧 一键补全分号' : '🔧 一键清理并修复';
          html += `
            <div class="diag-card">
              <div class="diag-header">
                <div class="diag-badges">
                  <span class="badge-sev err">ERROR</span>
                  <span class="badge-line" onclick="jumpToFileLine('${escapeHtml(err.file || fObj.filename)}', ${err.line || 1})">${escapeHtml(err.file || 'nginx.conf')}:${err.line ?? '?'} ↗</span>
                  <span class="badge-rule">${escapeHtml(err.rule || 'syntax')}</span>
                </div>
              </div>
              <div class="diag-msg">${escapeHtml(err.message)}</div>
              ${codeLine ? `<div class="code-preview"><span class="code-preview-ln">${err.line} |</span><span>${escapeHtml(codeLine)}</span></div>` : ''}
              ${err.suggestion ? `
                <div class="diag-Suggest">
                  <span>💡 <strong>修复建议：</strong>${escapeHtml(err.suggestion)}</span>
                  ${canAutoFix ? `<button class="btn-autofix" onclick="autoFixMissingSemicolon('${escapeHtml(err.file || fObj.filename)}', ${err.line})">${fixLabel}</button>` : ''}
                </div>` : ''}
            </div>`;
        });

        (data.warnings || []).forEach(w => {
          html += `
            <div class="diag-card warning">
              <div class="diag-header">
                <div class="diag-badges">
                  <span class="badge-sev warn">WARNING</span>
                  <span class="badge-line" onclick="jumpToFileLine('${escapeHtml(w.file || 'nginx.conf')}', ${w.line || 1})">${escapeHtml(w.file || 'nginx.conf')}:${w.line ?? '?'} ↗</span>
                  <span class="badge-rule">${escapeHtml(w.rule || 'warning')}</span>
                </div>
              </div>
              <div class="diag-msg">${escapeHtml(w.message)}</div>
              ${w.suggestion ? `<div class="diag-Suggest"><span>💡 <strong>优化建议：</strong>${escapeHtml(w.suggestion)}</span></div>` : ''}
            </div>`;
        });
      }
      diagContainer.innerHTML = html;

      // Render AST Tab
      const allConfigs = data.config || [];
      document.getElementById('astTreeContainer').innerHTML = allConfigs.map(c => `
        <div style="margin-bottom:10px;">
          <div style="font-size:12.5px;font-weight:700;color:var(--blue);margin-bottom:4px;">📄 ${escapeHtml(c.file)} (${c.status})</div>
          ${renderAstTree(c.parsed)}
        </div>
      `).join('');
      document.getElementById('jsonOutput').textContent = JSON.stringify(data, null, 2);

      // Render Tokens Tab
      const tokens = lexData.tokens || [];
      document.getElementById('badgeTokenCount').textContent = tokens.length;
      const byLine = {};
      tokens.forEach(t => {
        if (!byLine[t.line]) byLine[t.line] = [];
        byLine[t.line].push(t);
      });
      let tokHtml = '';
      Object.keys(byLine).forEach(ln => {
        const chips = byLine[ln].map(t => {
          const isDelim = !t.quoted && (t.token === ';' || t.token === '{' || t.token === '}');
          const cls = isDelim ? 'delim' : (t.quoted ? 'quoted' : '');
          return `<span class="tok-chip ${cls}">${escapeHtml(t.token)}</span>`;
        }).join('');
        tokHtml += `<div class="token-row"><span class="token-ln">Line ${ln}</span>${chips}</div>`;
      });
      document.getElementById('tokenContainer').innerHTML = tokHtml || '<div style="color:var(--text-muted)">无 Token</div>';

      // Render API Tab
      const payloadStr = JSON.stringify(reqBody, null, 2);
      document.getElementById('curlSnippet').textContent =
        `curl -s -X POST http://localhost:8090/api/v1/check \\\\\\n  -H "Content-Type: application/json" \\\\\\n  -d '${payloadStr.replace(/'/g, "'\\\\\\\\''")}' | jq .`;
    }

    async function formatConfig() {
      const curText = document.getElementById('configInput').value;
      const resp = await fetch('/api/v1/format', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          config: curText,
          filename: filesState[activeFileIdx].filename,
          indent: 4
        })
      });
      const res = await resp.json();
      if (res.formatted) {
        document.getElementById('configInput').value = res.formatted;
        filesState[activeFileIdx].content = res.formatted;
        runCheck();
      }
    }

    function handleFileUpload(e) {
      const file = e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = ev => {
        filesState[activeFileIdx].filename = file.name;
        filesState[activeFileIdx].content = ev.target.result;
        document.getElementById('configInput').value = ev.target.result;
        renderFileTabs();
        runCheck();
      };
      reader.readAsText(file);
    }

    function copyConfig() {
      copyText(document.getElementById('configInput').value);
    }

    function copyText(text) {
      navigator.clipboard.writeText(text);
    }

    document.addEventListener('keydown', e => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
        e.preventDefault();
        runCheck();
      }
    });

    window.addEventListener('DOMContentLoaded', () => {
      document.getElementById('configInput').value = filesState[0].content;
      renderFileTabs();
      runCheck();
    });
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index_page() -> str:
    return INDEX_HTML
