# -*- coding: utf-8 -*-
"""
Enhanced NGINX Crossplane Configuration Analyzer & Validator.

Combines official `crossplane` lexical/AST parsing with:
1. NGINX / NGINX Plus R37 directive definitions (http2, sticky, zone, etc.)
2. Token-level line tracking to detect missing semicolons (;) that swallow
   subsequent directives across lines (fixing the crossplane / nginx-go-crossplane
   false-negative defect).
3. Strict parameter validation for `upstream` `server` directives (matching
   NGINX's `ngx_http_upstream_server` and `ngx_stream_upstream_server`).
4. Smart snippet context auto-detection (so `conf.d/*.conf` fragments like
   `upstream {}` or `server {}` can be checked directly without manual `http {}` wrapping).
5. Optional `nginx -t` runtime verification inside the container.
"""

import os
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

import crossplane
from crossplane.analyzer import (
    DIRECTIVES,
    NGX_ANY_CONF,
    NGX_CONF_1MORE,
    NGX_CONF_2MORE,
    NGX_CONF_ANY,
    NGX_CONF_BLOCK,
    NGX_CONF_FLAG,
    NGX_CONF_NOARGS,
    NGX_CONF_TAKE1,
    NGX_CONF_TAKE2,
    NGX_CONF_TAKE3,
    NGX_CONF_TAKE12,
    NGX_CONF_TAKE13,
    NGX_CONF_TAKE23,
    NGX_CONF_TAKE123,
    NGX_EVENT_CONF,
    NGX_HTTP_LIF_CONF,
    NGX_HTTP_LMT_CONF,
    NGX_HTTP_LOC_CONF,
    NGX_HTTP_MAIN_CONF,
    NGX_HTTP_SIF_CONF,
    NGX_HTTP_SRV_CONF,
    NGX_HTTP_UPS_CONF,
    NGX_MAIN_CONF,
    NGX_STREAM_MAIN_CONF,
    NGX_STREAM_SRV_CONF,
    NGX_STREAM_UPS_CONF,
    analyze as crossplane_analyze,
    enter_block_ctx,
)
from crossplane.errors import NgxParserBaseException, NgxParserDirectiveError
from crossplane.lexer import _iterescape, _iterlinecount, EXTERNAL_LEXERS


# ---------------------------------------------------------------------------
# 1. Patch crossplane's DIRECTIVES table with modern NGINX / NGINX Plus (R37)
#    directives that may be missing in crossplane 0.5.8
# ---------------------------------------------------------------------------
MODERN_DIRECTIVES_PATCH = {
    "http2": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
    ],
    "http3": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
    ],
    "http3_hq": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
    ],
    "quic_retry": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
    ],
    "quic_gso": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
    ],
    "js_import": [
        NGX_HTTP_MAIN_CONF | NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE13,
    ],
    "js_preload_object": [
        NGX_HTTP_MAIN_CONF | NGX_STREAM_MAIN_CONF | NGX_CONF_TAKE13,
    ],
    "js_body_filter": [
        NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE12,
    ],
    "js_header_filter": [
        NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
    ],
    "js_periodic": [
        NGX_HTTP_LOC_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_1MORE,
    ],
    "status_zone": [
        NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_SIF_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE12,
        NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
    ],
    "resolver": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_UPS_CONF | NGX_CONF_1MORE,
        NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_STREAM_UPS_CONF | NGX_CONF_1MORE,
    ],
    "resolver_timeout": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
        NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_STREAM_UPS_CONF | NGX_CONF_TAKE1,
    ],
    "ntlm": [
        NGX_HTTP_UPS_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE1,
    ],
    "random": [
        NGX_HTTP_UPS_CONF | NGX_STREAM_UPS_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE12,
    ],
    "keepalive_time": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
    ],
    "keepalive_timeout": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
        NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
    ],
    "keepalive_requests": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1,
    ],
}

for _k, _v in MODERN_DIRECTIVES_PATCH.items():
    if _k not in DIRECTIVES:
        DIRECTIVES[_k] = _v
    else:
        for _mask in _v:
            if _mask not in DIRECTIVES[_k]:
                DIRECTIVES[_k].append(_mask)


# ---------------------------------------------------------------------------
# 2. Valid parameters for `server` inside `upstream` (HTTP & Stream)
#    Matches NGINX / NGINX Plus `ngx_http_upstream_server` specification
# ---------------------------------------------------------------------------
UPSTREAM_SERVER_FLAGS = {
    "backup",
    "down",
    "resolve",
    "drain",
}

UPSTREAM_SERVER_KV_PATTERNS = {
    "weight": re.compile(r"^[1-9]\d*$"),
    "max_conns": re.compile(r"^\d+$"),
    "max_fails": re.compile(r"^\d+$"),
    "fail_timeout": re.compile(r"^\d+(ms|s|m|h|d|w|M|y)?$"),
    "slow_start": re.compile(r"^\d+(ms|s|m|h|d|w|M|y)?$"),
    "route": re.compile(r"^.+"),
    "service": re.compile(r"^.+"),
    "sid": re.compile(r"^.+"),
}

# Common directives valid inside an `upstream` block (used to provide precise
# "missing semicolon on previous line swallowed directive X" diagnostics)
UPSTREAM_DIRECTIVES = {
    "server",
    "zone",
    "state",
    "hash",
    "ip_hash",
    "keepalive",
    "keepalive_requests",
    "keepalive_time",
    "keepalive_timeout",
    "ntlm",
    "least_conn",
    "least_time",
    "Random",
    "random",
    "queue",
    "sticky",
    "sticky_cookie_insert",
    "resolver",
    "resolver_timeout",
}

# Top-level directives that typically appear in conf.d/*.conf (HTTP context)
HTTP_CONTEXT_ROOT_DIRECTIVES = {
    "upstream",
    "server",
    "map",
    "geo",
    "split_clients",
    "limit_req_zone",
    "limit_conn_zone",
    "proxy_cache_path",
    "fastcgi_cache_path",
    "scgi_cache_path",
    "uwsgi_cache_path",
    "log_format",
    "subrequest_output_buffer_size",
    "js_import",
}

SERVER_CONTEXT_ROOT_DIRECTIVES = {
    "location",
    "listen",
    "server_name",
    "rewrite",
    "return",
    "proxy_pass",
    "Fastcgi_pass",
    "fastcgi_pass",
    "try_files",
    "error_page",
}


def validate_upstream_server_arg(arg: str) -> Optional[str]:
    """
    Validates a single parameter (after `address`) of an `upstream { server ... }` directive.
    Returns None if valid, or an error description if invalid.
    """
    if arg in UPSTREAM_SERVER_FLAGS:
        return None
    if "=" in arg:
        key, val = arg.split("=", 1)
        if key in UPSTREAM_SERVER_KV_PATTERNS:
            if not UPSTREAM_SERVER_KV_PATTERNS[key].match(val):
                return f'invalid value "{val}" for parameter "{key}" in upstream "server" directive'
            return None
        return f'invalid parameter "{arg}" in upstream "server" directive'
    return f'invalid parameter "{arg}" in upstream "server" directive'


# ---------------------------------------------------------------------------
# 3. Token-level Lexer with exact per-argument line tracking
#    Also fixes crossplane Issue #114 (unterminated final token at EOF)
# ---------------------------------------------------------------------------
def lex_string_with_lines(content: str, filename: str = "nginx.conf") -> Tuple[List[Tuple[str, int, bool]], List[Dict[str, Any]]]:
    """
    Tokenizes an NGINX configuration string into `(token, lineno, quoted)` tuples.
    Properly flushes any trailing token at EOF (fixing crossplane Issue #114).
    """
    tokens: List[Tuple[str, int, bool]] = []
    errors: List[Dict[str, Any]] = []

    # Ensure trailing newline so _lex_file_object doesn't drop the last token at EOF
    padded_content = content if content.endswith("\n") else content + "\n"
    lines = padded_content.splitlines(keepends=True)

    try:
        it = iter(lines)
        for tok, line, quoted in crossplane.lexer._lex_file_object(it):
            tokens.append((tok, line, quoted))
    except NgxParserBaseException as e:
        lineno = getattr(e, "lineno", None)
        strerror = getattr(e, "strerror", str(e))
        errors.append({
            "file": filename,
            "line": lineno,
            "error": f"{strerror} in {filename}:{lineno}" if lineno else f"{strerror} in {filename}",
            "type": "syntax_error",
            "rule": "lexer",
        })
    except Exception as e:
        errors.append({
            "file": filename,
            "line": None,
            "error": str(e),
            "type": "syntax_error",
            "rule": "lexer",
        })

    return tokens, errors


def detect_initial_context(tokens: List[Tuple[str, int, bool]], requested_context: str = "auto") -> Tuple[str, ...]:
    """
    Determines the starting NGINX context tuple for analysis:
    - `main` -> `()`
    - `http` -> `('http',)`
    - `stream` -> `('stream',)`
    - `server` -> `('http', 'server')`
    - `upstream` -> `('http', 'upstream')`
    - `auto` -> inspects the first non-comment directive token.
    """
    if requested_context == "main":
        return ()
    if requested_context == "http":
        return ("http",)
    if requested_context == "stream":
        return ("stream",)
    if requested_context == "server":
        return ("http", "server")
    if requested_context == "upstream":
        return ("http", "upstream")
    if requested_context == "location":
        return ("http", "server", "location")

    # Auto-detect based on first meaningful token
    for tok, _, quoted in tokens:
        if not quoted and tok.startswith("#"):
            continue
        if tok in ("events", "http", "stream", "mail", "user", "worker_processes", "pid", "load_module", "pcre_jit"):
            return ()
        if tok in HTTP_CONTEXT_ROOT_DIRECTIVES:
            return ("http",)
        if tok in SERVER_CONTEXT_ROOT_DIRECTIVES:
            return ("http", "server")
        if tok in UPSTREAM_DIRECTIVES and tok != "server":
            return ("http", "upstream")
        break
    return ()


# ---------------------------------------------------------------------------
# 4. AST Parser + Deep Semantic / Missing-Semicolon Analyzer
# ---------------------------------------------------------------------------
def parse_and_analyze_tokens(
    tokens: List[Tuple[str, int, bool]],
    filename: str = "nginx.conf",
    initial_ctx: Tuple[str, ...] = (),
    strict: bool = True,
    comments: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parses token stream into AST statements while recording exact `(arg, arg_line, arg_quoted)`
    for every argument, enabling:
    - Exact crossplane context & argument count checks
    - Upstream `server` parameter validation
    - Multi-line missing-semicolon (`;`) detection when a directive swallows the next line's directive
    """
    errors: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []

    token_iter = iter(tokens)

    def _add_error(line: Optional[int], msg: str, rule: str = "syntax", suggestion: Optional[str] = None):
        err: Dict[str, Any] = {
            "file": filename,
            "line": line,
            "error": f"{msg} in {filename}:{line}" if line else f"{msg} in {filename}",
            "message": msg,
            "rule": rule,
        }
        if suggestion:
            err["suggestion"] = suggestion
        errors.append(err)

    def _add_warning(line: Optional[int], msg: str, rule: str = "warning", suggestion: Optional[str] = None):
        warn: Dict[str, Any] = {
            "file": filename,
            "line": line,
            "warning": f"{msg} in {filename}:{line}" if line else f"{msg} in {filename}",
            "message": msg,
            "rule": rule,
        }
        if suggestion:
            warn["suggestion"] = suggestion
        warnings.append(warn)

    def _check_directive_semantics(stmt: Dict[str, Any], arg_meta: List[Tuple[str, int, bool]], ctx: Tuple[str, ...], is_block: bool):
        directive = stmt["directive"]
        line = stmt["line"]
        args = stmt["args"]

        # 1. Run standard crossplane analyze() (context + argument count bitmasks)
        try:
            crossplane_analyze(
                fname=filename,
                stmt=stmt,
                term="{" if is_block else ";",
                ctx=ctx,
                strict=strict,
                check_ctx=True,
                check_args=True,
            )
        except NgxParserDirectiveError as e:
            _add_error(e.lineno, e.strerror, rule="crossplane_directive")

        # 2. Check for multi-line missing semicolon swallowing another directive!
        #    When a directive has arguments spanning multiple lines, check if any argument
        #    on a subsequent line looks like a directive that got swallowed due to a missing `;`.
        if arg_meta:
            prev_line = line
            for idx, (arg_val, arg_line, arg_quoted) in enumerate(arg_meta):
                if arg_line > prev_line and not arg_quoted:
                    # Did this new line start with a known directive in the current context?
                    if ctx in (("http", "upstream"), ("stream", "upstream")) and directive == "server":
                        if arg_val in UPSTREAM_DIRECTIVES or arg_val in DIRECTIVES:
                            _add_error(
                                prev_line,
                                f'directive "{directive}" is not terminated by ";" (swallowed "{arg_val}" directive on line {arg_line})',
                                rule="missing_semicolon",
                                suggestion=f'Add a semicolon ";" at the end of line {prev_line} before "{arg_val}".',
                            )
                            break
                    elif arg_val in DIRECTIVES and directive != "types":
                        # Check if arg_val is valid in current ctx as a standalone directive
                        # and there are more arguments on `arg_line`
                        same_line_tokens = [a for a, l, _ in arg_meta[idx:] if l == arg_line]
                        if len(same_line_tokens) >= 2:
                            _add_error(
                                prev_line,
                                f'directive "{directive}" on line {line} appears to be missing a terminating ";" on line {prev_line} (swallowed "{arg_val}" on line {arg_line})',
                                rule="missing_semicolon",
                                suggestion=f'Add a semicolon ";" at the end of line {prev_line}.',
                            )
                            break
                prev_line = arg_line

        # 3. Validate `upstream` -> `server` parameters (exact NGINX runtime parity)
        if ctx in (("http", "upstream"), ("stream", "upstream")) and directive == "server" and not is_block:
            if len(arg_meta) >= 2:
                # First arg is the server address (e.g. 10.21.123.12:443 or unix:/tmp/backend.sock)
                for param_val, param_line, _ in arg_meta[1:]:
                    err_msg = validate_upstream_server_arg(param_val)
                    if err_msg:
                        hint = None
                        if param_line > line:
                            hint = (
                                f'Line {line} ("server {arg_meta[0][0]}") is likely missing a trailing semicolon ";", '
                                f'causing "{param_val}" on line {param_line} to be parsed as a server parameter.'
                            )
                        _add_error(
                            param_line,
                            err_msg,
                            rule="upstream_server_parameter",
                            suggestion=hint or 'Valid upstream server parameters: weight=<n>, max_conns=<n>, max_fails=<n>, fail_timeout=<time>, slow_start=<time>, backup, down, resolve, drain, route=<s>, service=<s>.',
                        )
                        if param_line > line:
                            # Do not spam remaining tokens of the swallowed directive on the next line
                            break

        # 4. Check deprecated `listen ... http2` (NGINX 1.25.1+ deprecation warning, matching NIM logs)
        if ctx == ("http", "server") and directive == "listen" and "http2" in args:
            _add_warning(
                line,
                'the "listen ... http2" directive is deprecated, use the standalone "http2 on;" directive instead',
                rule="deprecated_directive",
                suggestion='Remove "http2" from "listen" and add "http2 on;" inside the server block.',
            )

    def _parse_block(ctx: Tuple[str, ...], is_top_level: bool = False) -> List[Dict[str, Any]]:
        parsed: List[Dict[str, Any]] = []

        for token, lineno, quoted in token_iter:
            # Handle comments
            if token.startswith("#") and not quoted:
                if comments:
                    parsed.append({
                        "directive": "#",
                        "line": lineno,
                        "args": [],
                        "comment": token[1:],
                    })
                continue

            # Unexpected closing brace at top-level or end of current block
            if token == "}" and not quoted:
                if is_top_level:
                    _add_error(lineno, 'unexpected "}"', rule="syntax")
                    continue
                return parsed

            # Stray semicolon or opening brace where a directive name is expected
            if token in (";", "{") and not quoted:
                _add_error(lineno, f'unexpected "{token}"', rule="syntax")
                continue

            # Start reading a directive statement
            stmt: Dict[str, Any] = {
                "directive": token,
                "line": lineno,
                "args": [],
            }
            arg_meta: List[Tuple[str, int, bool]] = []

            # Handle special `if (...)` condition parenthesized arguments
            terminated = False
            terminator = None

            for arg_tok, arg_line, arg_quoted in token_iter:
                if not arg_quoted and arg_tok.startswith("#"):
                    if comments:
                        # Attach inline comment or continue scanning args
                        pass
                    continue

                if not arg_quoted and arg_tok in (";", "{"):
                    terminated = True
                    terminator = arg_tok
                    break

                if not arg_quoted and arg_tok == "}":
                    # Directive inside a block was not terminated by `;` before `}`!
                    last_line = arg_meta[-1][1] if arg_meta else lineno
                    _add_error(
                        last_line,
                        f'directive "{stmt["directive"]}" is not terminated by ";"',
                        rule="missing_semicolon",
                        suggestion=f'Add ";" at the end of the "{stmt["directive"]}" directive on line {last_line}.',
                    )
                    # Analyze what we have as a semicolon-terminated statement, then close block
                    if stmt["directive"] == "if":
                        crossplane.parser._prepare_if_args(stmt)
                    _check_directive_semantics(stmt, arg_meta, ctx, is_block=False)
                    parsed.append(stmt)
                    if is_top_level:
                        _add_error(arg_line, 'unexpected "}"', rule="syntax")
                    else:
                        return parsed
                    terminated = True
                    terminator = "}"
                    break

                stmt["args"].append(arg_tok)
                arg_meta.append((arg_tok, arg_line, arg_quoted))

            if not terminated:
                # Reached EOF without `;` or `{`! (Fixes crossplane Issue #114)
                last_line = arg_meta[-1][1] if arg_meta else lineno
                _add_error(
                    last_line,
                    f'unexpected end of file, expecting ";" or "}}" to terminate "{stmt["directive"]}" directive',
                    rule="missing_semicolon",
                    suggestion=f'Add ";" at the end of line {last_line}.',
                )
                parsed.append(stmt)
                break

            if terminator == "}":
                continue

            if stmt["directive"] == "if":
                crossplane.parser._prepare_if_args(stmt)

            is_block = terminator == "{"
            _check_directive_semantics(stmt, arg_meta, ctx, is_block=is_block)

            if is_block:
                inner_ctx = enter_block_ctx(stmt, ctx)
                stmt["block"] = _parse_block(inner_ctx, is_top_level=False)

            parsed.append(stmt)

        # If we were inside a block (`not is_top_level`) and reached EOF without `}`
        if not is_top_level:
            last_line = tokens[-1][1] if tokens else 1
            _add_error(
                last_line,
                'unexpected end of file, expecting "}"',
                rule="unclosed_block",
                suggestion='Add a closing brace "}" to close the open block.',
            )

        return parsed

    parsed_ast = _parse_block(initial_ctx, is_top_level=True)
    return parsed_ast, errors, warnings


# ---------------------------------------------------------------------------
# 5. Optional Runtime Verification via `nginx -t`
# ---------------------------------------------------------------------------
def run_nginx_runtime_test(content: str, detected_ctx: Tuple[str, ...]) -> Dict[str, Any]:
    """
    Runs the real `nginx -t` binary against the configuration (wrapping snippets in
    a minimal valid `events {}` / `http {}` skeleton when needed).
    """
    nginx_bin = shutil.which("nginx")
    if not nginx_bin:
        return {
            "available": False,
            "passed": None,
            "output": "nginx binary not installed in current environment",
        }

    with tempfile.TemporaryDirectory(prefix="ngx_check_") as tmpdir:
        conf_path = os.path.join(tmpdir, "nginx.conf")
        # Wrap snippet according to detected context so snippets like `upstream {...}` can be tested with `nginx -t`
        if detected_ctx == ("http",):
            wrapped = f"events {{ worker_connections 1024; }}\nhttp {{\n{content}\n}}\n"
            line_offset = 2
        elif detected_ctx == ("http", "server"):
            wrapped = f"events {{ worker_connections 1024; }}\nhttp {{\nserver {{\n{content}\n}}\n}}\n"
            line_offset = 3
        elif detected_ctx == ("http", "upstream"):
            wrapped = f"events {{ worker_connections 1024; }}\nhttp {{\nupstream _test_upstream {{\n{content}\n}}\n}}\n"
            line_offset = 3
        elif detected_ctx == ("stream",):
            wrapped = f"events {{ worker_connections 1024; }}\nstream {{\n{content}\n}}\n"
            line_offset = 2
        else:
            # Main context: ensure `events` exists if not present
            if not re.search(r"\bevents\s*\{", content):
                wrapped = f"events {{ worker_connections 1024; }}\n{content}\n"
                line_offset = 1
            else:
                wrapped = content
                line_offset = 0

        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(wrapped)

        proc = subprocess.run(
            [nginx_bin, "-t", "-c", conf_path, "-p", tmpdir, "-g", f"pid {tmpdir}/nginx.pid; error_log stderr;"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        raw_out = (proc.stderr or proc.stdout or "").strip()

        # Adjust line numbers in stderr back to user's snippet line numbers
        adjusted_lines = []
        for line in raw_out.splitlines():
            m = re.search(r"nginx\.conf:(\d+)", line)
            if m and line_offset > 0:
                orig_line = max(1, int(m.group(1)) - line_offset)
                line = line.replace(f"{conf_path}:{m.group(1)}", f"nginx.conf:{orig_line}")
            else:
                line = line.replace(conf_path, "nginx.conf")
            adjusted_lines.append(line)

        return {
            "available": True,
            "passed": proc.returncode == 0,
            "exit_code": proc.returncode,
            "output": "\n".join(adjusted_lines),
        }


# ---------------------------------------------------------------------------
# 6. High-level Check Entrypoint
# ---------------------------------------------------------------------------
def check_nginx_config(
    config_text: str,
    filename: str = "nginx.conf",
    context: str = "auto",
    strict: bool = True,
    comments: bool = False,
    check_runtime: bool = False,
) -> Dict[str, Any]:
    """
    Runs full crossplane + enhanced semantic analysis (and optional `nginx -t`)
    on an NGINX configuration string.
    """
    tokens, lex_errors = lex_string_with_lines(config_text, filename=filename)
    detected_ctx = detect_initial_context(tokens, requested_context=context)

    parsed_ast, parse_errors, warnings = parse_and_analyze_tokens(
        tokens=tokens,
        filename=filename,
        initial_ctx=detected_ctx,
        strict=strict,
        comments=comments,
    )

    all_errors = lex_errors + parse_errors
    status = "ok" if len(all_errors) == 0 else "failed"

    result: Dict[str, Any] = {
        "status": status,
        "valid": len(all_errors) == 0,
        "detected_context": "main" if not detected_ctx else " > ".join(detected_ctx),
        "error_count": len(all_errors),
        "warning_count": len(warnings),
        "errors": all_errors,
        "warnings": warnings,
        "config": [
            {
                "file": filename,
                "status": status,
                "errors": [
                    {"line": e["line"], "error": e["error"], "rule": e.get("rule"), "suggestion": e.get("suggestion")}
                    for e in all_errors
                ],
                "parsed": parsed_ast,
            }
        ],
    }

    if check_runtime:
        runtime_res = run_nginx_runtime_test(config_text, detected_ctx)
        result["runtime_check"] = runtime_res

    return result
