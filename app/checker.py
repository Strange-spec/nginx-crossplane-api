# -*- coding: utf-8 -*-
"""
Enhanced NGINX Crossplane Configuration Analyzer & Validator (v1.2).

Combines official `crossplane` lexical/AST parsing with:
1. NGINX / NGINX Plus R37 directive definitions (http2, sticky, zone, health_check, api, etc.)
2. Token-level line tracking to detect missing semicolons (;) that swallow
   subsequent directives across lines (including 0-arg directives like `internal;` or `ip_hash;`).
3. Strict parameter validation for `upstream` `server` directives (supporting compound
   NGINX durations like `1m30s` and NGINX Plus parameters).
4. Multi-file configuration analysis with recursive `include` resolution (e.g. `conf.d/*.conf`)
   and context propagation.
5. Smart snippet context auto-detection (`upstream {}`, `server {}`, `location {}`).
6. Real `nginx -t` runtime verification in an isolated sandbox with automatic external
   dependency mocking (self-signed SSL certs/keys/dhparams, `mime.types`, log/cache dirs,
   undefined `proxy_pass` upstreams, and NGINX Plus proprietary directive shimming).
"""

import fnmatch
import os
import posixpath
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Set, Tuple

import crossplane
from crossplane.analyzer import (
    CONTEXTS,
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
    NGX_CONF_TAKE1234,
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
    "quic_bpf": [
        NGX_MAIN_CONF | NGX_CONF_FLAG,
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
    "health_check": [
        NGX_HTTP_LOC_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_ANY,
    ],
    "health_check_timeout": [
        NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
    ],
    "match": [
        NGX_HTTP_MAIN_CONF | NGX_STREAM_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_TAKE1,
    ],
    "api": [
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS | NGX_CONF_TAKE12,
    ],
    "sticky": [
        NGX_HTTP_UPS_CONF | NGX_CONF_1MORE,
    ],
    "sticky_cookie_insert": [
        NGX_HTTP_UPS_CONF | NGX_CONF_TAKE1234,
    ],
    "zone": [
        NGX_HTTP_UPS_CONF | NGX_STREAM_UPS_CONF | NGX_CONF_TAKE12,
    ],
    "state": [
        NGX_HTTP_UPS_CONF | NGX_STREAM_UPS_CONF | NGX_CONF_TAKE1,
    ],
    "queue": [
        NGX_HTTP_UPS_CONF | NGX_CONF_TAKE12,
    ],
    "mgmt": [
        NGX_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS,
    ],
    "otel_exporter": [
        NGX_HTTP_MAIN_CONF | NGX_CONF_BLOCK | NGX_CONF_NOARGS,
    ],
    "otel_trace": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ],
    "otel_trace_context": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ],
    "otel_service_name": [
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
    ],
    "otel_span_name": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
    ],
    "otel_span_attr": [
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
    ],
}

for _k, _v in MODERN_DIRECTIVES_PATCH.items():
    if _k not in DIRECTIVES:
        DIRECTIVES[_k] = list(_v)
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

# Supports both single unit (`10s`, `500ms`) and compound NGINX time strings (`1m30s`, `2h15m`)
NGX_DURATION_RE = re.compile(r"^(?:\d+(?:ms|s|m|h|d|w|M|y))+$|^\d+$")

UPSTREAM_SERVER_KV_PATTERNS = {
    "weight": re.compile(r"^[1-9]\d*$"),
    "max_conns": re.compile(r"^\d+$"),
    "max_fails": re.compile(r"^\d+$"),
    "fail_timeout": NGX_DURATION_RE,
    "slow_start": NGX_DURATION_RE,
    "route": re.compile(r"^.+"),
    "service": re.compile(r"^.+"),
    "sid": re.compile(r"^.+"),
}

# Common directives valid inside an `upstream` block
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
    "fastcgi_pass",
    "try_files",
    "error_page",
}


FULLWIDTH_CHARS = {
    "；": ";",
    "：": ":",
    "（": "(",
    "）": ")",
    "｛": "{",
    "｝": "}",
    "，": ",",
    "“": '"',
    "”": '"',
    "‘": "'",
    "’": "'",
}


def find_fullwidth_char(token: str) -> Optional[str]:
    """Returns the first full-width punctuation character found in an unquoted token, if any."""
    for ch in token:
        if ch in FULLWIDTH_CHARS:
            return ch
    return None


def validate_upstream_server_address(addr: str) -> Optional[Tuple[str, str]]:
    """
    Validates the 1st argument (`address`) of `upstream { server <address> [params]; }`.
    Returns `(error_message, suggestion)` if invalid, or `None` if valid.
    """
    fw = find_fullwidth_char(addr)
    if fw:
        ascii_eq = FULLWIDTH_CHARS[fw]
        return (
            f'invalid full-width character "{fw}" in upstream server "{addr}"',
            f'Replace or remove full-width character "{fw}" (ASCII equivalent: "{ascii_eq}") in "{addr}".',
        )

    if addr.startswith("unix:"):
        sock_path = addr[5:]
        if not sock_path or any(c in sock_path for c in ("(", ")", ";", "{", "}")):
            return (
                f'invalid unix domain socket path in upstream "{addr}"',
                'Specify a valid unix socket path, e.g. "unix:/var/run/backend.sock".',
            )
        return None

    # IPv6 address: [ipv6] or [ipv6]:port
    if addr.startswith("["):
        m_v6 = re.match(r"^\[([0-9a-fA-F:.]+)\](?::(.+))?$", addr)
        if not m_v6:
            return (
                f'invalid IPv6 address in upstream "{addr}"',
                'Use valid bracketed IPv6 format, e.g. "[::1]:8080".',
            )
        port_part = m_v6.group(2)
        if port_part is not None and not port_part.startswith("$"):
            if not re.match(r"^\d+$", port_part) or not (1 <= int(port_part) <= 65535):
                return (
                    f'invalid port in upstream "{addr}"',
                    f'Port "{port_part}" is invalid; specify an integer port between 1 and 65535 without extra characters.',
                )
        return None

    # Host / IPv4 with optional :port
    if ":" in addr:
        if addr.count(":") > 1:
            return (
                f'invalid host in upstream "{addr}" (IPv6 addresses must be enclosed in "[...]")',
                'Wrap IPv6 address in brackets, e.g. "[::1]:8080".',
            )
        host, port_part = addr.split(":", 1)
        if not port_part or (
            not port_part.startswith("$")
            and (not re.match(r"^\d+$", port_part) or not (1 <= int(port_part) <= 65535))
        ):
            return (
                f'invalid port in upstream "{addr}"',
                f'Port "{port_part}" in "{addr}" is invalid; specify a clean port number (1-65535) without extra characters like ")" or "）".',
            )
    else:
        host = addr

    if not host:
        return (
            f'invalid empty host in upstream "{addr}"',
            'Specify a valid IP address or hostname before the port.',
        )

    # Pure digits and dots -> must be a valid 4-octet IPv4 address
    if re.match(r"^[\d.]+$", host):
        octets = host.split(".")
        if len(octets) != 4 or any(not o or int(o) > 255 for o in octets):
            return (
                f'invalid IPv4 address "{host}" in upstream "{addr}"',
                f'"{host}" is not a valid IPv4 address (expected 4 octets 0-255).',
            )
        return None

    # Hostname or NGINX variable
    if not re.match(r"^[A-Za-z0-9._$-]+$", host):
        return (
            f'invalid host in upstream "{addr}"',
            f'Host "{host}" contains illegal characters; remove stray symbols such as ")" or "(" from "{addr}".',
        )

    return None


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


def is_directive_valid_in_ctx(directive_name: str, ctx: Tuple[str, ...]) -> bool:
    """
    Checks if `directive_name` is a known NGINX directive valid in `ctx`.
    """
    if directive_name not in DIRECTIVES:
        return False
    ctx_bit = CONTEXTS.get(ctx, 0)
    if not ctx_bit:
        return True
    for mask in DIRECTIVES[directive_name]:
        if mask & ctx_bit:
            return True
    return False


# ---------------------------------------------------------------------------
# 3. Token-level Lexer with exact per-argument line tracking
#    Also fixes crossplane Issue #114 (unterminated final token at EOF)
# ---------------------------------------------------------------------------
def lex_string_with_lines(
    content: str, filename: str = "nginx.conf"
) -> Tuple[List[Tuple[str, int, bool]], List[Dict[str, Any]]]:
    """
    Tokenizes an NGINX configuration string into `(token, lineno, quoted)` tuples.
    Properly flushes any trailing token at EOF (fixing crossplane Issue #114).
    """
    tokens: List[Tuple[str, int, bool]] = []
    errors: List[Dict[str, Any]] = []

    padded_content = content if content.endswith("\n") else content + "\n"
    lines = padded_content.splitlines(keepends=True)

    try:
        it = iter(lines)
        for tok, line, quoted in crossplane.lexer._lex_file_object(it):
            tokens.append((tok, line, quoted))
    except NgxParserBaseException as e:
        lineno = getattr(e, "lineno", None)
        strerror = getattr(e, "strerror", str(e))
        errors.append(
            {
                "file": filename,
                "line": lineno,
                "error": f"{strerror} in {filename}:{lineno}" if lineno else f"{strerror} in {filename}",
                "message": strerror,
                "type": "syntax_error",
                "rule": "lexer",
            }
        )
    except Exception as e:
        errors.append(
            {
                "file": filename,
                "line": None,
                "error": str(e),
                "message": str(e),
                "type": "syntax_error",
                "rule": "lexer",
            }
        )

    return tokens, errors


def detect_initial_context(
    tokens: List[Tuple[str, int, bool]], requested_context: str = "auto"
) -> Tuple[str, ...]:
    """
    Determines the starting NGINX context tuple for analysis:
    - `main` -> `()`
    - `http` -> `('http',)`
    - `stream` -> `('stream',)`
    - `server` -> `('http', 'server')`
    - `upstream` -> `('http', 'upstream')`
    - `location` -> `('http', 'server', 'location')`
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

    for tok, _, quoted in tokens:
        if not quoted and tok.startswith("#"):
            continue
        if tok in (
            "events",
            "http",
            "stream",
            "mail",
            "user",
            "worker_processes",
            "pid",
            "load_module",
            "pcre_jit",
            "mgmt",
        ):
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
# Directives that legitimately span multiple lines with arbitrary unquoted tokens
MULTILINE_EXEMPT_DIRECTIVES = {
    "types",
    "log_format",
}


def parse_and_analyze_tokens(
    tokens: List[Tuple[str, int, bool]],
    filename: str = "nginx.conf",
    initial_ctx: Tuple[str, ...] = (),
    strict: bool = True,
    comments: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Tuple[str, Tuple[str, ...], int]]]:
    """
    Parses token stream into AST statements while recording exact `(arg, arg_line, arg_quoted)`
    for every argument, enabling:
    - Exact crossplane context & argument count checks
    - Upstream `server` parameter validation
    - Multi-line missing-semicolon (`;`) detection when a directive swallows the next line's directive
      (including 0-arg directives like `internal;` or `ip_hash;`)
    - Collection of `(include_pattern, ctx, line)` for multi-file include resolution.
    """
    errors: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    includes_found: List[Tuple[str, Tuple[str, ...], int]] = []

    token_iter = iter(tokens)

    def _add_error(
        line: Optional[int],
        msg: str,
        rule: str = "syntax",
        suggestion: Optional[str] = None,
    ):
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

    def _add_warning(
        line: Optional[int],
        msg: str,
        rule: str = "warning",
        suggestion: Optional[str] = None,
    ):
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

    def _check_directive_semantics(
        stmt: Dict[str, Any],
        arg_meta: List[Tuple[str, int, bool]],
        ctx: Tuple[str, ...],
        is_block: bool,
    ):
        directive = stmt["directive"]
        line = stmt["line"]
        args = stmt["args"]

        # Record `include` directives for multi-file analysis
        if directive == "include" and len(args) == 1 and not is_block:
            includes_found.append((args[0], ctx, line))

        # 0. Check for unquoted full-width punctuation (e.g. Chinese ； ） （ ：) in directive or arguments
        fw_dir = find_fullwidth_char(directive)
        if fw_dir:
            ascii_eq = FULLWIDTH_CHARS[fw_dir]
            _add_error(
                line,
                f'invalid full-width character "{fw_dir}" in directive "{directive}"',
                rule="invalid_character",
                suggestion=f'Replace full-width "{fw_dir}" with standard ASCII "{ascii_eq}".',
            )

        is_upstream_server = (
            ctx in (("http", "upstream"), ("stream", "upstream"))
            and directive == "server"
            and not is_block
        )
        for idx, (arg_val, arg_line, arg_quoted) in enumerate(arg_meta):
            if not arg_quoted:
                # For upstream server arg[0], validate_upstream_server_address handles full-width chars with specific context
                if is_upstream_server and idx == 0:
                    continue
                fw_arg = find_fullwidth_char(arg_val)
                if fw_arg:
                    ascii_eq = FULLWIDTH_CHARS[fw_arg]
                    _add_error(
                        arg_line,
                        f'invalid full-width character "{fw_arg}" in argument "{arg_val}"',
                        rule="invalid_character",
                        suggestion=f'Replace or remove full-width "{fw_arg}" (ASCII equivalent: "{ascii_eq}") in "{arg_val}".',
                    )

        # 1. Check for multi-line missing semicolon swallowing another directive FIRST
        swallowed_detected = False
        if arg_meta and directive not in MULTILINE_EXEMPT_DIRECTIVES:
            prev_line = line
            for idx, (arg_val, arg_line, arg_quoted) in enumerate(arg_meta):
                if arg_line > prev_line and not arg_quoted:
                    if ctx in (("http", "upstream"), ("stream", "upstream")) and directive == "server":
                        if arg_val in UPSTREAM_DIRECTIVES or is_directive_valid_in_ctx(arg_val, ctx):
                            _add_error(
                                prev_line,
                                f'directive "{directive}" is not terminated by ";" (swallowed "{arg_val}" directive on line {arg_line})',
                                rule="missing_semicolon",
                                suggestion=f'Add a semicolon ";" at the end of line {prev_line} before "{arg_val}".',
                            )
                            swallowed_detected = True
                            break
                    elif is_directive_valid_in_ctx(arg_val, ctx):
                        # Whether the swallowed directive has 0 args (e.g. `internal;`, `ip_hash;`)
                        # or 1+ args, if a new line starts with a valid directive for the current context,
                        # the previous line was missing a semicolon!
                        _add_error(
                            prev_line,
                            f'directive "{directive}" on line {line} is not terminated by ";" on line {prev_line} (swallowed "{arg_val}" directive on line {arg_line})',
                            rule="missing_semicolon",
                            suggestion=f'Add a semicolon ";" at the end of line {prev_line} before "{arg_val}".',
                        )
                        swallowed_detected = True
                        break
                prev_line = arg_line

        # 2. Run standard crossplane analyze() (context + argument count bitmasks)
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

        # 3. Validate `upstream` -> `server` address and parameters (exact NGINX runtime parity)
        if is_upstream_server:
            if len(arg_meta) >= 1:
                addr_val, addr_line, _ = arg_meta[0]
                addr_err = validate_upstream_server_address(addr_val)
                if addr_err:
                    err_msg, addr_hint = addr_err
                    _add_error(
                        addr_line,
                        err_msg,
                        rule="upstream_server_address",
                        suggestion=addr_hint,
                    )
            if len(arg_meta) >= 2:
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
                            suggestion=hint
                            or "Valid upstream server parameters: weight=<n>, max_conns=<n>, max_fails=<n>, fail_timeout=<time>, slow_start=<time>, backup, down, resolve, drain, route=<s>, service=<s>.",
                        )
                        if param_line > line:
                            break

        # 4. Check deprecated `listen ... http2` (NGINX 1.25.1+ deprecation warning)
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
            if token.startswith("#") and not quoted:
                if comments:
                    parsed.append(
                        {
                            "directive": "#",
                            "line": lineno,
                            "args": [],
                            "comment": token[1:],
                        }
                    )
                continue

            if token == "}" and not quoted:
                if is_top_level:
                    _add_error(lineno, 'unexpected "}"', rule="syntax")
                    continue
                return parsed

            if token in (";", "{") and not quoted:
                _add_error(lineno, f'unexpected "{token}"', rule="syntax")
                continue

            stmt: Dict[str, Any] = {
                "directive": token,
                "line": lineno,
                "args": [],
            }
            arg_meta: List[Tuple[str, int, bool]] = []

            terminated = False
            terminator = None

            for arg_tok, arg_line, arg_quoted in token_iter:
                if not arg_quoted and arg_tok.startswith("#"):
                    continue

                if not arg_quoted and arg_tok in (";", "{"):
                    terminated = True
                    terminator = arg_tok
                    break

                if not arg_quoted and arg_tok == "}":
                    last_line = arg_meta[-1][1] if arg_meta else lineno
                    _add_error(
                        last_line,
                        f'directive "{stmt["directive"]}" is not terminated by ";"',
                        rule="missing_semicolon",
                        suggestion=f'Add ";" at the end of the "{stmt["directive"]}" directive on line {last_line}.',
                    )
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
                if stmt["directive"] in ("match", "mgmt", "otel_exporter"):
                    inner_ctx = ctx
                else:
                    inner_ctx = enter_block_ctx(stmt, ctx)
                stmt["block"] = _parse_block(inner_ctx, is_top_level=False)

            parsed.append(stmt)

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
    return parsed_ast, errors, warnings, includes_found


# ---------------------------------------------------------------------------
# 5. Runtime Verification via `nginx -t` with Automatic External Mocking
# ---------------------------------------------------------------------------
DEFAULT_MIME_TYPES = """types {
    text/html                             html htm shtml;
    text/css                              css;
    text/xml                              xml;
    image/gif                             gif;
    image/jpeg                            jpeg jpg;
    application/javascript                js;
    application/json                      json;
    text/plain                            txt;
    application/octet-stream              bin exe dll;
}
"""

DEFAULT_FASTCGI_PARAMS = """fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE       $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;
"""

_CACHED_MOCK_CERT: Optional[Tuple[str, str]] = None


def _get_or_create_mock_ssl_cert() -> Tuple[str, str]:
    """
    Returns `(cert_pem, key_pem)`. Uses pre-generated `/app/mock_assets` if present,
    or generates a self-signed RSA 2048 certificate on the fly via `openssl`.
    """
    global _CACHED_MOCK_CERT
    if _CACHED_MOCK_CERT is not None:
        return _CACHED_MOCK_CERT

    pre_cert = "/app/mock_assets/mock.crt"
    pre_key = "/app/mock_assets/mock.key"
    if os.path.exists(pre_cert) and os.path.exists(pre_key):
        with open(pre_cert, "r", encoding="utf-8") as fc, open(pre_key, "r", encoding="utf-8") as fk:
            _CACHED_MOCK_CERT = (fc.read(), fk.read())
            return _CACHED_MOCK_CERT

    openssl_bin = shutil.which("openssl")
    if openssl_bin:
        with tempfile.TemporaryDirectory() as tmp:
            crt_file = os.path.join(tmp, "mock.crt")
            key_file = os.path.join(tmp, "mock.key")
            subprocess.run(
                [
                    openssl_bin,
                    "req",
                    "-x509",
                    "-nodes",
                    "-days",
                    "3650",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    key_file,
                    "-out",
                    crt_file,
                    "-subj",
                    "/CN=localhost",
                ],
                capture_output=True,
                check=False,
                timeout=5,
            )
            if os.path.exists(crt_file) and os.path.exists(key_file):
                with open(crt_file, "r", encoding="utf-8") as fc, open(key_file, "r", encoding="utf-8") as fk:
                    _CACHED_MOCK_CERT = (fc.read(), fk.read())
                    return _CACHED_MOCK_CERT

    return ("", "")


def _normalize_rel_path(path: str) -> str:
    """
    Normalizes a user-supplied virtual file path into a safe relative path inside the sandbox.
    Strips `/etc/nginx/` prefix or leading `/` and prevents `..` traversal.
    """
    p = path.strip().replace("\\", "/")
    if p.startswith("/etc/nginx/"):
        p = p[len("/etc/nginx/") :]
    p = p.lstrip("/")
    norm = posixpath.normpath(p)
    parts = [seg for seg in norm.split("/") if seg not in ("", ".", "..")]
    return "/".join(parts) or "nginx.conf"


def _transform_config_for_sandbox(
    content: str,
    tmpdir: str,
    provided_rel_paths: Set[str],
    mock_externals: bool,
    mocked_items: List[str],
) -> str:
    """
    When `mock_externals=True`, rewrites external certificate paths, log paths,
    and NGINX Plus proprietary directives in the sandbox copy so open-source `nginx -t`
    can verify syntax & context without failing on missing host files or commercial modules.
    """
    if not mock_externals:
        return content

    cert_path = os.path.join(tmpdir, "_mock_ssl.crt")
    key_path = os.path.join(tmpdir, "_mock_ssl.key")

    out_lines: List[str] = []
    prev_terminated = True

    def _is_line_terminated(s: str) -> bool:
        code_part = s.split("#", 1)[0].strip()
        if not code_part:
            return True
        return code_part.endswith((";", "{", "}"))

    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            out_lines.append(raw_line)
            continue

        cur_terminated = _is_line_terminated(stripped)

        # If the previous non-empty line was not terminated by ';', '{', or '}',
        # this line is being swallowed as arguments of the previous directive.
        # Do not shim/comment it out so `nginx -t` reports the exact swallowed token error.
        if not prev_terminated:
            out_lines.append(raw_line)
            prev_terminated = cur_terminated
            continue

        prev_terminated = cur_terminated

        # 1. Mock SSL certificates & keys
        m_cert = re.match(
            r"^(\s*)(ssl_certificate|ssl_trusted_certificate|ssl_client_certificate|proxy_ssl_certificate|proxy_ssl_trusted_certificate)\s+([^;\s]+)\s*;(.*)$",
            raw_line,
        )
        if m_cert:
            indent, d_name, target, rest = m_cert.groups()
            rel = _normalize_rel_path(target)
            if "$" not in target and rel not in provided_rel_paths:
                mocked_items.append(f"Mocked {d_name} '{target}' -> self-signed certificate")
                out_lines.append(f"{indent}{d_name} {cert_path};{rest}")
                continue

        m_key = re.match(
            r"^(\s*)(ssl_certificate_key|proxy_ssl_certificate_key)\s+([^;\s]+)\s*;(.*)$",
            raw_line,
        )
        if m_key:
            indent, d_name, target, rest = m_key.groups()
            rel = _normalize_rel_path(target)
            if "$" not in target and rel not in provided_rel_paths:
                mocked_items.append(f"Mocked {d_name} '{target}' -> self-signed private key")
                out_lines.append(f"{indent}{d_name} {key_path};{rest}")
                continue

        # 2. Mock access_log / error_log paths
        m_log = re.match(r"^(\s*)(access_log|error_log)\s+([^;\s]+)(.*);(.*)$", raw_line)
        if m_log:
            indent, d_name, target, extra, rest = m_log.groups()
            if target not in ("off", "stderr", "/dev/stdout", "/dev/stderr", "/dev/null") and not target.startswith("syslog:"):
                safe_log = os.path.join(tmpdir, "logs", _normalize_rel_path(target))
                os.makedirs(os.path.dirname(safe_log), exist_ok=True)
                mocked_items.append(f"Redirected {d_name} '{target}' -> sandbox log")
                out_lines.append(f"{indent}{d_name} {safe_log}{' ' + extra.strip() if extra.strip() else ''};{rest}")
                continue

        # 3. Mock auth_basic_user_file
        m_auth = re.match(r"^(\s*auth_basic_user_file)\s+([^;\s]+)\s*;(.*)$", raw_line)
        if m_auth:
            prefix, target, rest = m_auth.groups()
            rel = _normalize_rel_path(target)
            if rel not in provided_rel_paths:
                mock_htpasswd = os.path.join(tmpdir, "_mock_htpasswd")
                with open(mock_htpasswd, "w", encoding="utf-8") as fh:
                    fh.write("user:{PLAIN}pass\n")
                mocked_items.append(f"Mocked auth_basic_user_file '{target}'")
                out_lines.append(f"{prefix} {mock_htpasswd};{rest}")
                continue

        # 4. Rewrite `/etc/nginx/...` in `include` to sandbox relative path
        m_inc = re.match(r"^(\s*include)\s+([^;\s]+)\s*;(.*)$", raw_line)
        if m_inc:
            prefix, inc_target, rest = m_inc.groups()
            rel_inc = _normalize_rel_path(inc_target)
            abs_inc = os.path.join(tmpdir, rel_inc)
            # If wildcard include matches nothing in sandbox, create an empty placeholder directory
            if "*" in rel_inc:
                os.makedirs(os.path.dirname(abs_inc), exist_ok=True)
                out_lines.append(f"{prefix} {abs_inc};{rest}")
                continue
            elif os.path.exists(abs_inc):
                out_lines.append(f"{prefix} {abs_inc};{rest}")
                continue
            else:
                os.makedirs(os.path.dirname(abs_inc), exist_ok=True)
                with open(abs_inc, "w", encoding="utf-8") as fi:
                    fi.write("# Mocked empty include file\n")
                mocked_items.append(f"Created placeholder for missing include '{inc_target}'")
                out_lines.append(f"{prefix} {abs_inc};{rest}")
                continue

        # 5. Shim NGINX Plus proprietary directives (sticky, status_zone, health_check, api, ntlm)
        #    so open-source `nginx -t` does not fail with `unknown directive` after static check passed
        m_plus = re.match(
            r"^(\s*)(sticky|sticky_cookie_insert|status_zone|health_check|health_check_timeout|api|ntlm|queue)\b(.*);(.*)$",
            raw_line,
        )
        if m_plus:
            indent, d_name, _, _ = m_plus.groups()
            mocked_items.append(f"Shimmed NGINX Plus directive '{d_name}' for open-source nginx -t")
            out_lines.append(f"{indent}# [NGINX-Plus-Shimmed] {stripped}")
            continue

        # 6. Strip NGINX Plus-only parameters on `upstream { server <addr> <params>; }`
        #    (`resolve`, `drain`, `route=`, `slow_start=`, `service=`, `sid=`)
        m_ups_srv = re.match(r"^(\s*server\s+[^\s;]+)(\s+[^;]+);(.*)$", raw_line)
        if m_ups_srv and "listen" not in raw_line and "{" not in raw_line:
            head, params_part, rest = m_ups_srv.groups()
            kept_params = []
            stripped_any = False
            for p_tok in params_part.split():
                if p_tok in ("resolve", "drain") or p_tok.startswith(("route=", "slow_start=", "service=", "sid=")):
                    mocked_items.append(f"Shimmed NGINX Plus upstream server param '{p_tok}' for open-source nginx -t")
                    stripped_any = True
                else:
                    kept_params.append(p_tok)
            if stripped_any:
                joined = (" " + " ".join(kept_params)) if kept_params else ""
                out_lines.append(f"{head}{joined};{rest}")
                continue

        out_lines.append(raw_line)

    return "\n".join(out_lines)


def _find_missing_proxy_upstreams(all_contents: List[str]) -> List[str]:
    """
    Finds upstream names referenced in `proxy_pass http(s)://<name>` that are not
    defined in any `upstream <name> {` block and are not IP addresses / localhost.
    """
    defined_upstreams: Set[str] = set()
    referenced_upstreams: Set[str] = set()

    for text in all_contents:
        for m in re.finditer(r"\bupstream\s+([A-Za-z0-9_.-]+)\s*\{", text):
            defined_upstreams.add(m.group(1))
        for m in re.finditer(r"\bproxy_pass\s+https?://([A-Za-z0-9_.-]+)(?::\d+)?(?:/[^\s;]*)?\s*;", text):
            host = m.group(1)
            if host == "localhost" or re.match(r"^\d+\.\d+\.\d+\.\d+$", host) or "$" in host:
                continue
            referenced_upstreams.add(host)

    return sorted(referenced_upstreams - defined_upstreams)


def run_nginx_runtime_test(
    main_content: str,
    detected_ctx: Tuple[str, ...],
    main_filename: str = "nginx.conf",
    extra_files: Optional[Dict[str, str]] = None,
    mock_externals: bool = True,
) -> Dict[str, Any]:
    """
    Runs the real `nginx -t` binary against the configuration inside an isolated sandbox,
    automatically mocking missing SSL certificates, `mime.types`, log directories,
    undefined upstreams, and NGINX Plus directives when `mock_externals=True`.
    """
    nginx_bin = shutil.which("nginx")
    if not nginx_bin:
        return {
            "available": False,
            "passed": None,
            "output": "nginx binary not installed in current environment",
            "mocked_items": [],
        }

    mocked_items: List[str] = []
    extra_files = extra_files or {}

    with tempfile.TemporaryDirectory(prefix="ngx_check_") as tmpdir:
        # 1. Pre-populate standard NGINX auxiliary files & self-signed certs
        with open(os.path.join(tmpdir, "mime.types"), "w", encoding="utf-8") as f:
            f.write(DEFAULT_MIME_TYPES)
        with open(os.path.join(tmpdir, "fastcgi_params"), "w", encoding="utf-8") as f:
            f.write(DEFAULT_FASTCGI_PARAMS)

        cert_pem, key_pem = _get_or_create_mock_ssl_cert()
        if cert_pem and key_pem:
            with open(os.path.join(tmpdir, "_mock_ssl.crt"), "w", encoding="utf-8") as fc:
                fc.write(cert_pem)
            with open(os.path.join(tmpdir, "_mock_ssl.key"), "w", encoding="utf-8") as fk:
                fk.write(key_pem)

        os.makedirs(os.path.join(tmpdir, "logs"), exist_ok=True)

        provided_rel_paths: Set[str] = {_normalize_rel_path(main_filename)}
        for k in extra_files:
            provided_rel_paths.add(_normalize_rel_path(k))

        # 2. Write extra files into sandbox
        all_texts = [main_content] + list(extra_files.values())
        for rel_name, file_text in extra_files.items():
            norm_rel = _normalize_rel_path(rel_name)
            full_path = os.path.join(tmpdir, norm_rel)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            transformed_sub = _transform_config_for_sandbox(
                file_text, tmpdir, provided_rel_paths, mock_externals, mocked_items
            )
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(transformed_sub)

        # 3. Transform main configuration & inject missing upstreams if needed
        transformed_main = _transform_config_for_sandbox(
            main_content, tmpdir, provided_rel_paths, mock_externals, mocked_items
        )

        missing_upstreams = _find_missing_proxy_upstreams(all_texts) if mock_externals else []
        upstream_stubs = ""
        if missing_upstreams:
            stub_lines = []
            for u_name in missing_upstreams:
                stub_lines.append(f"upstream {u_name} {{ server 127.0.0.1:80; }}")
                mocked_items.append(f"Auto-stubbed undefined upstream '{u_name}' -> 127.0.0.1:80")
            upstream_stubs = "\n".join(stub_lines) + "\n"

        # 4. Wrap snippet according to detected context so snippets like `upstream {...}` or `server {...}` work with `nginx -t`
        norm_main_rel = _normalize_rel_path(main_filename)
        conf_path = os.path.join(tmpdir, norm_main_rel)
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)

        stub_line_count = len(upstream_stubs.splitlines()) if upstream_stubs else 0

        if detected_ctx == ("http",):
            wrapped = f"events {{ worker_connections 1024; }}\nhttp {{\n{upstream_stubs}{transformed_main}\n}}\n"
            line_offset = 2 + stub_line_count
        elif detected_ctx == ("http", "server"):
            wrapped = f"events {{ worker_connections 1024; }}\nhttp {{\n{upstream_stubs}server {{\n{transformed_main}\n}}\n}}\n"
            line_offset = 3 + stub_line_count
        elif detected_ctx == ("http", "upstream"):
            wrapped = f"events {{ worker_connections 1024; }}\nhttp {{\nupstream _test_upstream {{\n{transformed_main}\n}}\n}}\n"
            line_offset = 3
        elif detected_ctx == ("stream",):
            wrapped = f"events {{ worker_connections 1024; }}\nstream {{\n{transformed_main}\n}}\n"
            line_offset = 2
        else:
            if not re.search(r"\bevents\s*\{", transformed_main):
                wrapped = f"events {{ worker_connections 1024; }}\n{transformed_main}\n"
                line_offset = 1
            else:
                wrapped = transformed_main
                line_offset = 0

        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(wrapped)

        proc = subprocess.run(
            [
                nginx_bin,
                "-t",
                "-c",
                conf_path,
                "-p",
                tmpdir,
                "-g",
                f"pid {tmpdir}/nginx.pid; error_log stderr;",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        raw_out = (proc.stderr or proc.stdout or "").strip()

        # Clean up sandbox path prefixes & adjust line numbers back to user's original lines
        adjusted_lines = []
        for line in raw_out.splitlines():
            m = re.search(re.escape(conf_path) + r":(\d+)", line)
            if m and line_offset > 0:
                orig_line = max(1, int(m.group(1)) - line_offset)
                line = line.replace(f"{conf_path}:{m.group(1)}", f"{norm_main_rel}:{orig_line}")
            else:
                line = line.replace(tmpdir + "/", "").replace(tmpdir, "")
            adjusted_lines.append(line)

        return {
            "available": True,
            "passed": proc.returncode == 0,
            "exit_code": proc.returncode,
            "output": "\n".join(adjusted_lines),
            "mocked_items": mocked_items,
        }


# ---------------------------------------------------------------------------
# 6. High-level Check & Format Entrypoints (Single-File & Multi-File)
# ---------------------------------------------------------------------------
def check_nginx_config(
    config_text: Optional[str] = None,
    filename: str = "nginx.conf",
    context: str = "auto",
    strict: bool = True,
    comments: bool = False,
    check_runtime: bool = False,
    mock_externals: bool = True,
    files: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Runs full crossplane + enhanced semantic analysis (and optional `nginx -t`)
    on a single NGINX configuration string or a multi-file configuration set.
    """
    file_map: Dict[str, str] = {}
    main_file = _normalize_rel_path(filename)

    if files:
        for item in files:
            fname = _normalize_rel_path(item.get("filename", "nginx.conf"))
            file_map[fname] = item.get("content", "")
        if main_file not in file_map and files:
            main_file = _normalize_rel_path(files[0].get("filename", "nginx.conf"))
        if config_text is not None and main_file not in file_map:
            file_map[main_file] = config_text
    else:
        file_map[main_file] = config_text or ""

    main_content = file_map.get(main_file, "")
    tokens, lex_errors = lex_string_with_lines(main_content, filename=main_file)
    detected_ctx = detect_initial_context(tokens, requested_context=context)

    all_errors: List[Dict[str, Any]] = []
    all_warnings: List[Dict[str, Any]] = []
    config_entries: List[Dict[str, Any]] = []
    analyzed_files: Set[str] = set()

    def _analyze_single_file(fname: str, content: str, start_ctx: Tuple[str, ...]):
        if fname in analyzed_files:
            return
        analyzed_files.add(fname)

        f_tokens, f_lex_errors = lex_string_with_lines(content, filename=fname)
        f_ast, f_parse_errors, f_warnings, f_includes = parse_and_analyze_tokens(
            tokens=f_tokens,
            filename=fname,
            initial_ctx=start_ctx,
            strict=strict,
            comments=comments,
        )
        f_errors = f_lex_errors + f_parse_errors
        all_errors.extend(f_errors)
        all_warnings.extend(f_warnings)

        config_entries.append(
            {
                "file": fname,
                "status": "ok" if len(f_errors) == 0 else "failed",
                "errors": [
                    {
                        "line": e["line"],
                        "error": e["error"],
                        "rule": e.get("rule"),
                        "suggestion": e.get("suggestion"),
                    }
                    for e in f_errors
                ],
                "parsed": f_ast,
            }
        )

        # Follow `include` directives across provided `file_map`
        for inc_pattern, inc_ctx, _ in f_includes:
            norm_pat = _normalize_rel_path(inc_pattern)
            for candidate_name in sorted(file_map.keys()):
                if candidate_name not in analyzed_files and fnmatch.fnmatch(candidate_name, norm_pat):
                    _analyze_single_file(candidate_name, file_map[candidate_name], inc_ctx)

    # 1. Analyze main entry file and recursively follow any matched `include` files
    _analyze_single_file(main_file, main_content, detected_ctx)

    # 2. Analyze any remaining files in `file_map` that were not explicitly matched by an `include`
    for extra_fname, extra_content in file_map.items():
        if extra_fname not in analyzed_files:
            extra_tokens, _ = lex_string_with_lines(extra_content, filename=extra_fname)
            extra_ctx = detect_initial_context(extra_tokens, requested_context="auto")
            _analyze_single_file(extra_fname, extra_content, extra_ctx)

    runtime_res: Optional[Dict[str, Any]] = None
    if check_runtime:
        extra_map = {k: v for k, v in file_map.items() if k != main_file}
        runtime_res = run_nginx_runtime_test(
            main_content=main_content,
            detected_ctx=detected_ctx,
            main_filename=main_file,
            extra_files=extra_map,
            mock_externals=mock_externals,
        )
        # If static check passed but `nginx -t` caught a deeper runtime error, surface it
        if runtime_res.get("available") and runtime_res.get("passed") is False and len(all_errors) == 0:
            rt_out = runtime_res.get("output", "nginx -t failed")
            m_loc = re.search(r"\bin\s+([^\s:]+):(\d+)", rt_out)
            err_file = m_loc.group(1) if m_loc else main_file
            err_line = int(m_loc.group(2)) if m_loc else None
            all_errors.append(
                {
                    "file": err_file,
                    "line": err_line,
                    "error": rt_out,
                    "message": rt_out,
                    "rule": "nginx_runtime_test",
                }
            )

    status = "ok" if len(all_errors) == 0 else "failed"

    result: Dict[str, Any] = {
        "status": status,
        "valid": len(all_errors) == 0,
        "detected_context": "main" if not detected_ctx else " > ".join(detected_ctx),
        "error_count": len(all_errors),
        "warning_count": len(all_warnings),
        "errors": all_errors,
        "warnings": all_warnings,
        "config": config_entries,
    }

    if runtime_res is not None:
        result["runtime_check"] = runtime_res

    return result


def format_nginx_config(
    config_text: str,
    filename: str = "nginx.conf",
    indent: int = 4,
    tabs: bool = False,
    comments: bool = True,
) -> Dict[str, Any]:
    """
    Directly parses and formats raw NGINX configuration text into standardized indentation.
    """
    check_res = check_nginx_config(
        config_text=config_text,
        filename=filename,
        context="auto",
        strict=False,
        comments=comments,
        check_runtime=False,
    )
    parsed = check_res["config"][0]["parsed"] if check_res.get("config") else []
    formatted = crossplane.build(parsed, indent=indent, tabs=tabs)
    return {
        "status": "ok" if check_res["valid"] else "warning",
        "valid": check_res["valid"],
        "formatted": formatted,
        "errors": check_res["errors"],
    }
