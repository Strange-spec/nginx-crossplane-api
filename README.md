# NGINX Crossplane Config Checker API (Docker)

基于官方 [`nginxinc/crossplane`](https://github.com/nginxinc/crossplane) 构建的容器化 NGINX / NGINX Plus 配置文件静态检查与 AST 解析 API 服务。

## 核心增强特性（解决 NIM `nginx-go-crossplane` 静态分析缺陷）

1. **跨行漏写分号（`;`）吞并下一行指令检测 (`missing_semicolon`)**：
   - 修复原生 `crossplane` / `nginx-go-crossplane` 将漏写分号的 `server 10.21.123.12:443` 下一行的 `sticky cookie ...` 误判为 `server` 附加参数（False Negative）的缺陷。
2. **`upstream` `server` 参数严格白名单与格式校验 (`upstream_server_parameter`)**：
   - 对齐 NGINX / NGINX Plus 运行时 `ngx_http_upstream_server` 规范，严格校验 `weight=`、`max_conns=`、`max_fails=`、`fail_timeout=`、`slow_start=`、`backup`、`down`、`resolve`、`drain`、`route=`、`service=`、`sid=` 等参数。
3. **NGINX Plus R37 最新指令集支持**：
   - 补全 `http2 on|off;`、`http3`、`quic_*`、`js_import`、`status_zone`、`ntlm`、`random`、`resolver` (in upstream) 等新版本指令。
4. **配置片段（Snippet）上下文自动识别 (`context: "auto"`)**：
   - 支持直接传入 `conf.d/*.conf` 片段（如单独的 `upstream { ... }`、`server { ... }`、`location { ... }`）而无需手动包裹 `events {}` / `http {}`。
5. **修复 `crossplane` Issue #114（文件末尾最后一条指令漏写分号漏报/空报错问题）**。
6. **内置可视化 Web 检查台 + Swagger 文档 (`/docs`)**。

---

## 一键启动（Docker / Docker Compose）

### 方式 1：使用 `docker compose` 直接拉起
```bash
cd nginx-crossplane-api
docker compose up -d --build
```

### 方式 2：使用 `docker build` & `docker run`
```bash
cd nginx-crossplane-api
docker build -t nginx-crossplane-api:latest .
docker run -d --name nginx-crossplane-api -p 8090:8080 nginx-crossplane-api:latest
```

启动后访问：
- **可视化检查界面 (Web UI)**：`http://localhost:8090/`
- **Swagger OpenAPI 文档**：`http://localhost:8090/docs`
- **健康检查**：`http://localhost:8090/health`

---

## API 调用示例

### 1. JSON 方式检查配置 (`POST /api/v1/check`)
```bash
curl -s -X POST http://localhost:8090/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "config": "upstream upstream_cmp-test123.carizon.work {\n    zone upstream_cmp-test123.carizon.work 64k;\n    server 10.21.123.12:443\n    sticky cookie srv_id expires=1h path=/;\n}",
    "context": "auto",
    "strict": true
  }' | jq .
```

**返回结果示例（精准拦截漏写分号及非法参数）：**
```json
{
  "status": "failed",
  "valid": false,
  "detected_context": "http",
  "error_count": 2,
  "warning_count": 0,
  "errors": [
    {
      "file": "nginx.conf",
      "line": 3,
      "error": "directive \"server\" is not terminated by \";\" (swallowed \"sticky\" directive on line 4) in nginx.conf:3",
      "message": "directive \"server\" is not terminated by \";\" (swallowed \"sticky\" directive on line 4)",
      "rule": "missing_semicolon",
      "suggestion": "Add a semicolon \";\" at the end of line 3 before \"sticky\"."
    },
    {
      "file": "nginx.conf",
      "line": 4,
      "error": "invalid parameter \"sticky\" in upstream \"server\" directive in nginx.conf:4",
      "message": "invalid parameter \"sticky\" in upstream \"server\" directive",
      "rule": "upstream_server_parameter",
      "suggestion": "Line 3 (\"server 10.21.123.12:443\") is likely missing a trailing semicolon \";\", causing \"sticky\" on line 4 to be parsed as a server parameter."
    }
  ]
}
```

---

## 背景说明：为什么 NIM 2.23.1 静态分析会出现漏报（False Negative）？

在 NGINX Instance Manager (NIM) 2.23.1 中，控制面静态分析依赖 `nginx-go-crossplane`：
1. **词法/语法器跨行吞并**：NGINX 配置以 `;` 或 `{` 作为指令结束符（换行符仅被视作普通空白字符）。当 `upstream` 块内的 `server 10.21.123.12:443` 漏写结尾 `;` 时，解析器会继续读取下一行的 `sticky cookie srv_id expires=1h path=/;` 直到遇到 `;`，并将整行内容合并为一条拥有 6 个参数的 `server` 指令：
   - `directive`: `"server"`
   - `args`: `["10.21.123.12:443", "sticky", "cookie", "srv_id", "expires=1h", "path=/"]`
2. **位掩码（Bitmask）仅校验参数个数而不校验参数语义**：`crossplane` / `nginx-go-crossplane` 中 `upstream` 下的 `server` 指令掩码包含 `NGX_CONF_1MORE`（允许 1 个或多个参数），但不检查第 2 个起的参数名是否属于合法 `server` 参数，也不检查参数是否跨行吞并了其他指令关键字，从而导致 **NIM 静态分析返回无错误（False Negative）**，直到下发至数据面 `nginx -t` 时才被 `ngx_http_upstream_server` 拒绝。

本项目通过 **AST + Token 行号联合回溯 (`missing_semicolon`)** 与 **`upstream` `server` 参数严格白名单校验 (`upstream_server_parameter`)** 彻底解决该漏报问题，并提供带行内高亮与一键自动补全分号修复的 **NGINX Crossplane Studio** Web 工作台。

### 2. 直接上传本地配置文件检查 (`Content-Type: text/plain`)
```bash
curl -s -X POST "http://localhost:8090/api/v1/check?filename=app.conf" \
  -H "Content-Type: text/plain" \
  --data-binary @/path/to/app.conf | jq .
```

### 3. 词法分析 Token 流 (`POST /api/v1/lex`)
```bash
curl -s -X POST http://localhost:8090/api/v1/lex \
  -H "Content-Type: application/json" \
  -d '{"config": "server 10.21.123.12:443;\n"}' | jq .
```

### 4. AST 反向生成格式化配置 (`POST /api/v1/build`)
```bash
curl -s -X POST http://localhost:8090/api/v1/build \
  -H "Content-Type: application/json" \
  -d '{
    "parsed": [
      {
        "directive": "upstream",
        "args": ["backend"],
        "block": [
          {"directive": "server", "args": ["10.0.0.1:8080", "weight=5"]}
        ]
      }
    ],
    "indent": 4
  }' | jq -r .config
```
