# NGINX Crossplane Config Checker API (Docker v1.2)

基于官方 [`nginxinc/crossplane`](https://github.com/nginxinc/crossplane) + 深度语义分析引擎 + 真实 `nginx -t` 沙盒构建的容器化 NGINX / NGINX Plus 配置文件静态检查与 AST 解析 API 服务。

## 核心增强特性（解决 NIM `nginx-go-crossplane` 静态分析缺陷 + 真实运行时双保险）

1. **跨行漏写分号（`;`）吞并下一行指令检测 (`missing_semicolon`)**：
   - 修复原生 `crossplane` / `nginx-go-crossplane` 将漏写分号的 `server 10.21.123.12:443` 下一行的 `sticky cookie ...` 误判为 `server` 附加参数（False Negative）的缺陷。
   - 支持检测吞并无参指令（如 `internal;`、`ip_hash;`、`least_conn;`）及单参/多参指令。
2. **`upstream` `server` 参数严格白名单与复合时间格式校验 (`upstream_server_parameter`)**：
   - 对齐 NGINX / NGINX Plus 运行时 `ngx_http_upstream_server` 规范，严格校验 `weight=`、`max_conns=`、`max_fails=`、`fail_timeout=`、`slow_start=`、`backup`、`down`、`resolve`、`drain`、`route=`、`service=`、`sid=` 等参数，支持 `1m30s` 等复合时间单位。
3. **多文件结构与 `include conf.d/*.conf` 递归上下文追踪**：
   - 支持在请求中传入 `files` 数组，自动匹配 `include` 通配符并将父级上下文（如 `http`）传递至子文件进行深度静态检查与 AST 构建。
4. **容器内置真实 `nginx -t` 沙盒校验 + 外部依赖自动 Mock (`check_runtime` & `mock_externals`)**：
   - 容器内置 `nginx` 二进制与预生成自签名 SSL 证书；开启 `check_runtime: true` 时自动在隔离沙盒中：
     - 将缺失的 `ssl_certificate` / `ssl_certificate_key` 等指向沙盒自签名证书；
     - 自动创建缺失的 `access_log` / `error_log` 目录、`auth_basic_user_file`、`mime.types`；
     - 自动为片段中未定义的 `proxy_pass` upstream 注入临时占位定义；
     - 自动对 NGINX Plus 专有指令（`sticky`、`status_zone`、`health_check`、`api` 等）在静态校验通过后做开源版 `nginx -t` 兼容降级。
5. **NGINX Plus R37 最新指令集支持**：
   - 补全 `http2 on|off;`、`http3`、`quic_*`、`js_import`、`status_zone`、`health_check`、`match`、`api`、`sticky`、`zone`、`state`、`ntlm`、`random`、`otel_*`、`mgmt` 等指令。
6. **新增 `/api/v1/format` 一键配置美化接口**。
7. **内置可视化多文件 Web 检查台 (`NGINX Crossplane Studio`) + Swagger 文档 (`/docs`)**。

---

## 一键启动（Docker / Docker Compose）

### 方式 1：使用 `docker compose` 直接拉起
```bash
docker compose up -d --build
```

### 方式 2：使用 `docker build` & `docker run`
```bash
docker build -t nginx-crossplane-api:latest .
docker run -d --name nginx-crossplane-api -p 8090:8080 nginx-crossplane-api:latest
```

启动后访问：
- **可视化检查界面 (Web UI)**：`http://localhost:8090/`
- **Swagger OpenAPI 文档**：`http://localhost:8090/docs`
- **健康检查**：`http://localhost:8090/health`

---

## API 调用示例

### 1. 单文件检查 + 真实 `nginx -t` 自动 Mock 校验 (`POST /api/v1/check`)
```bash
curl -s -X POST http://localhost:8090/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "config": "upstream upstream_cmp-test123.carizon.work {\n    zone upstream_cmp-test123.carizon.work 64k;\n    server 10.21.123.12:443\n    sticky cookie srv_id expires=1h path=/;\n}",
    "context": "auto",
    "strict": true,
    "check_runtime": true,
    "mock_externals": true
  }' | jq .
```

### 2. 多文件 `include conf.d/*.conf` 检查 (`POST /api/v1/check`)
```bash
curl -s -X POST http://localhost:8090/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "nginx.conf",
    "files": [
      {
        "filename": "nginx.conf",
        "content": "events { worker_connections 1024; }\nhttp {\n    include mime.types;\n    include conf.d/*.conf;\n}"
      },
      {
        "filename": "conf.d/app.conf",
        "content": "server {\n    listen 443 ssl;\n    http2 on;\n    ssl_certificate /etc/nginx/ssl/prod.crt;\n    ssl_certificate_key /etc/nginx/ssl/prod.key;\n    location / {\n        proxy_pass https://backend_pool;\n    }\n}"
      }
    ],
    "strict": true,
    "check_runtime": true,
    "mock_externals": true
  }' | jq .
```

### 3. 一键配置格式化美化 (`POST /api/v1/format`)
```bash
curl -s -X POST http://localhost:8090/api/v1/format \
  -H "Content-Type: application/json" \
  -d '{
    "config": "upstream backend { server 10.0.0.1:8080 weight=5; keepalive 16; }",
    "indent": 4
  }' | jq -r .formatted
```

### 4. 词法分析 Token 流 (`POST /api/v1/lex`)
```bash
curl -s -X POST http://localhost:8090/api/v1/lex \
  -H "Content-Type: application/json" \
  -d '{"config": "server 10.21.123.12:443;\n"}' | jq .
```

### 5. AST 反向生成配置 (`POST /api/v1/build`)
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
