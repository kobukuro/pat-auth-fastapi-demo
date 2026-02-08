# PAT Auth FastAPI Demo

一個實作 **Personal Access Token (PAT) 權限控管系統** 的 FastAPI 專案，類似 GitHub 的 Fine-grained Personal Access Tokens 機制。

## 專案簡介

本專案實作了雙層認證架構：
- **JWT Token**：用於用戶身份驗證（登入、PAT 管理）
- **PAT Token**：用於 API 存取，帶有精細的範圍權限控制

### 主要功能

- 雙層認證系統（JWT + PAT）
- 層級式範圍授權系統
- 審計日誌（記錄所有 PAT 使用）
- FCS 檔案上傳（支援chunked upload）
- 背景任務系統（統計計算、chunked upload完成後的檔案處理）
- 私人/公開檔案存取控制

---

## 系統架構

### 認證流程

```
┌─────────────────────────────────────────────────────────┐
│  1. 用戶註冊 → 創建帳號                                   │
│  2. 用戶登入 → 取得 JWT                                  │
│  3. 使用 JWT 呼叫 /tokens API → 建立 PAT                 │
│  4. 使用 PAT 呼叫受保護資源 → 依 scopes 授權               │
└─────────────────────────────────────────────────────────┘
```

### 認證與授權詳細流程

```
┌─────────────────────────────────────────────────────────────┐
│ 步驟 1: 用戶登入                                              │
├─────────────────────────────────────────────────────────────┤
│ POST /api/v1/auth/login                                     │
│ → 驗證 email + 密碼 (bcrypt)                                 │
│ → 生成 JWT Token (30分鐘有效)                                 │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 步驟 2: 創建 PAT                                            │
├─────────────────────────────────────────────────────────────┤
│ POST /api/v1/tokens (需要 JWT)                              │
│ → 驗證 JWT Token                                            │
│ → 生成 PAT (pat_ + 隨機字串)                                 │
│ → 儲存 SHA-256 雜湊 以及 前8字元前綴                            │
│ → 關聯 Scopes (權限範圍)                                     │
│ → 返回完整 Token (僅此一次)                                  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 步驟 3: 使用 PAT 存取 API                                     │
├─────────────────────────────────────────────────────────────┤
│ GET /api/v1/workspaces (Header: Authorization: Bearer pat_) │
│ → 1. [Dependency] HTTPBearer 提取 Token                     │
│ → 2. [Dependency] 驗證格式 (pat_ 前綴)                       │
│ → 3. [Dependency] 查詢資料庫 (SHA-256 雜湊比對)               │
│ → 4. [Dependency] 檢查過期時間 & 撤銷狀態                     │
│ → 5. [Dependency] 載入關聯的 Scopes                          │
│ → 6. [Dependency] 檢查權限 (層級繼承規則)                     │
│ → 7. 執行業務邏輯                                            │
│ → 8. [Middleware] 記錄審計日誌（請求完成後）                 │
└─────────────────────────────────────────────────────────────┘
```

### 權限驗證流程

```
用戶請求 GET /api/v1/workspaces (需要 workspaces:read)
                    │
                    ▼
    ┌───────────────────────────────┐
    │ [Dependency] 提取 PAT Token  　│ 
    │    HTTPBearer 自動提取         │
    │    Authorization: Bearer pat_ │
    └───────────────┬───────────────┘
                    ▼
    ┌───────────────────────────────┐
    │ [Dependency] 驗證 Token        │
    │    SHA-256(token) == db.hash  │
    └───────────────┬───────────────┘
                    ▼
    ┌───────────────────────────────┐
    │ [Dependency] 檢查 Token 狀態   │
    │    - 是否沒被撤銷               │
    │    - 是否還沒過期               │
    └───────────────┬───────────────┘
                    ▼
    ┌───────────────────────────────┐
    │ [Dependency] 載入用戶 Scopes   │
    │    ["workspaces:admin", ...]  │
    └───────────────┬───────────────┘
                    ▼
    ┌───────────────────────────────┐
    │ [Dependency] 層級權限檢查       │
    │    需要: workspaces:read       │
    │    用戶有: workspaces:admin    │
    │    │                          │
    │    ├─> admin(4) >= read(1) ✓  │
    │    └─> 授權成功                │
    └───────────────┬───────────────┘
                    ▼
    ┌───────────────────────────────┐
    │ 執行業務邏輯                    │
    │    返回 API 回應               │
    └───────────────┬───────────────┘
                    ▼
    ┌───────────────────────────────┐
    │ [Middleware] 記錄審計日誌       │
    │    - endpoint, method, IP     │
    │    - status_code, authorized  │
    └───────────────────────────────┘
```

**說明**：
- **Dependency**：`app/dependencies/pat.py` 使用 FastAPI 的 `HTTPBearer` 和 `Depends` 進行驗證
- **Middleware**：`app/middleware/audit.py` 在請求完成後記錄審計日誌

### 審計日誌架構

```
每個 PAT 請求 → Audit Middleware
                    │
                    ├─> 記錄成功請求
                    │    - token_id, timestamp, ip
                    │    - endpoint, method, status_code
                    │    - authorized: true
                    │
                    ├─> 記錄失敗請求
                    │    - authorized: false
                    │    - reason: "Unauthorized", "Insufficient permissions"
                    │
                    └─> 容錯設計（同步執行）
                         - 記錄失敗不影響請求（try-except 捕獲）
                         - 使用獨立 DB Session
                         - 請求完成後寫入日誌
```

### 檔案上傳架構（chunked upload）

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. 初始化上傳                                                    │
│    POST /api/v1/fcs/upload                                      │
│    → 創建任務記錄於資料庫 (BackgroundTask model, status: pending) │
│    → 計算總chunk數 (file_size / chunk_size)                      │
│    → 初始化臨時檔案                                              │
└────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. chunked upload                                           │
│    POST /api/v1/fcs/upload/chunk (每個chunk都呼叫一次endpoint)│ 
│    → 驗證 chunk_number 範圍                                 │
│    → 驗證 chunk 大小                                        │
│    → 寫入臨時檔案 (按 offset 定位)                           │
│    → 更新進度 (uploaded_chunks, progress%)                 │
│    → 最後一塊自動觸發完成                                    │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. 後台處理                                                  │
│    FastAPI BackgroundTask (非同步): finalize_chunked_upload   │
│    → 解析 FCS 檔案                                          │
│    → 提取參數與事件數據                                     │
│    → 儲存到 FCSFile 表                                      │
│    → 生成短 ID (base62)                                     │
│    → 移動到最終儲存位置                                     │
└─────────────────────────────────────────────────────────────┘
```

### 權限等級（層級式）

每個資源擁有獨立的權限階層，高階權限自動包含低階權限（不跨資源繼承）：

| 資源 | 權限階層（高 → 低） |
|------|---------------------|
| `workspaces` | admin > delete > write > read |
| `users` | write > read |
| `fcs` | analyze > write > read |

**規則**：例如擁有 `workspaces:admin` 可存取所有 workspaces 相關端點，但無法存取 `fcs:read`。

### 可用範圍（Scopes）

```
workspaces:read, workspaces:write, workspaces:delete, workspaces:admin
users:read, users:write
fcs:read, fcs:write, fcs:analyze
```

---

## 執行方式

### 前置作業
1. 建立.env file(參考.env.sample範本來做設定)
2. 安裝Docker 以及 Docker Compose



### Docker Compose

```bash
# 開發環境（自動執行遷移 + 啟動應用）
docker compose --profile dev up -d --build
# 接著就能在http://localhost:8000/docs看到API文件了

# 測試環境（執行所有測試）
docker compose --profile test up --build
```

---

## API 使用範例

Windows PowerShell(因為手邊沒有macOS或Linux的機器)

### 1. 用戶註冊與登入

```bash
# 註冊新用戶
curl.exe -X 'POST' `
  'http://localhost:8000/api/v1/auth/register' `
  -H 'accept: application/json' `
  -H 'Content-Type: application/json' `
  -d '{\"email\": \"user@example.com\", \"password\": \"Aa12345678!\"}'

# 回應
{
  "success": true,
  "data": {
    "id": 1,
    "email": "user@example.com",
    "created_at": "CREATION_TIMESTAMP"
  }
}

# 登入（取得 JWT Token）
curl.exe -X 'POST' `
  'http://localhost:8000/api/v1/auth/login' `
  -H 'accept: application/json' `
  -H 'Content-Type: application/json' `
  -d '{\"email\": \"user@example.com\", \"password\": \"Aa12345678!\"}'

# 回應
{
  "success": true,
  "data": {
    "access_token": "ACTUAL_JWT_TOKEN",
    "token_type": "bearer"
  }
}
```

### 2. 創建與管理 PAT

```bash
# 創建 PAT（使用 JWT）
$env:JWT_TOKEN = "ACTUAL_JWT_TOKEN"

curl.exe -X POST http://localhost:8000/api/v1/tokens `
  -H "Authorization: Bearer $env:JWT_TOKEN" `
  -H "Content-Type: application/json" `
  -d '{\"name\": \"CI/CD Pipeline Token\", \"scopes\": [\"workspaces:read\", \"workspaces:write\", \"fcs:read\"], \"expires_in_days\": 30}'

# 回應（Token 僅顯示一次）
{
  "success": true,
  "data": {
    "id": 1,
    "name": "CI/CD Pipeline Token",
    "token": "PAT_TOKEN_VALUE",
    "scopes": [
        "workspaces:read",
        "workspaces:write",
        "fcs:read"
    ],
    "created_at": "CREATION_TIMESTAMP",
    "expires_at": "EXPIRATION_TIMESTAMP",
  }
}

# 列出所有 PAT（僅顯示前綴）
curl.exe -X GET http://localhost:8000/api/v1/tokens `
  -H "Authorization: Bearer $env:JWT_TOKEN"

# 撤銷 PAT
curl.exe -X DELETE http://localhost:8000/api/v1/tokens/1 `
  -H "Authorization: Bearer $env:JWT_TOKEN"

# 取得 PAT 審計日誌
curl.exe -X GET http://localhost:8000/api/v1/tokens/1/logs `
  -H "Authorization: Bearer $env:JWT_TOKEN"
```



### 3. 使用 PAT 存取受保護資源

```bash
$env:PAT_TOKEN = "PAT_TOKEN_VALUE"

# 列出工作空間（需要 workspaces:read）
curl.exe -X GET http://localhost:8000/api/v1/workspaces `
  -H "Authorization: Bearer $env:PAT_TOKEN"

# 創建工作空間（需要 workspaces:write）
curl.exe -X POST http://localhost:8000/api/v1/workspaces `
  -H "Authorization: Bearer $env:PAT_TOKEN"

# 刪除工作空間（需要 workspaces:delete）
curl.exe -X DELETE http://localhost:8000/api/v1/workspaces/5 `
  -H "Authorization: Bearer $env:PAT_TOKEN"
```

### 4. FCS 檔案操作

```bash
# 初始化分塊上傳
curl.exe -X POST http://localhost:8000/api/v1/fcs/upload `
  -H "Authorization: Bearer $env:PAT_TOKEN" `
  -F "filename=sample.fcs" `
  -F "file_size=157286400" `
  -F "chunk_size=5242880" `
  -F "is_public=true"

# 回應
{
  "success": true,
  "data": {
    "task_id": 1,
    "filename": "sample.fcs",
    "file_size": 157286400,
    "chunk_size": 5242880,
    "total_chunks": 30,
    "status": "processing"
  }
}

# 上傳chunk（自己先把檔案切好）
curl.exe -X POST http://localhost:8000/api/v1/fcs/upload/chunk `
  -H "Authorization: Bearer $env:PAT_TOKEN" `
  -F "task_id=1" `
  -F "chunk_number=0" `
  -F "chunk=@chunk0.tmp"

# 查詢上傳任務狀態(上傳完成可以看到file_id)
curl.exe -X GET http://localhost:8000/api/v1/fcs/tasks/1 `
  -H "Authorization: Bearer $env:PAT_TOKEN"

# 取得 FCS 參數
curl.exe -X GET "http://localhost:8000/api/v1/fcs/parameters?file_id=abc123xyz" `
  -H "Authorization: Bearer $env:PAT_TOKEN"

# 取得 FCS 事件資料（分頁）
curl.exe -X GET "http://localhost:8000/api/v1/fcs/events?file_id=abc123xyz&limit=100&offset=0" `
  -H "Authorization: Bearer $env:PAT_TOKEN"

# 觸發統計計算（背景任務）
curl.exe -X POST http://localhost:8000/api/v1/fcs/statistics/calculate `
  -H "Authorization: Bearer $env:PAT_TOKEN" `
  -H "Content-Type: application/json" `
  -d '{\"file_id\": \"abc123xyz\"}'

# 取得統計資料
curl.exe -X GET "http://localhost:8000/api/v1/fcs/statistics?file_id=abc123xyz" `
  -H "Authorization: Bearer $env:PAT_TOKEN"

# 下載 FCS 檔案
curl.exe -X GET "http://localhost:8000/api/v1/fcs/files/abc123xyz/download" `
  -H "Authorization: Bearer $env:PAT_TOKEN" `
  -o downloaded_sample.fcs
```

---

## 設計決策
1. scope 儲存在資料庫
    - 新增 scope 不需修改程式碼
    - level欄位定義了權限階層，方便實作繼承邏輯，也容易調整
2. PAT與scope的多對多關聯儲存在資料庫
    - 透過foreign key確保referential integrity(無效的scope_id無法被關聯到PAT, 無效的pat_id無法被關聯到scope)
    - 當PAT或scope被刪除時，CASCADE規則可以自動清理關聯
3. endpoint的權限需求定義在程式碼中
    - 不在資料庫定義，避免要維護兩份(符合DRY原則)
4. 當最後一個chunk上傳後，觸發背景任務來處理檔案
    - 提高使用者體驗，在呼叫API上傳最後一個chunk時不需要等待檔案處理完成才收到回應