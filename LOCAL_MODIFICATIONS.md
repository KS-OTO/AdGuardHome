# 本地修改说明

本文档记录了本项目相对于 AdGuard Home 官方版本的定制修改。

## 修改内容

### 可配置登录页路径

新增 `http.login_path` 配置项，允许自定义登录页访问路径，隐藏默认的 `/login.html` 入口。

**修改文件：**

- `internal/home/config.go` — `httpConfig` 新增 `LoginPath` 字段
- `internal/home/authhttp.go` — 认证中间件支持自定义登录路径
  - `isPublicResource`：配置自定义路径后，原始 `/login.*` 不再是公开资源
  - `handlePublicAccess`：自定义路径请求内部重写为 `/login.html`；原始路径返回 403；根路径返回 403
  - `handleAuthenticatedUser`：已认证用户访问自定义路径也重定向到 `/`
  - `handleLogout`：登出后重定向到自定义路径
- `internal/home/auth.go` — 将 `LoginPath` 配置传入认证中间件
- `internal/home/authglinet.go` — 适配 `isPublicResource` 签名变更
- `internal/home/authhttp_internal_test.go` — 更新测试用例

### 上游自动同步

- `.github/workflows/sync-upstream.yml` — 每天自动同步上游仓库更新，冲突时创建 PR

## 配置示例

```yaml
http:
  address: 0.0.0.0:3000
  session_ttl: 720h
  login_path: wsshuiji.html
```

## 维护指南

### 上游同步

GitHub Actions 每天 UTC 2:00 自动从上游拉取更新并合并。如有冲突会自动创建 PR，需手动解决后合并。也可在 Actions 页面手动触发同步。

### 重新编译

```bash
# 安装前端依赖并构建
cd client && npm ci && npm run build-prod && cd ..

# 编译 Linux 二进制
GOOS=linux GOARCH=amd64 go build -o AdGuardHome_linux_amd64 -ldflags "-s -w" .
```
