# 本地修改说明

本文档记录了本项目相对于 AdGuard Home 官方版本的定制修改。

## 修改内容

### 可配置登录页路径

新增 `http.login_path` 配置项，允许自定义登录页访问路径，隐藏默认的 `/login.html` 入口。

**修改文件：**

- `internal/configmgr/http.go` — `HTTPConfig` 新增 `LoginPath` 字段（2026-10 上游重构后，HTTP 配置由 `internal/home` 迁移至 `configmgr` 包）
- `internal/home/authhttp.go` — 认证中间件支持自定义登录路径
  - `handleCustomLoginAccess`：自定义路径请求内部重写为 `/login.html`；原始 `/login.html` 返回 403
  - `handlePublicAccess`：根路径与 `/index.html` 在配置自定义路径时返回 403
  - `handleAuthenticatedUser`：已认证用户访问自定义路径也重定向到 `/`
  - `handleLogout`：登出后重定向到自定义路径
- `internal/home/auth.go` — 将 `LoginPath` 配置传入认证中间件
- `internal/home/authglinet.go` — 适配上游 `isPublicResource` 签名
- `internal/home/authhttp_internal_test.go` — `TestAuthMiddlewareDefault_customLoginPath*` 回归测试

### 上游 workflow 禁用

上游的 `release.yaml` 与 `snapcraft.yaml` 依赖 AdGuard 私有基础设施（`AdGuardSoftwareLimited/actions` 私有可复用 workflow、内部 runner），在本 fork 上永远无法运行（`release.yaml` 每日定时触发且启动即失败）。fork 已移除二者的 `schedule` 触发器，保留 `workflow_dispatch`。fork 的发布由 tag 触发的 `release.yml` 完成。

### 本地构建修复

- `client_v2/webpack.common.js` — 用 `fileURLToPath(import.meta.url)` 计算 `__dirname`，修复 Windows 宿主机上 `/D:/...` 路径拼接错误（上游仅在 Linux docker 中构建前端，未暴露此问题）

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

GitHub Actions 每周一 UTC 4:00 自动从上游拉取更新并合并。如有冲突会自动创建 PR，需手动解决后合并。也可在 Actions 页面手动触发同步。

### 重新编译

```bash
# 安装前端依赖并构建
cd client && npm ci && npm run build-prod && cd ..

# 编译 Linux 二进制
GOOS=linux GOARCH=amd64 go build -o AdGuardHome_linux_amd64 -ldflags "-s -w" .
```
