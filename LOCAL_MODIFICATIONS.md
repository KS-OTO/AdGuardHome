# 本地修改说明

本文档记录了本项目相对于 AdGuard Home 官方版本的定制修改。

## 修改内容

### 访问控制修改

**文件**: `internal/home/authhttp.go`

**位置**: `handlePublicAccess` 函数（约第 432 行）

**修改说明**: 访问根路径（`/` 或 `/index.html`）时返回 403 Forbidden，而不是自动重定向到登录页。

```go
// 修改后
if path == "/" || path == "/index.html" {
    w.WriteHeader(http.StatusForbidden)
    return true
}
```

**测试文件**: `internal/home/authhttp_internal_test.go` - 更新了相关测试用例的预期状态码

## 维护指南

### 自动维护（推荐）

项目已配置 `post-merge` hook，每次执行 `git pull` 后会自动：

1. 恢复被覆盖的 `README.md`（从本地备份）
2. 应用代码补丁（`my-fixes.patch`）

### 手动维护

如果 hook 提示冲突，请手动解决后执行：

```bash
git add -A
```

### 重新生成补丁

如果修改了更多文件，更新补丁：

```bash
git diff internal/home/authhttp.go internal/home/authhttp_internal_test.go README.md > my-fixes.patch
```
