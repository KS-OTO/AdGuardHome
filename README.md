# AdGuard Home (定制版)

基于 [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) 官方版本的定制版。

## 项目简介

AdGuard Home 是一个全网级别的广告和追踪器拦截 DNS 服务器。配置完成后，它能覆盖你所有的家庭设备，无需安装任何客户端软件。

### 定制功能

- **根路径访问被拒绝**：访问根路径 `/` 时，返回 **403 Forbidden**，防止未授权访问。
- **登录页访问**：必须通过 `/xxxxxxxxx自定义URL地址.html` 路径访问登录页面，增加了一层安全保护。

## 快速安装

使用以下命令一键安装（自动获取最新版本）：

```bash
curl -s -S -L https://gh.felicity.ac.cn/https://raw.githubusercontent.com/KS-OTO/AdGuardHome/master/scripts/installcn.sh | sh -s -- -v
```

### 安装选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-C cpu_type` | CPU 类型 (amd64, 386, arm64, 等) | 自动检测 |
| `-O os` | 操作系统 (linux, darwin, freebsd, openbsd) | 自动检测 |
| `-o output_dir` | 输出目录 | /opt |
| `-t tag` | 版本标签（默认自动获取最新版本） | 自动获取 |
| `-v` | 详细输出 | 关闭 |
| `-r` | 重新安装 | - |
| `-u` | 卸载 | - |

### 安装示例

```bash
# 安装最新版本（自动获取 GitHub 最新 tag）
curl -s -S -L https://gh.felicity.ac.cn/https://raw.githubusercontent.com/KS-OTO/AdGuardHome/master/scripts/installcn.sh | sh -s -- -v

# 安装指定版本
curl -s -S -L https://gh.felicity.ac.cn/https://raw.githubusercontent.com/KS-OTO/AdGuardHome/master/scripts/installcn.sh | sh -s -- -t v0.3.0

# 指定安装目录
curl -s -S -L https://gh.felicity.ac.cn/https://raw.githubusercontent.com/KS-OTO/AdGuardHome/master/scripts/installcn.sh | sh -s -- -o /opt

# 重新安装（先卸载当前版本再安装最新版本）
curl -s -S -L https://gh.felicity.ac.cn/https://raw.githubusercontent.com/KS-OTO/AdGuardHome/master/scripts/installcn.sh | sh -s -- -r

# 重新安装指定版本（先卸载当前版本再安装指定版本）
curl -s -S -L https://gh.felicity.ac.cn/https://raw.githubusercontent.com/KS-OTO/AdGuardHome/master/scripts/installcn.sh | sh -s -- -r -t v0.3.0

# 卸载
curl -s -S -L https://gh.felicity.ac.cn/https://raw.githubusercontent.com/KS-OTO/AdGuardHome/master/scripts/installcn.sh | sh -s -- -u
```

### 安装ADGuard Home后的常用指令

需在安装目录下执行，默认安装目录为 `/opt/AdGuardHome`。

```bash
# 运行安装 AdGuard Home 作为系统服务
sudo ./AdGuardHome -s install

# 卸载 AdGuard Home 服务
sudo ./AdGuardHome -s uninstall

# 开始服务
sudo ./AdGuardHome -s start

# 停止服务
sudo ./AdGuardHome -s stop

# 重启服务
sudo ./AdGuardHome -s restart

# 显示当前服务状态
sudo ./AdGuardHome -s status

```

### 版本同步

安装脚本会自动从 GitHub API 获取最新发布的版本号，确保安装的版本与 GitHub Releases 保持一致。

## 与官方版本的区别

新增 `login_path` 配置项，支持自定义登录页路径，隐藏默认登录入口。

| 特性 | 官方版本 | 本定制版（配置 login_path 后） |
|------|----------|-------------------------------|
| 根路径访问 | 自动跳转到 `/login.html` | 返回 **403 Forbidden** |
| `/login.html` | 正常访问登录页 | 返回 **403 Forbidden** |
| 自定义路径 | 不支持 | 手动访问自定义路径进入登录页 |
| 未配置 login_path | - | 行为与官方版本完全一致 |

## 配置方法

在 `AdGuardHome.yaml` 的 `http` 块中添加 `login_path`：

```yaml
http:
  address: 0.0.0.0:3000
  session_ttl: 720h
  login_path: wsshuiji.html  # 自定义登录页路径，留空则使用默认行为
```

配置后：
- 访问 `http://your-server:3000/` → 403 Forbidden
- 访问 `http://your-server:3000/wsshuiji.html` → 登录页
- 访问 `http://your-server:3000/login.html` → 403 Forbidden

## 上游同步

本仓库通过 GitHub Actions 每天自动同步上游 [AdguardTeam/AdGuardHome](https://github.com/AdguardTeam/AdGuardHome) 的更新。如有合并冲突会自动创建 PR 提醒手动处理。

## 更多信息

- 官方文档：https://github.com/AdguardTeam/AdGuardHome/wiki
- 本地修改说明：[LOCAL_MODIFICATIONS.md](./LOCAL_MODIFICATIONS.md)
