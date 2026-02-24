# AdGuard Home (定制版)

基于 [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) 官方版本的定制版。

## 项目简介

AdGuard Home 是一个全网级别的广告和追踪器拦截 DNS 服务器。配置完成后，它能覆盖你所有的家庭设备，无需安装任何客户端软件。

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
