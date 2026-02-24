# AdGuard Home (定制版)

基于 [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) 官方版本的定制版。

## 项目简介

AdGuard Home 是一个全网级别的广告和追踪器拦截 DNS 服务器。配置完成后，它能覆盖你所有的家庭设备，无需安装任何客户端软件。

## 与官方版本的区别

| 特性 | 官方版本 | 本定制版 |
|------|----------|----------|
| 根路径访问 | 自动跳转到 `/login.html` | 返回 **403 Forbidden** |
| 登录页访问 | 需要通过跳转 | **必须手动输入路径** `/login.html` |

**定制目的**：增强安全性，访问根路径不会暴露登录入口。

## 更多信息

- 官方文档：https://github.com/AdguardTeam/AdGuardHome/wiki
- 本地修改说明：[LOCAL_MODIFICATIONS.md](./LOCAL_MODIFICATIONS.md)
