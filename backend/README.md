# Modern DNS — Go Backend

## 技术栈
| 组件 | 选型 |
|------|------|
| 语言 | Go 1.22 |
| Web 框架 | Gin v1.10 |
| ORM | GORM v2 + MySQL Driver |
| 缓存 | Redis 7 (go-redis v9) |
| 认证 | JWT (HS256, golang-jwt/v5) |
| 密码 | bcrypt (golang.org/x/crypto) |
| 配置 | Viper (YAML + 环境变量) |
| 跨域 | gin-contrib/cors |

## 目录结构
```
backend/
├── main.go                     # 入口
├── config/
│   ├── config.go               # 配置加载
│   └── config.yaml             # 配置文件（可覆盖）
├── migrations/
│   └── schema.sql              # 全量 DDL + 初始数据
├── middleware/
│   ├── auth.go                 # JWT 认证中间件
│   └── logger.go               # 请求日志中间件
├── pkg/
│   ├── db/
│   │   ├── mysql.go            # MySQL 连接
│   │   └── redis.go            # Redis 连接
│   ├── jwt/
│   │   └── jwt.go              # Token 签发/解析
│   └── resp/
│       └── resp.go             # 统一响应格式
└── internal/
    ├── model/
    │   └── model.go            # 所有 GORM 模型
    ├── handler/
    │   ├── auth.go             # 登录/刷新/登出/个人信息
    │   ├── dashboard.go        # 仪表盘 + 告警规则
    │   ├── domain.go           # Zone + 记录 + SOA + DNSSEC
    │   ├── forward.go          # 全局转发 + 条件转发
    │   ├── cache.go            # 缓存策略 + Redis 缓存条目
    │   ├── security.go         # 黑白名单 + DDoS + DNSSEC
    │   ├── monitor.go          # 实时日志 + 监控规则 + 报表
    │   ├── tools.go            # Dig + DNSSEC调试 + 全球测试 + IP归属
    │   └── setting.go          # 通用配置 + 用户 + 角色 + 备份 + 通知 + 日志
    └── router/
        └── router.go           # 路由注册
```

## 快速启动

### 1. 准备数据库
```bash
mysql -u root -p < migrations/schema.sql
```

### 2. 修改配置
编辑 `config/config.yaml`，填入正确的 MySQL DSN 和 Redis 地址。

或者使用环境变量覆盖（格式：`MYSQL_DSN`, `REDIS_ADDR`, `JWT_SECRET` 等）。

### 3. 安装依赖 & 运行
```bash
cd backend
go mod tidy
go run main.go
```

服务默认监听 `:8080`。

### 4. 默认账号
| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin  | admin123 | 超级管理员 |

**生产环境请立即修改默认密码和 JWT Secret。**

## API 概览

所有接口统一前缀 `/api`，响应格式：
```json
{ "code": 0, "data": <T>, "message": "ok" }
```

除登录/刷新外，所有接口需要 `Authorization: Bearer <access_token>` 请求头。

| 模块 | 前缀 |
|------|------|
| 认证 | `/api/auth/` |
| 仪表盘 | `/api/dashboard/` |
| 域名管理 | `/api/domain/` |
| 转发管理 | `/api/forward/` |
| 缓存管理 | `/api/cache/` |
| 安全中心 | `/api/security/` |
| 监控中心 | `/api/monitor/` |
| 工具箱 | `/api/tools/` |
| 系统设置 | `/api/setting/` |

## Redis 键规范

| 用途 | 键模式 | TTL |
|------|--------|-----|
| DNS 缓存条目 | `dns:cache:<type>:<domain>` | 由记录 TTL 决定 |
| Dig 查询历史 | `tools:dig:history` | 永久 (LList, cap 50) |
| 访问令牌黑名单（扩展） | `auth:blacklist:<jti>` | 令牌剩余有效期 |

## 通知模板示例

- 通知通道模板示例库：`docs/notification-template-examples.md`
