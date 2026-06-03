# Modern DNS

Modern DNS 是一个前后端一体化的 DNS 管理平台，提供域名解析管理、转发策略、缓存策略、安全防护、监控告警、工具诊断与系统配置等能力。

## 项目状态

- 后端：Go + Gin + GORM + Redis，提供完整 API 与 DNS 引擎能力
- 前端：Vue 3 + TypeScript + Vite + Element Plus，提供完整管理控制台
- 仓库类型：单仓（Monorepo），包含 backend 与 frontend 两个子项目

## 技术栈

### 后端

- Go 1.22
- Gin
- GORM + MySQL
- Redis
- JWT

### 前端

- Vue 3 + TypeScript
- Vite 5
- Element Plus
- Pinia + Vue Router + Vue I18n
- Axios + ECharts
- Vitest + ESLint + Prettier

## 目录结构

```text
.
├── backend/    # Go 后端服务与 DNS 引擎
├── frontend/   # Vue 管理台
├── scripts/    # 项目脚本
└── README.md
```

更多子模块说明：

- backend/README.md
- docs/notification-template-examples.md

## 快速开始

### 1. 环境准备

- Go >= 1.22
- Node.js >= 20
- npm >= 9
- MySQL >= 8
- Redis >= 7

### 2. 初始化数据库

在 MySQL 中执行：

```bash
mysql -u <user> -p < backend/migrations/schema.sql
```

### 3. 启动后端

```bash
cd backend
go mod tidy
go run main.go
```

默认服务端口：8080。

配置文件位于 backend/config/config.yaml，请根据实际环境修改 MySQL、Redis、JWT 等配置。

### 4. 启动前端

```bash
cd frontend
npm install
npm run dev
```

默认开发服务器由 Vite 提供。前端通过 /api 代理访问后端。

如需覆盖后端地址，可设置环境变量 VITE_API_BASE_URL。

## 常用命令

### 后端

```bash
cd backend
go test ./...
go run main.go
```

### 前端

```bash
cd frontend
npm run dev
npm run build
npm run preview
npm run test:run
npm run lint
npm run format:check
```

## 功能模块

- 仪表盘
- 域名管理（Zone、记录、SOA、DNSSEC）
- 转发管理（全局转发、条件转发）
- 缓存管理
- 安全中心（ACL、黑白名单、限流等）
- 监控与告警
- 工具箱（Dig、调试与测试能力）
- 系统设置（用户、角色、备份、通知模板等）

## 安全注意事项

- 请勿在生产环境使用默认 JWT Secret。
- 请及时修改默认管理员账号密码。
- 建议通过环境变量或外部密钥管理系统注入敏感配置。

## 开发建议

- 提交前建议运行前端 lint 与 test。
- 后端新增模型后，优先补充迁移脚本与接口测试。
- API 变更时请同步更新前端调用与文档。
