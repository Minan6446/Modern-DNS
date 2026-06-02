# Modern DNS

基于 Vue 3 + TypeScript + Vite 5 + Element Plus + Pinia + Vue Router + Vue I18n + Axios + ECharts + VueUse 的 DNS 管理系统前端演示项目。

## 技术栈

- Vue 3
- TypeScript
- Vite 5
- Element Plus
- Vue I18n
- Pinia
- Vue Router
- Axios
- ECharts
- VueUse
- Vitest
- ESLint
- Prettier

## 功能范围

当前项目为纯前端实现，包含以下内容：

- 左侧菜单、顶部导航、主内容区统一布局
- 8 个一级菜单、完整二级路由
- 仪表盘、域名管理、转发管理、缓存管理、安全中心、监控日志、工具箱、系统设置
- 404 页面与无权限占位页
- 基于模拟数据的表格、表单、弹窗、图表、筛选、分页、批量操作
- 深浅色主题切换与响应式布局

当前项目不包含以下内容：

- 后端接口实现
- 数据库与持久化服务
- 登录鉴权后端逻辑
- 真实部署配置

## 目录结构

src 目录主要结构：

- layout: 全局布局
- router: 路由配置
- stores: Pinia 全局状态
- api: Axios 封装与模拟服务
- components: 通用图表组件
- constants: 菜单与常量
- views: 各业务模块页面

## 启动方式

安装依赖：

```bash
npm install
```

启动开发环境：

```bash
npm run dev
```

构建生产包：

```bash
npm run build
```

运行单元测试：

```bash
npm run test:run
```

检查代码质量：

```bash
npm run lint
npm run format:check
```

预览构建结果：

```bash
npm run preview
```

## 说明

- 接口调用位置已保留在 src/api 中，当前默认走模拟数据。
- 图表统一通过 BaseChart 组件封装。
- 菜单结构与路由路径严格对应页面要求。
- 国际化当前提供 zh-CN 与 en-US 两套基础语言包，默认使用 zh-CN。
