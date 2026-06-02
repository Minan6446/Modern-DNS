# Modern DNS 数据库数据字典

> 数据库：`modern_dns`  
> 字符集：`utf8mb4_unicode_ci`  
> 引擎：InnoDB  
> 适用版本：MySQL 8.0+

---

## 目录

- [Auth 认证模块](#auth-认证模块)
  - [roles — 角色表](#roles--角色表)
  - [users — 用户表](#users--用户表)
  - [role_permissions — 角色权限表](#role_permissions--角色权限表)
  - [operation_logs — 操作审计日志表](#operation_logs--操作审计日志表)
  - [api_keys — API 密钥表](#api_keys--api-密钥表)
- [Dashboard 仪表盘模块](#dashboard-仪表盘模块)
  - [alert_rules — 告警规则表](#alert_rules--告警规则表)
  - [alert_events — 告警事件表](#alert_events--告警事件表)
  - [alert_audit_logs — 告警操作日志表](#alert_audit_logs--告警操作日志表)
  - [domain_health — 域名健康状态表](#domain_health--域名健康状态表)
- [Domain DNS 解析模块](#domain-dns-解析模块)
  - [zones — DNS 区域表](#zones--dns-区域表)
  - [dns_records — DNS 解析记录表](#dns_records--dns-解析记录表)
  - [zone_soa — SOA 记录表](#zone_soa--soa-记录表)
  - [zone_dnssec — DNSSEC 密钥表](#zone_dnssec--dnssec-密钥表)
- [Forward 转发模块](#forward-转发模块)
  - [forward_global — 全局转发配置表](#forward_global--全局转发配置表)
  - [forward_servers — 上游转发服务器表](#forward_servers--上游转发服务器表)
  - [forward_rules — 转发规则表](#forward_rules--转发规则表)
- [Cache 缓存模块](#cache-缓存模块)
  - [cache_global_strategy — 全局缓存策略表](#cache_global_strategy--全局缓存策略表)
  - [cache_domain_rules — 域名缓存规则表](#cache_domain_rules--域名缓存规则表)
- [Security 安全模块](#security-安全模块)
  - [bw_rules — 黑白名单规则表](#bw_rules--黑白名单规则表)
  - [ddos_global — DDoS 全局防护配置表](#ddos_global--ddos-全局防护配置表)
  - [ddos_domain_rules — DDoS 域名限速规则表](#ddos_domain_rules--ddos-域名限速规则表)
  - [security_dnssec — DNSSEC 安全状态表](#security_dnssec--dnssec-安全状态表)
  - [tls_certs — TLS 证书管理表](#tls_certs--tls-证书管理表)
- [Monitor 监控模块](#monitor-监控模块)
  - [query_logs — DNS 查询日志表](#query_logs--dns-查询日志表)
  - [monitor_qps_rule — QPS 监控规则表](#monitor_qps_rule--qps-监控规则表)
  - [monitor_nxdomain_rule — NXDOMAIN 监控规则表](#monitor_nxdomain_rule--nxdomain-监控规则表)
  - [monitor_rule_history — 监控触发历史表](#monitor_rule_history--监控触发历史表)
- [Tools 工具模块](#tools-工具模块)
  - [dig_history — Dig 查询历史表](#dig_history--dig-查询历史表)
  - [global_test_history — 全球解析测试历史表](#global_test_history--全球解析测试历史表)
- [Cluster 集群模块](#cluster-集群模块)
  - [cluster_nodes — 集群节点表](#cluster_nodes--集群节点表)
  - [cluster_config_sync — 集群配置同步状态表](#cluster_config_sync--集群配置同步状态表)
- [Setting 系统设置模块](#setting-系统设置模块)
  - [system_config — 系统全局配置表](#system_config--系统全局配置表)
  - [backups — 备份记录表](#backups--备份记录表)
  - [notice_config — 通知渠道配置表](#notice_config--通知渠道配置表)

---

## Auth 认证模块

### roles — 角色表

**说明**：存储系统角色定义，内置超级管理员（id=1）、运维管理员（id=2）、只读用户（id=3），id≤3 不可删除。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| name | VARCHAR(64) | 否 | — | 角色名称，全局唯一 |
| remark | VARCHAR(255) | 否 | `''` | 角色备注说明 |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间，自动维护 |

**索引**：PRIMARY KEY(id)，UNIQUE(name)

---

### users — 用户表

**说明**：系统登录用户，`password` 使用 bcrypt 哈希存储，关联 `roles` 表。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| username | VARCHAR(64) | 否 | — | 登录用户名，全局唯一 |
| password | VARCHAR(255) | 否 | — | bcrypt 哈希密码 |
| real_name | VARCHAR(64) | 否 | `''` | 真实姓名 |
| role_id | BIGINT UNSIGNED | 否 | `0` | 关联 roles.id |
| role_name | VARCHAR(64) | 否 | `''` | 冗余存储角色名（展示用） |
| status | VARCHAR(16) | 否 | `'启用'` | 账号状态：`启用` / `禁用` |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，UNIQUE(username)，INDEX(status)

---

### role_permissions — 角色权限表

**说明**：角色与权限标识的多对多关系，每个 `(role_id, permission)` 组合唯一。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| role_id | BIGINT UNSIGNED | 否 | — | 关联 roles.id |
| permission | VARCHAR(64) | 否 | — | 权限标识，如 `zone:read`、`record:write` |

**索引**：PRIMARY KEY(id)，UNIQUE(role_id, permission)

---

### operation_logs — 操作审计日志表

**说明**：记录所有用户操作行为，支持操作前后数据对比，用于安全审计与合规。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| log_id | VARCHAR(64) | 否 | `''` | 日志唯一标识，格式如 `AUD-20260423-001` |
| operator | VARCHAR(64) | 否 | `''` | 操作人用户名 |
| operator_role | VARCHAR(64) | 否 | `''` | 操作人角色名 |
| action_type | VARCHAR(32) | 否 | `''` | 操作大类，如 `配置`、`编辑`、`删除` |
| action | VARCHAR(32) | 否 | `''` | 具体操作动作，如 `新增`、`同步`、`吊销` |
| module | VARCHAR(64) | 否 | `''` | 操作模块，如 `区域管理`、`用户管理` |
| target | VARCHAR(255) | 否 | `''` | 操作对象，如域名、用户名、密钥前缀 |
| content | VARCHAR(255) | 否 | `''` | 操作描述摘要 |
| ip | VARCHAR(64) | 否 | `''` | 操作来源 IP |
| result | VARCHAR(16) | 否 | `'成功'` | 操作结果：`成功` / `失败` / `拒绝` |
| duration | INT | 否 | `0` | 操作耗时（毫秒） |
| before_val | TEXT | 是 | NULL | 操作前数据快照（JSON） |
| after_val | TEXT | 是 | NULL | 操作后数据快照（JSON） |
| detail | TEXT | 是 | NULL | 扩展详情（JSON） |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 操作时间 |

**索引**：PRIMARY KEY(id)，INDEX(operator)，INDEX(module)，INDEX(result)，INDEX(created_at)

---

### api_keys — API 密钥表

**说明**：第三方系统集成凭证，密钥明文仅在创建时返回一次，此后只存储 bcrypt 哈希与可展示前缀。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| name | VARCHAR(128) | 否 | `''` | 密钥名称，描述用途 |
| prefix | VARCHAR(32) | 否 | `''` | 可展示前缀，如 `dns_m8kp****` |
| key_hash | VARCHAR(255) | 否 | `''` | 密钥 bcrypt 哈希，不对外暴露 |
| scope | JSON | 是 | NULL | 权限范围数组，如 `["zone:read","record:write"]` |
| created_by | VARCHAR(64) | 否 | `''` | 创建人用户名 |
| expires_at | VARCHAR(32) | 否 | `'never'` | 过期时间，`never` 表示永不过期 |
| status | VARCHAR(16) | 否 | `'正常'` | 状态：`正常` / `已禁用` / `已过期` |
| last_used_at | VARCHAR(32) | 否 | `''` | 最后使用时间，`—` 表示未使用 |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 创建时间 |

**索引**：PRIMARY KEY(id)，INDEX(status)

---

## Dashboard 仪表盘模块

### alert_rules — 告警规则表

**说明**：定义告警触发规则，支持多渠道通知，关联告警事件。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| rule_id | VARCHAR(64) | 否 | — | 规则唯一标识，全局唯一 |
| rule_name | VARCHAR(128) | 否 | `''` | 规则名称 |
| alert_type | VARCHAR(64) | 否 | `''` | 告警类型，如 `QPS异常`、`NXDOMAIN激增` |
| level | VARCHAR(32) | 否 | `'警告'` | 告警级别：`严重` / `警告` / `提示` |
| channel | VARCHAR(32) | 否 | `'邮件'` | 通知渠道：`邮件` / `Webhook` / `短信` |
| target | VARCHAR(255) | 否 | `''` | 监控目标，如域名或 `*` 全局 |
| threshold | INT | 否 | `1` | 触发阈值（含义依 alert_type 而定） |
| status | VARCHAR(16) | 否 | `'启用'` | 规则状态：`启用` / `禁用` |
| remark | VARCHAR(255) | 否 | `''` | 备注说明 |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，UNIQUE(rule_id)，INDEX(status)

---

### alert_events — 告警事件表

**说明**：记录触发的告警事件实例，支持处理状态跟踪与已读标记。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| level | VARCHAR(32) | 否 | `''` | 告警级别：`严重` / `警告` / `提示` |
| type | VARCHAR(64) | 否 | `''` | 告警类型 |
| domain | VARCHAR(255) | 否 | `''` | 关联域名 |
| content | VARCHAR(512) | 否 | `''` | 告警内容描述 |
| status | VARCHAR(32) | 否 | `'未处理'` | 处理状态：`未处理` / `处理中` / `已忽略` / `已解决` |
| is_read | TINYINT(1) | 否 | `0` | 是否已读：`0` 未读 / `1` 已读 |
| triggered_at | DATETIME | 否 | CURRENT_TIMESTAMP | 触发时间 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，INDEX(status)，INDEX(level)

---

### alert_audit_logs — 告警操作日志表

**说明**：记录对告警事件的处理操作历史（如确认、忽略、解决）。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| operator | VARCHAR(64) | 否 | `''` | 操作人用户名 |
| action | VARCHAR(128) | 否 | `''` | 操作描述 |
| target | VARCHAR(255) | 否 | `''` | 操作对象（告警事件ID等） |
| result | VARCHAR(32) | 否 | `'成功'` | 操作结果：`成功` / `失败` |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 操作时间 |

**索引**：PRIMARY KEY(id)

---

### domain_health — 域名健康状态表

**说明**：定期探测域名可用性，存储最新一次检测结果。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| domain | VARCHAR(255) | 否 | — | 域名，全局唯一 |
| status | VARCHAR(32) | 否 | `'未检测'` | 健康状态：`正常` / `异常` / `未检测` |
| availability | VARCHAR(16) | 否 | `'--'` | 可用率，如 `99.9%` |
| check_ip | VARCHAR(64) | 否 | `'--'` | 最近解析到的 IP 地址 |
| checked_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最近检测时间 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，UNIQUE(domain)

---

## Domain DNS 解析模块

### zones — DNS 区域表

**说明**：DNS Zone 定义，对应权威 DNS 的一个区域，支持 Primary / Secondary / Forward 三种类型。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| zone_id | VARCHAR(64) | 否 | — | Zone 业务标识，全局唯一 |
| domain | VARCHAR(255) | 否 | — | Zone 域名，全局唯一，如 `example.com` |
| type | VARCHAR(32) | 否 | `'Primary'` | Zone 类型：`Primary` / `Secondary` / `Forward` |
| status | VARCHAR(32) | 否 | `'正常'` | 状态：`正常` / `暂停` / `异常` |
| remark | VARCHAR(255) | 否 | `''` | 备注 |
| upstream | VARCHAR(255) | 否 | `''` | 上游服务器地址（Secondary/Forward 使用） |
| serial | VARCHAR(32) | 否 | `''` | SOA Serial 号 |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，UNIQUE(zone_id)，UNIQUE(domain)，INDEX(type)，INDEX(status)

---

### dns_records — DNS 解析记录表

**说明**：Zone 下的具体解析记录，支持 A/AAAA/CNAME/MX/TXT/NS/SRV/PTR 等所有标准记录类型。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| zone_id | BIGINT UNSIGNED | 否 | — | 关联 zones.id |
| type | VARCHAR(16) | 否 | `'A'` | 记录类型：`A` / `AAAA` / `CNAME` / `MX` / `TXT` 等 |
| host | VARCHAR(255) | 否 | `'@'` | 主机名，`@` 表示区域根 |
| value | VARCHAR(512) | 否 | `''` | 解析值，如 IP 地址、目标域名 |
| ttl | INT | 否 | `600` | TTL（秒） |
| status | VARCHAR(16) | 否 | `'启用'` | 状态：`启用` / `禁用` |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，INDEX(zone_id)，INDEX(type)

---

### zone_soa — SOA 记录表

**说明**：Zone 的 SOA（Start of Authority）记录参数，每个 Zone 有且仅有一条。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| zone_id | BIGINT UNSIGNED | 否 | — | 关联 zones.id，唯一 |
| mname | VARCHAR(255) | 否 | `''` | 主域名服务器 FQDN |
| rname | VARCHAR(255) | 否 | `''` | 管理员邮箱（点号替代@，如 `admin.example.com`） |
| refresh | INT | 否 | `3600` | Secondary 刷新间隔（秒） |
| retry | INT | 否 | `600` | 刷新失败重试间隔（秒） |
| expire | INT | 否 | `1209600` | Secondary 数据过期时间（秒，默认14天） |
| minimum_ttl | INT | 否 | `300` | 否定缓存 TTL（秒） |

**索引**：PRIMARY KEY(id)，UNIQUE(zone_id)

---

### zone_dnssec — DNSSEC 密钥表

**说明**：Zone 的 DNSSEC 签名密钥，支持 KSK（Key Signing Key）和 ZSK（Zone Signing Key）。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| zone_id | BIGINT UNSIGNED | 否 | — | 关联 zones.id |
| key_type | VARCHAR(8) | 否 | `'KSK'` | 密钥类型：`KSK` / `ZSK` |
| key_id | VARCHAR(64) | 否 | `''` | 密钥标识符 |
| algorithm | VARCHAR(64) | 否 | `'RSASHA256'` | 签名算法，如 `RSASHA256`、`ECDSAP256SHA256` |
| status | VARCHAR(32) | 否 | `'生效中'` | 状态：`生效中` / `已撤销` / `待轮换` |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 创建时间 |

**索引**：PRIMARY KEY(id)，UNIQUE(zone_id, key_id)，INDEX(zone_id)

---

## Forward 转发模块

### forward_global — 全局转发配置表

**说明**：单行配置表（id=1），全局 DNS 转发开关与默认公共 DNS 设置。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键，固定为 1 |
| enabled | TINYINT(1) | 否 | `1` | 全局转发总开关：`0` 关 / `1` 开 |
| public_dns | VARCHAR(64) | 否 | `'AliDNS'` | 默认公共 DNS 名称，如 `AliDNS`、`Google` |
| public_dns_enabled | TINYINT(1) | 否 | `1` | 公共 DNS 是否启用 |
| public_dns_custom | VARCHAR(255) | 否 | `''` | 自定义公共 DNS 地址 |
| timeout | INT | 否 | `5` | 上游查询超时时间（秒） |
| retries | INT | 否 | `2` | 超时后重试次数 |
| strategy | VARCHAR(32) | 否 | `'priority'` | 上游选择策略：`priority`（优先级）/ `random`（随机）/ `rr`（轮询） |

**索引**：PRIMARY KEY(id)

---

### forward_servers — 上游转发服务器表

**说明**：配置自定义上游 DNS 转发服务器，支持 UDP/TCP/DoT/DoH 协议。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| name | VARCHAR(128) | 否 | `''` | 服务器名称 |
| address | VARCHAR(255) | 否 | `''` | 服务器地址（IP 或域名） |
| port | INT | 否 | `53` | 端口号 |
| protocol | VARCHAR(16) | 否 | `'UDP'` | 协议：`UDP` / `TCP` / `DoT` / `DoH` |
| priority | INT | 否 | `1` | 优先级，数值越小优先级越高 |
| status | VARCHAR(16) | 否 | `'启用'` | 状态：`启用` / `禁用` |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，INDEX(priority)

---

### forward_rules — 转发规则表

**说明**：基于域名匹配的定向转发规则，优先级高的规则先匹配。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| rule_id | VARCHAR(64) | 否 | — | 规则唯一标识 |
| domains | TEXT | 否 | — | 匹配域名列表（换行或逗号分隔） |
| upstream_id | BIGINT UNSIGNED | 否 | `0` | 关联 forward_servers.id |
| upstream_name | VARCHAR(255) | 否 | `''` | 冗余存储上游名称（展示用） |
| priority | INT | 否 | `1` | 规则优先级，数值越小越优先 |
| status | VARCHAR(16) | 否 | `'启用'` | 状态：`启用` / `禁用` |
| remark | VARCHAR(255) | 否 | `''` | 备注说明 |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，UNIQUE(rule_id)，INDEX(upstream_id)，INDEX(status)

---

## Cache 缓存模块

### cache_global_strategy — 全局缓存策略表

**说明**：单行配置表（id=1），全局 DNS 缓存策略参数。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键，固定为 1 |
| ttl_max | INT | 否 | `86400` | 缓存最大 TTL（秒，默认 24 小时） |
| min_retain | INT | 否 | `300` | 最短保留时间（秒） |
| auto_cleanup | TINYINT(1) | 否 | `1` | 是否自动清理过期缓存 |
| cleanup_cycle | VARCHAR(32) | 否 | `'hourly'` | 清理周期：`hourly`（每小时）/ `daily`（每天） |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)

---

### cache_domain_rules — 域名缓存规则表

**说明**：对特定域名设置独立缓存 TTL，覆盖全局策略。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| domain | VARCHAR(255) | 否 | — | 目标域名，全局唯一 |
| custom_ttl | INT | 否 | `1800` | 自定义最大缓存 TTL（秒） |
| custom_retain | INT | 否 | `600` | 自定义最短保留时间（秒） |
| status | VARCHAR(16) | 否 | `'启用'` | 状态：`启用` / `禁用` |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，UNIQUE(domain)

---

## Security 安全模块

### bw_rules — 黑白名单规则表

**说明**：IP 或域名的访问控制规则，黑名单拒绝访问，白名单绕过安全检测。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| rule_id | VARCHAR(64) | 否 | — | 规则唯一标识 |
| type | VARCHAR(16) | 否 | `'IP'` | 规则类型：`IP` / `域名` |
| list_type | VARCHAR(16) | 否 | `'黑名单'` | 名单类型：`黑名单` / `白名单` |
| value | VARCHAR(255) | 否 | `''` | 匹配值，支持 CIDR（如 `192.168.0.0/24`）或域名 |
| remark | VARCHAR(255) | 否 | `''` | 备注说明 |
| status | VARCHAR(16) | 否 | `'启用'` | 状态：`启用` / `禁用` |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，UNIQUE(rule_id)，INDEX(type)，INDEX(list_type)，INDEX(status)

---

### ddos_global — DDoS 全局防护配置表

**说明**：单行配置表（id=1），全局 DDoS 防护开关与 QPS 阈值。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键，固定为 1 |
| enabled | TINYINT(1) | 否 | `1` | 全局 DDoS 防护开关 |
| qps_limit | INT | 否 | `10000` | 全局 QPS 限制阈值 |
| current_qps | INT | 否 | `0` | 当前实时 QPS（采集更新） |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)

---

### ddos_domain_rules — DDoS 域名限速规则表

**说明**：对特定域名设置独立的 QPS 限速，超出后触发防护。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| domain | VARCHAR(255) | 否 | — | 目标域名，全局唯一 |
| qps_limit | INT | 否 | `1000` | 该域名的 QPS 限制阈值 |
| status | VARCHAR(16) | 否 | `'启用'` | 状态：`启用` / `禁用` |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，UNIQUE(domain)

---

### security_dnssec — DNSSEC 安全状态表

**说明**：独立于 Zone 模块的 DNSSEC 安全验证状态表，用于安全中心集中展示。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| domain | VARCHAR(255) | 否 | — | 域名，全局唯一 |
| dnssec_status | VARCHAR(32) | 否 | `'未开启'` | DNSSEC 状态：`已启用` / `未开启` / `异常` |
| signature_status | VARCHAR(32) | 否 | `'未检查'` | 签名验证状态：`有效` / `无效` / `未检查` |
| last_check_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最近检查时间 |
| ksk_json | TEXT | 是 | NULL | KSK 密钥信息（JSON） |
| zsk_json | TEXT | 是 | NULL | ZSK 密钥信息（JSON） |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，UNIQUE(domain)

---

### tls_certs — TLS 证书管理表

**说明**：DoT/DoH 服务使用的 TLS 证书，包含证书内容与到期监控信息。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| domain | VARCHAR(255) | 否 | `''` | 证书绑定域名 |
| cert_type | VARCHAR(16) | 否 | `'DoT'` | 证书用途：`DoT` / `DoH` |
| issuer | VARCHAR(255) | 否 | `''` | 颁发机构名称 |
| expire_at | VARCHAR(16) | 否 | `''` | 到期日期，格式 `YYYY-MM-DD` |
| days_left | INT | 否 | `0` | 剩余有效天数 |
| status | VARCHAR(16) | 否 | `'正常'` | 状态：`正常` / `即将过期` / `已过期` |
| fingerprint | VARCHAR(255) | 否 | `''` | 证书指纹（SHA-256） |
| uploaded_at | VARCHAR(16) | 否 | `''` | 上传日期 |
| cert_content | LONGTEXT | 是 | NULL | PEM 格式证书内容 |
| key_content | LONGTEXT | 是 | NULL | PEM 格式私钥内容（加密存储） |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 创建时间 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，INDEX(domain)，INDEX(status)

---

## Monitor 监控模块

### query_logs — DNS 查询日志表

**说明**：记录每条 DNS 查询请求详情，支持安全审计和流量分析，高写入场景建议按日分区。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| query_id | VARCHAR(64) | 否 | `''` | 查询唯一标识 |
| domain | VARCHAR(255) | 否 | `''` | 查询域名 |
| record_type | VARCHAR(16) | 否 | `''` | 查询类型：`A` / `AAAA` / `MX` 等 |
| source_ip | VARCHAR(64) | 否 | `''` | 客户端 IP 地址 |
| region | VARCHAR(32) | 否 | `''` | 来源地区 |
| response_status | VARCHAR(32) | 否 | `''` | 响应状态：`NOERROR` / `NXDOMAIN` / `SERVFAIL` 等 |
| response_time | INT | 否 | `0` | 响应耗时（毫秒） |
| rcode | VARCHAR(32) | 否 | `''` | DNS 响应码 |
| transaction_id | VARCHAR(32) | 否 | `''` | DNS 事务 ID |
| request_payload | TEXT | 是 | NULL | 原始请求报文（调试用） |
| response_payload | TEXT | 是 | NULL | 原始响应报文（调试用） |
| created_at | DATETIME | 否 | CURRENT_TIMESTAMP | 查询时间 |

**索引**：PRIMARY KEY(id)，INDEX(domain)，INDEX(source_ip)，INDEX(response_status)，INDEX(created_at)

---

### monitor_qps_rule — QPS 监控规则表

**说明**：单行配置表（id=1），QPS 异常监控的全局规则参数。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键，固定为 1 |
| global_threshold_percent | INT | 否 | `50` | 全局 QPS 告警触发百分比（相对正常基线） |
| domain_threshold_percent | INT | 否 | `100` | 单域名 QPS 告警触发百分比 |
| period_sec | INT | 否 | `60` | 统计周期（秒） |
| enabled | TINYINT(1) | 否 | `1` | 规则是否启用 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)

---

### monitor_nxdomain_rule — NXDOMAIN 监控规则表

**说明**：单行配置表（id=1），NXDOMAIN 激增（域名不存在响应异常增多）监控规则。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键，固定为 1 |
| threshold_percent | INT | 否 | `200` | NXDOMAIN 响应占比阈值（%），超出后触发告警 |
| period_sec | INT | 否 | `60` | 统计周期（秒） |
| enabled | TINYINT(1) | 否 | `1` | 规则是否启用 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)

---

### monitor_rule_history — 监控触发历史表

**说明**：记录监控规则每次被触发的历史，用于展示告警频次和处理追踪。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| rule_id | VARCHAR(64) | 否 | `''` | 触发的规则标识 |
| rule_type | VARCHAR(64) | 否 | `''` | 规则类型，如 `QPS` / `NXDOMAIN` |
| content | VARCHAR(512) | 否 | `''` | 触发详情描述 |
| handle_status | VARCHAR(32) | 否 | `'未处理'` | 处理状态：`未处理` / `已处理` / `已忽略` |
| trigger_at | DATETIME | 否 | CURRENT_TIMESTAMP | 触发时间 |

**索引**：PRIMARY KEY(id)，INDEX(handle_status)

---

## Tools 工具模块

### dig_history — Dig 查询历史表

**说明**：记录用户在工具页面执行 Dig 查询的历史记录。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| domain | VARCHAR(255) | 否 | `''` | 查询域名 |
| record_type | VARCHAR(16) | 否 | `'A'` | 查询记录类型 |
| dns_server | VARCHAR(255) | 否 | `''` | 使用的 DNS 服务器地址 |
| output | TEXT | 是 | NULL | Dig 命令输出结果 |
| queried_at | DATETIME | 否 | CURRENT_TIMESTAMP | 查询时间 |

**索引**：PRIMARY KEY(id)，INDEX(domain)，INDEX(queried_at)

---

### global_test_history — 全球解析测试历史表

**说明**：记录从全球多节点发起 DNS 解析测试的结果，`result_json` 含各节点响应详情。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| domain | VARCHAR(255) | 否 | `''` | 测试域名 |
| record_type | VARCHAR(16) | 否 | `'A'` | 测试记录类型 |
| node_group | VARCHAR(32) | 否 | `'all'` | 测试节点组：`all` / `cn` / `oversea` 等 |
| result_json | LONGTEXT | 是 | NULL | 各节点测试结果（JSON 数组） |
| tested_at | DATETIME | 否 | CURRENT_TIMESTAMP | 测试时间 |

**索引**：PRIMARY KEY(id)，INDEX(domain)，INDEX(tested_at)

---

## Cluster 集群模块

### cluster_nodes — 集群节点表

**说明**：DNS 集群中各节点的状态信息，由心跳机制定期刷新 `cpu_usage`、`mem_usage`、`qps` 等实时指标。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| name | VARCHAR(128) | 否 | `''` | 节点名称，如 `dns-master-01` |
| ip | VARCHAR(64) | 否 | `''` | 节点 IP 地址 |
| port | INT | 否 | `53` | 节点 DNS 服务端口 |
| role | VARCHAR(32) | 否 | `'从节点'` | 节点角色：`主节点` / `从节点` / `仲裁节点` |
| zone | VARCHAR(64) | 否 | `''` | 所属可用区，如 `cn-east-1` |
| status | VARCHAR(32) | 否 | `'在线'` | 节点状态：`在线` / `离线` / `异常` |
| version | VARCHAR(32) | 否 | `''` | 节点软件版本 |
| cpu_usage | INT | 否 | `0` | CPU 使用率（%） |
| mem_usage | INT | 否 | `0` | 内存使用率（%） |
| qps | INT | 否 | `0` | 当前 QPS |
| sync_lag | INT | 否 | `0` | 与主节点的同步延迟（毫秒），`99999` 表示仲裁节点/不适用 |
| last_heartbeat | DATETIME | 否 | CURRENT_TIMESTAMP | 最近心跳时间 |
| joined_at | DATETIME | 否 | CURRENT_TIMESTAMP | 节点加入集群时间 |

**索引**：PRIMARY KEY(id)，INDEX(status)，INDEX(role)

---

### cluster_config_sync — 集群配置同步状态表

**说明**：记录每个集群节点的配置同步状态及与主节点的版本差异。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| node_id | BIGINT UNSIGNED | 否 | `0` | 关联 cluster_nodes.id |
| node_name | VARCHAR(128) | 否 | `''` | 冗余存储节点名称 |
| node_ip | VARCHAR(64) | 否 | `''` | 冗余存储节点 IP |
| node_role | VARCHAR(32) | 否 | `''` | 冗余存储节点角色 |
| zone | VARCHAR(64) | 否 | `''` | 冗余存储可用区 |
| config_version | VARCHAR(64) | 否 | `''` | 节点当前配置版本 |
| master_version | VARCHAR(64) | 否 | `''` | 主节点最新配置版本 |
| sync_status | VARCHAR(32) | 否 | `'待同步'` | 同步状态：`已同步` / `待同步` / `同步中` / `失败` |
| last_sync_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最近同步时间 |
| diff_count | INT | 否 | `0` | 与主节点的配置差异项数量 |
| diff_detail | LONGTEXT | 是 | NULL | 差异详情（JSON） |

**索引**：PRIMARY KEY(id)，INDEX(node_id)，INDEX(sync_status)

---

## Setting 系统设置模块

### system_config — 系统全局配置表

**说明**：单行配置表（id=1），存储系统级全局参数。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键，固定为 1 |
| timezone | VARCHAR(32) | 否 | `'UTC+8'` | 系统时区 |
| language | VARCHAR(16) | 否 | `'zh-CN'` | 界面语言 |
| auto_backup | TINYINT(1) | 否 | `1` | 是否启用自动备份 |
| backup_cycle | VARCHAR(32) | 否 | `'每日'` | 自动备份周期：`每日` / `每周` / `每月` |
| backup_retention_days | INT | 否 | `30` | 备份保留天数 |
| dnssec_global | TINYINT(1) | 否 | `1` | 是否全局启用 DNSSEC |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)

---

### backups — 备份记录表

**说明**：系统配置备份的元数据记录，实际备份文件由文件系统存储。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| backup_id | VARCHAR(64) | 否 | — | 备份唯一标识，格式如 `BK-1745123456789` |
| backup_scope | JSON | 否 | — | 备份内容范围，如 `["系统配置","域名解析"]` |
| backup_time | DATETIME | 否 | CURRENT_TIMESTAMP | 备份创建时间 |
| file_size | VARCHAR(32) | 否 | `''` | 备份文件大小，如 `1.2MB` |
| format | VARCHAR(16) | 否 | `'JSON'` | 备份格式：`JSON` / `Excel` |
| file_name | VARCHAR(255) | 否 | `''` | 备份文件名 |

**索引**：PRIMARY KEY(id)，UNIQUE(backup_id)

---

### notice_config — 通知渠道配置表

**说明**：各通知渠道（邮件、Webhook、短信）的配置，每个渠道一条记录。

| 列名 | 类型 | 可空 | 默认值 | 说明 |
|------|------|------|--------|------|
| id | BIGINT UNSIGNED | 否 | AUTO_INCREMENT | 主键 |
| channel | VARCHAR(32) | 否 | — | 渠道标识：`email` / `webhook` / `sms`，全局唯一 |
| enabled | TINYINT(1) | 否 | `0` | 是否启用该渠道 |
| config_json | JSON | 否 | — | 渠道配置参数（JSON），含 SMTP 地址、Webhook URL 等 |
| updated_at | DATETIME | 否 | CURRENT_TIMESTAMP | 最后更新时间 |

**索引**：PRIMARY KEY(id)，UNIQUE(channel)

---

*数据字典生成时间：2026-04-23*
