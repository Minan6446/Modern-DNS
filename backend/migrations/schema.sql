-- Modern DNS Backend Schema
-- MySQL 8.0+  charset: utf8mb4

CREATE DATABASE IF NOT EXISTS modern_dns DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE modern_dns;

-- ─── Auth ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS roles (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(64)  NOT NULL UNIQUE,
  remark      VARCHAR(255) NOT NULL DEFAULT '',
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS users (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username     VARCHAR(64)  NOT NULL UNIQUE,
  password     VARCHAR(255) NOT NULL,
  real_name    VARCHAR(64)  NOT NULL DEFAULT '',
  email        VARCHAR(128) NOT NULL DEFAULT '',
  phone        VARCHAR(32)  NOT NULL DEFAULT '',
  department   VARCHAR(128) NOT NULL DEFAULT '',
  role_id      BIGINT UNSIGNED NOT NULL DEFAULT 0,
  role_name    VARCHAR(64)  NOT NULL DEFAULT '',
  status       VARCHAR(16)  NOT NULL DEFAULT '启用',
  created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS role_permissions (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  role_id    BIGINT UNSIGNED NOT NULL,
  permission VARCHAR(64)     NOT NULL,
  UNIQUE KEY uk_role_perm (role_id, permission)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS operation_logs (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  log_id        VARCHAR(64)  NOT NULL DEFAULT '',
  operator      VARCHAR(64)  NOT NULL DEFAULT '',
  operator_role VARCHAR(64)  NOT NULL DEFAULT '',
  action_type   VARCHAR(32)  NOT NULL DEFAULT '',
  action        VARCHAR(32)  NOT NULL DEFAULT '',
  module        VARCHAR(64)  NOT NULL DEFAULT '',
  target        VARCHAR(255) NOT NULL DEFAULT '',
  content       VARCHAR(255) NOT NULL DEFAULT '',
  ip            VARCHAR(64)  NOT NULL DEFAULT '',
  result        VARCHAR(16)  NOT NULL DEFAULT '成功',
  duration      INT          NOT NULL DEFAULT 0,
  before_val    TEXT,
  after_val     TEXT,
  detail        TEXT,
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_operator (operator),
  INDEX idx_module   (module),
  INDEX idx_result   (result),
  INDEX idx_created  (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS api_keys (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name         VARCHAR(128) NOT NULL DEFAULT '',
  prefix       VARCHAR(32)  NOT NULL DEFAULT '',
  key_hash     VARCHAR(255) NOT NULL DEFAULT '',
  scope        JSON,
  created_by   VARCHAR(64)  NOT NULL DEFAULT '',
  expires_at   VARCHAR(32)  NOT NULL DEFAULT 'never',
  status       VARCHAR(16)  NOT NULL DEFAULT '正常',
  last_used_at VARCHAR(32)  NOT NULL DEFAULT '',
  created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_status (status)
) ENGINE=InnoDB;

-- ─── Dashboard ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS alert_rules (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  rule_id     VARCHAR(64)  NOT NULL UNIQUE,
  rule_name   VARCHAR(128) NOT NULL DEFAULT '',
  alert_type  VARCHAR(64)  NOT NULL DEFAULT '',
  level       VARCHAR(32)  NOT NULL DEFAULT '警告',
  channel     VARCHAR(32)  NOT NULL DEFAULT '邮件',
  target      VARCHAR(255) NOT NULL DEFAULT '',
  threshold   INT          NOT NULL DEFAULT 1,
  status      VARCHAR(16)  NOT NULL DEFAULT '启用',
  remark      VARCHAR(255) NOT NULL DEFAULT '',
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS alert_events (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  level        VARCHAR(32)  NOT NULL DEFAULT '',
  type         VARCHAR(64)  NOT NULL DEFAULT '',
  domain       VARCHAR(255) NOT NULL DEFAULT '',
  content      VARCHAR(512) NOT NULL DEFAULT '',
  status       VARCHAR(32)  NOT NULL DEFAULT '未处理',
  is_read      TINYINT(1)   NOT NULL DEFAULT 0,
  triggered_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_status (status),
  INDEX idx_level (level)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS alert_audit_logs (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  operator   VARCHAR(64)  NOT NULL DEFAULT '',
  action     VARCHAR(128) NOT NULL DEFAULT '',
  target     VARCHAR(255) NOT NULL DEFAULT '',
  result     VARCHAR(32)  NOT NULL DEFAULT '成功',
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS domain_health (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain       VARCHAR(255) NOT NULL UNIQUE,
  status       VARCHAR(32)  NOT NULL DEFAULT '未检测',
  availability VARCHAR(16)  NOT NULL DEFAULT '--',
  check_ip     VARCHAR(64)  NOT NULL DEFAULT '--',
  checked_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ─── Domain ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS zones (
  id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  zone_id        VARCHAR(64)  NOT NULL UNIQUE,
  domain         VARCHAR(255) NOT NULL UNIQUE,
  type           VARCHAR(32)  NOT NULL DEFAULT 'Primary',
  status         VARCHAR(32)  NOT NULL DEFAULT '正常',
  remark         VARCHAR(255) NOT NULL DEFAULT '',
  upstream       VARCHAR(255) NOT NULL DEFAULT '',
  -- AXFR / IXFR wire protocol for Secondary / Stub zones:
  --   'tcp'  = classical XFR over 53/TCP (RFC 5936) — default
  --   'tls'  = XFR-over-TLS over 853/TCP (RFC 9103)
  --   'quic' = AXFR over DNS-over-QUIC (RFC 9250 framing, ALPN doq)
  -- Ignored for Primary / Reverse / Forward.
  transport      VARCHAR(16)  NOT NULL DEFAULT 'tcp',
  -- Per-zone TLS / QUIC peer-certificate verification opt-out.
  -- 1 = skip verify (lab / self-signed master); 0 = strict.
  -- Ignored when transport = 'tcp' (no TLS handshake at all).
  axfr_insecure  TINYINT(1)   NOT NULL DEFAULT 0,
  serial         VARCHAR(32)  NOT NULL DEFAULT '',
  -- Stamp of the most recent successful AXFR. NULL means "never
  -- synced" and forces the periodic-refresh worker to schedule the
  -- zone on its next tick.
  last_synced_at DATETIME     NULL DEFAULT NULL,
  created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_type (type),
  INDEX idx_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS dns_records (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  zone_id    BIGINT UNSIGNED NOT NULL,
  type       VARCHAR(16)  NOT NULL DEFAULT 'A',
  host       VARCHAR(255) NOT NULL DEFAULT '@',
  value      VARCHAR(512) NOT NULL DEFAULT '',
  ttl        INT          NOT NULL DEFAULT 600,
  status     VARCHAR(16)  NOT NULL DEFAULT '启用',
  remark       VARCHAR(255) NOT NULL DEFAULT '',
  last_used_at DATETIME     NULL DEFAULT NULL,
  created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_zone (zone_id),
  INDEX idx_type (type),
  INDEX idx_created (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS zone_soa (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  zone_id     BIGINT UNSIGNED NOT NULL UNIQUE,
  mname       VARCHAR(255) NOT NULL DEFAULT '',
  rname       VARCHAR(255) NOT NULL DEFAULT '',
  refresh     INT          NOT NULL DEFAULT 3600,
  retry       INT          NOT NULL DEFAULT 600,
  expire      INT          NOT NULL DEFAULT 1209600,
  minimum_ttl INT          NOT NULL DEFAULT 300
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS zone_dnssec (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  zone_id    BIGINT UNSIGNED NOT NULL,
  key_type   VARCHAR(8)   NOT NULL DEFAULT 'KSK',
  key_id     VARCHAR(64)  NOT NULL DEFAULT '',
  algorithm  VARCHAR(64)  NOT NULL DEFAULT 'RSASHA256',
  status     VARCHAR(32)  NOT NULL DEFAULT '生效中',
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uk_zone_key (zone_id, key_id),
  INDEX idx_zone (zone_id)
) ENGINE=InnoDB;

-- Per-zone server-side policy controls — the「区域选项」dialog.
-- One row per zone; ACL / target / allow-types columns hold raw
-- newline / comma-separated text exactly as the operator typed it.
CREATE TABLE IF NOT EXISTS zone_options (
  id                  BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  zone_id             BIGINT UNSIGNED NOT NULL UNIQUE,
  -- Who can query: deny / allow / private / ns-only / acl / ns-acl
  query_mode          VARCHAR(16)  NOT NULL DEFAULT 'allow',
  query_acl           TEXT,
  -- Who can pull AXFR: deny / allow / ns-only / acl
  transfer_mode       VARCHAR(16)  NOT NULL DEFAULT 'deny',
  transfer_acl        TEXT,
  -- DNS NOTIFY targets on serial change: none / ns / custom
  notify_mode         VARCHAR(16)  NOT NULL DEFAULT 'none',
  notify_targets      TEXT,
  notify_on_change    TINYINT(1)   NOT NULL DEFAULT 1,
  -- Who can run dynamic update: deny / allow / private / acl
  dyn_mode            VARCHAR(16)  NOT NULL DEFAULT 'deny',
  dyn_acl             TEXT,
  dyn_tsig_required   TINYINT(1)   NOT NULL DEFAULT 1,
  dyn_allow_types     VARCHAR(255) NOT NULL DEFAULT 'A,AAAA',
  created_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ─── Forward ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS forward_global (
  id                 BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  enabled            TINYINT(1)   NOT NULL DEFAULT 1,
  public_dns         VARCHAR(64)  NOT NULL DEFAULT 'AliDNS',
  public_dns_enabled TINYINT(1)   NOT NULL DEFAULT 1,
  public_dns_custom  VARCHAR(255) NOT NULL DEFAULT '',
  timeout            INT          NOT NULL DEFAULT 5,
  retries            INT          NOT NULL DEFAULT 2,
  strategy           VARCHAR(32)  NOT NULL DEFAULT 'priority'
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS forward_servers (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(128) NOT NULL DEFAULT '',
  address    VARCHAR(255) NOT NULL DEFAULT '',
  port       INT          NOT NULL DEFAULT 53,
  protocol   VARCHAR(16)  NOT NULL DEFAULT 'UDP',
  priority   INT          NOT NULL DEFAULT 1,
  status     VARCHAR(16)  NOT NULL DEFAULT '启用',
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_priority (priority)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS forward_rules (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  rule_id       VARCHAR(64)  NOT NULL UNIQUE,
  domains       TEXT         NOT NULL,
  upstream_id   BIGINT UNSIGNED NOT NULL DEFAULT 0,
  upstream_name VARCHAR(255) NOT NULL DEFAULT '',
  priority      INT          NOT NULL DEFAULT 1,
  status        VARCHAR(16)  NOT NULL DEFAULT '启用',
  remark        VARCHAR(255) NOT NULL DEFAULT '',
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_upstream (upstream_id),
  INDEX idx_status (status)
) ENGINE=InnoDB;

-- ─── Cache ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cache_global_strategy (
  id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  ttl_max        INT          NOT NULL DEFAULT 86400,
  min_retain     INT          NOT NULL DEFAULT 300,
  auto_cleanup   TINYINT(1)   NOT NULL DEFAULT 1,
  cleanup_cycle  VARCHAR(32)  NOT NULL DEFAULT 'hourly',
  updated_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cache_domain_rules (
  id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain         VARCHAR(255) NOT NULL UNIQUE,
  custom_ttl     INT          NOT NULL DEFAULT 1800,
  custom_retain  INT          NOT NULL DEFAULT 600,
  status         VARCHAR(16)  NOT NULL DEFAULT '启用',
  created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- 手动清理历史：每次「手动清理」执行后写入一行，UI 直接读这张表渲染
-- 「清理历史」面板。和 operation_logs 解耦的原因在 model.go 注释里。
CREATE TABLE IF NOT EXISTS cache_clear_logs (
  id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  scope          VARCHAR(32)  NOT NULL DEFAULT 'all',
  scope_label    VARCHAR(128) NOT NULL DEFAULT '',
  domains        TEXT,
  time_start     VARCHAR(32)  NOT NULL DEFAULT '',
  time_end       VARCHAR(32)  NOT NULL DEFAULT '',
  cleared_count  INT          NOT NULL DEFAULT 0,
  operator       VARCHAR(64)  NOT NULL DEFAULT '',
  client_ip      VARCHAR(64)  NOT NULL DEFAULT '',
  detail         TEXT,
  created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_cache_clear_logs_scope (scope),
  KEY idx_cache_clear_logs_created (created_at)
) ENGINE=InnoDB;

-- ─── Security ────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS bw_rules (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  rule_id    VARCHAR(64)  NOT NULL UNIQUE,
  type       VARCHAR(16)  NOT NULL DEFAULT 'IP',
  list_type  VARCHAR(16)  NOT NULL DEFAULT '黑名单',
  value      VARCHAR(255) NOT NULL DEFAULT '',
  remark     VARCHAR(255) NOT NULL DEFAULT '',
  status     VARCHAR(16)  NOT NULL DEFAULT '启用',
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_type (type),
  INDEX idx_list (list_type),
  INDEX idx_status (status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ddos_global (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  enabled     TINYINT(1)  NOT NULL DEFAULT 1,
  qps_limit   INT         NOT NULL DEFAULT 10000,
  current_qps INT         NOT NULL DEFAULT 0,
  updated_at  DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ddos_domain_rules (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain     VARCHAR(255) NOT NULL UNIQUE,
  qps_limit  INT          NOT NULL DEFAULT 1000,
  status     VARCHAR(16)  NOT NULL DEFAULT '启用',
  created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS acl_rules (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(128) NOT NULL DEFAULT '',
  cidr        VARCHAR(64)  NOT NULL DEFAULT '',
  type        VARCHAR(16)  NOT NULL DEFAULT '允许',
  priority    INT          NOT NULL DEFAULT 0,
  query_types VARCHAR(255) NOT NULL DEFAULT '',
  zones       VARCHAR(512) NOT NULL DEFAULT '',
  hit_count   INT          NOT NULL DEFAULT 0,
  status      VARCHAR(16)  NOT NULL DEFAULT '启用',
  remark      VARCHAR(512) NOT NULL DEFAULT '',
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS rpz_rules (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(128) NOT NULL DEFAULT '',
  category    VARCHAR(64)  NOT NULL DEFAULT '',
  type        VARCHAR(32)  NOT NULL DEFAULT '',
  pattern     VARCHAR(255) NOT NULL DEFAULT '',
  action      VARCHAR(32)  NOT NULL DEFAULT '',
  redirect_to VARCHAR(255) NOT NULL DEFAULT '',
  hit_count   INT          NOT NULL DEFAULT 0,
  status      VARCHAR(16)  NOT NULL DEFAULT '启用',
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS security_dnssec (
  id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain           VARCHAR(255) NOT NULL UNIQUE,
  dnssec_status    VARCHAR(32)  NOT NULL DEFAULT '未开启',
  signature_status VARCHAR(32)  NOT NULL DEFAULT '未检查',
  last_check_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ksk_json         TEXT,
  zsk_json         TEXT,
  updated_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS tls_certs (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain       VARCHAR(255) NOT NULL DEFAULT '',
  cert_type    VARCHAR(16)  NOT NULL DEFAULT 'DoT',
  issuer       VARCHAR(255) NOT NULL DEFAULT '',
  expire_at    VARCHAR(16)  NOT NULL DEFAULT '',
  days_left    INT          NOT NULL DEFAULT 0,
  status       VARCHAR(16)  NOT NULL DEFAULT '正常',
  fingerprint  VARCHAR(255) NOT NULL DEFAULT '',
  uploaded_at  VARCHAR(16)  NOT NULL DEFAULT '',
  cert_content LONGTEXT,
  key_content  LONGTEXT,
  created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_domain (domain),
  INDEX idx_status (status)
) ENGINE=InnoDB;

-- ─── Monitor ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS query_logs (
  id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  query_id         VARCHAR(64)  NOT NULL DEFAULT '',
  domain           VARCHAR(255) NOT NULL DEFAULT '',
  record_type      VARCHAR(16)  NOT NULL DEFAULT '',
  source_ip        VARCHAR(64)  NOT NULL DEFAULT '',
  region           VARCHAR(32)  NOT NULL DEFAULT '',
  response_status  VARCHAR(32)  NOT NULL DEFAULT '',
  response_time    INT          NOT NULL DEFAULT 0,
  rcode            VARCHAR(32)  NOT NULL DEFAULT '',
  transaction_id   VARCHAR(32)  NOT NULL DEFAULT '',
  request_payload  TEXT,
  response_payload TEXT,
  created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_domain (domain),
  INDEX idx_source (source_ip),
  INDEX idx_status (response_status),
  INDEX idx_created (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS monitor_qps_rule (
  id                       BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  global_threshold_percent INT     NOT NULL DEFAULT 50,
  domain_threshold_percent INT     NOT NULL DEFAULT 100,
  period_sec               INT     NOT NULL DEFAULT 60,
  enabled                  TINYINT(1) NOT NULL DEFAULT 1,
  updated_at               DATETIME   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS monitor_nxdomain_rule (
  id                 BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  threshold_percent  INT        NOT NULL DEFAULT 200,
  period_sec         INT        NOT NULL DEFAULT 60,
  enabled            TINYINT(1) NOT NULL DEFAULT 1,
  updated_at         DATETIME   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS monitor_latency_rule (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  threshold_ms  INT        NOT NULL DEFAULT 500,
  period_sec    INT        NOT NULL DEFAULT 60,
  enabled       TINYINT(1) NOT NULL DEFAULT 0,
  updated_at    DATETIME   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS monitor_cache_hit_rule (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  min_hit_percent INT        NOT NULL DEFAULT 50,
  period_sec      INT        NOT NULL DEFAULT 300,
  enabled         TINYINT(1) NOT NULL DEFAULT 0,
  updated_at      DATETIME   NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS monitor_rule_history (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  rule_id       VARCHAR(64)  NOT NULL DEFAULT '',
  rule_type     VARCHAR(64)  NOT NULL DEFAULT '',
  content       VARCHAR(512) NOT NULL DEFAULT '',
  handle_status VARCHAR(32)  NOT NULL DEFAULT '未处理',
  trigger_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_status (handle_status)
) ENGINE=InnoDB;

-- ─── Tools ───────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS dig_history (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain      VARCHAR(255) NOT NULL DEFAULT '',
  record_type VARCHAR(16)  NOT NULL DEFAULT 'A',
  dns_server  VARCHAR(255) NOT NULL DEFAULT '',
  output      TEXT,
  queried_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_domain (domain),
  INDEX idx_queried (queried_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS global_test_history (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain      VARCHAR(255) NOT NULL DEFAULT '',
  record_type VARCHAR(16)  NOT NULL DEFAULT 'A',
  node_group  VARCHAR(32)  NOT NULL DEFAULT 'all',
  result_json LONGTEXT,
  tested_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_domain (domain),
  INDEX idx_tested (tested_at)
) ENGINE=InnoDB;

-- ─── Cluster ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS cluster_nodes (
  id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  node_id        VARCHAR(64)  NOT NULL DEFAULT '',
  name           VARCHAR(128) NOT NULL DEFAULT '',
  ip             VARCHAR(64)  NOT NULL DEFAULT '',
  ip_addresses   VARCHAR(512) NOT NULL DEFAULT '',
  url            VARCHAR(255) NOT NULL DEFAULT '',
  port           INT          NOT NULL DEFAULT 53,
  role           VARCHAR(32)  NOT NULL DEFAULT '从节点',
  zone           VARCHAR(64)  NOT NULL DEFAULT '',
  version        VARCHAR(32)  NOT NULL DEFAULT '',
  certificate    TEXT,
  joined_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  drained        TINYINT(1)   NOT NULL DEFAULT 0,
  INDEX idx_node_id (node_id),
  INDEX idx_role    (role)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS cluster_settings (
  id                     BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  initialized            TINYINT(1)   NOT NULL DEFAULT 0,
  cluster_domain         VARCHAR(255) NOT NULL DEFAULT '',
  primary_ips            VARCHAR(512) NOT NULL DEFAULT '',
  api_token              VARCHAR(255) NOT NULL DEFAULT '',
  heartbeat_interval_sec INT          NOT NULL DEFAULT 5,
  config_refresh_sec     INT          NOT NULL DEFAULT 60,
  config_version         VARCHAR(64)  NOT NULL DEFAULT '',
  updated_at             DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- cluster_config_sync stores per-node sync attempt facts ONLY. Node identity
-- columns (name/ip/role/zone) are intentionally NOT duplicated here; they
-- live in cluster_nodes and are JOINed at read time to keep a single source
-- of truth.
CREATE TABLE IF NOT EXISTS cluster_config_sync (
  id             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  node_id        BIGINT UNSIGNED NOT NULL DEFAULT 0,
  config_version VARCHAR(64)  NOT NULL DEFAULT '',
  master_version VARCHAR(64)  NOT NULL DEFAULT '',
  sync_status    VARCHAR(32)  NOT NULL DEFAULT '待同步',
  last_sync_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  diff_count     INT          NOT NULL DEFAULT 0,
  diff_detail    LONGTEXT,
  INDEX idx_node   (node_id),
  INDEX idx_status (sync_status)
) ENGINE=InnoDB;

-- ─── Setting ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS system_config (
  id                    BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  timezone              VARCHAR(32)  NOT NULL DEFAULT 'UTC+8',
  language              VARCHAR(16)  NOT NULL DEFAULT 'zh-CN',
  auto_backup           TINYINT(1)   NOT NULL DEFAULT 1,
  backup_cycle          VARCHAR(32)  NOT NULL DEFAULT '每日',
  backup_retention_days INT          NOT NULL DEFAULT 30,
  backup_storage_type   VARCHAR(16)  NOT NULL DEFAULT 'local',
  backup_storage_path   VARCHAR(512) NOT NULL DEFAULT '',
  dnssec_global         TINYINT(1)   NOT NULL DEFAULT 1,
  default_ttl           INT          NOT NULL DEFAULT 3600,
  negative_cache_ttl    INT          NOT NULL DEFAULT 300,
  ecs_enabled           TINYINT(1)   NOT NULL DEFAULT 0,
  doh_enabled           TINYINT(1)   NOT NULL DEFAULT 0,
  dot_enabled           TINYINT(1)   NOT NULL DEFAULT 0,
  -- TTL clamp & upstream / ECS / padding (added 2026-05).
  min_ttl                  INT          NOT NULL DEFAULT 0,
  max_ttl                  INT          NOT NULL DEFAULT 0,
  upstream_protocol_order  VARCHAR(64)  NOT NULL DEFAULT 'udp,tcp',
  upstream_timeout_ms      INT          NOT NULL DEFAULT 2000,
  -- DoHPreferGET: route DoH through HTTP GET (RFC 8484 §4.1.1) instead of
  -- POST. Useful in corporate networks where HTTP proxies strip POST
  -- application/dns-message bodies.
  doh_prefer_get           TINYINT(1)   NOT NULL DEFAULT 0,
  ecs_prefix_v4            INT          NOT NULL DEFAULT 24,
  ecs_prefix_v6            INT          NOT NULL DEFAULT 56,
  dns_padding_enabled      TINYINT(1)   NOT NULL DEFAULT 0,
  dns_padding_block        INT          NOT NULL DEFAULT 128,
  login_timeout_minutes INT          NOT NULL DEFAULT 30,
  login_max_failures    INT          NOT NULL DEFAULT 5,
  login_lock_minutes    INT          NOT NULL DEFAULT 15,
  mfa_required          TINYINT(1)   NOT NULL DEFAULT 0,
  ip_whitelist          TEXT,
  -- Password & session policy (added 2026-05).
  pwd_min_length           INT          NOT NULL DEFAULT 8,
  pwd_require_upper        TINYINT(1)   NOT NULL DEFAULT 1,
  pwd_require_lower        TINYINT(1)   NOT NULL DEFAULT 1,
  pwd_require_digit        TINYINT(1)   NOT NULL DEFAULT 1,
  pwd_require_symbol       TINYINT(1)   NOT NULL DEFAULT 0,
  pwd_expire_days          INT          NOT NULL DEFAULT 0,
  max_concurrent_login     INT          NOT NULL DEFAULT 0,
  -- Soft-deadline (in days) for accepting JWTs minted before the
  -- MaxConcurrentLogin upgrade (no Sid claim). Past this, sid-less
  -- tokens are 401'd. 0 disables the deadline.
  session_legacy_grace_days INT         NOT NULL DEFAULT 7,
  -- DB connection pool (live-tunable; applied via db.ApplyPoolFromSystemConfig).
  db_max_open_conns        INT          NOT NULL DEFAULT 50,
  db_max_idle_conns        INT          NOT NULL DEFAULT 25,
  db_conn_max_lifetime_min INT          NOT NULL DEFAULT 10,
  db_conn_max_idle_min     INT          NOT NULL DEFAULT 5,
  -- NTP time-sync state (servers + last poll outcome).
  ntp_enabled              TINYINT(1)   NOT NULL DEFAULT 1,
  ntp_servers              TEXT,
  ntp_check_interval       INT          NOT NULL DEFAULT 300,
  ntp_last_sync            DATETIME     NULL,
  ntp_last_drift_ms        BIGINT       NOT NULL DEFAULT 0,
  ntp_last_error           VARCHAR(255) NOT NULL DEFAULT '',
  log_retention_days    INT          NOT NULL DEFAULT 90,
  log_level             VARCHAR(16)  NOT NULL DEFAULT 'INFO',
  log_export_format     VARCHAR(16)  NOT NULL DEFAULT 'csv',
  global_qps_threshold  INT          NOT NULL DEFAULT 10000,
  maintenance_enabled   TINYINT(1)   NOT NULL DEFAULT 0,
  maintenance_window    VARCHAR(64)  NOT NULL DEFAULT '',
  -- Branding columns (system_title / logo_url / theme_color) were
  -- dropped in the 2026-05 cleanup. The application no longer reads
  -- them, but existing deployments may keep the columns harmlessly.
  updated_at            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS backups (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  backup_id    VARCHAR(64)  NOT NULL UNIQUE,
  backup_scope JSON         NOT NULL,
  backup_time  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  file_size    VARCHAR(32)  NOT NULL DEFAULT '',
  format       VARCHAR(16)  NOT NULL DEFAULT 'JSON',
  file_name    VARCHAR(255) NOT NULL DEFAULT ''
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS notice_config (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  channel         VARCHAR(32)  NOT NULL UNIQUE,
  enabled         TINYINT(1)   NOT NULL DEFAULT 0,
  config_json     JSON         NOT NULL,
  updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS notice_templates (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  channel         VARCHAR(32)  NOT NULL UNIQUE,
  subject         VARCHAR(512) NOT NULL DEFAULT '',
  body            MEDIUMTEXT   NOT NULL,
  updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  updated_by      BIGINT UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB;

-- ─── Load Balance ────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS lb_groups (
  id                    BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name                  VARCHAR(128) NOT NULL DEFAULT '',
  algorithm             VARCHAR(32)  NOT NULL DEFAULT '轮询',
  health_check_interval INT          NOT NULL DEFAULT 10,
  status                VARCHAR(16)  NOT NULL DEFAULT '启用',
  created_at            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at            DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS lb_servers (
  id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  group_id     BIGINT UNSIGNED NOT NULL,
  name         VARCHAR(128) NOT NULL DEFAULT '',
  address      VARCHAR(255) NOT NULL DEFAULT '',
  port         INT          NOT NULL DEFAULT 53,
  protocol     VARCHAR(16)  NOT NULL DEFAULT 'UDP',
  weight       INT          NOT NULL DEFAULT 1,
  max_conns    INT          NOT NULL DEFAULT 500,
  latency      INT          NOT NULL DEFAULT 0,
  success_rate DOUBLE       NOT NULL DEFAULT 0,
  status       VARCHAR(16)  NOT NULL DEFAULT '检测中',
  enabled      TINYINT(1)   NOT NULL DEFAULT 1,
  -- Most-recent probe failure reason; empty when last probe succeeded.
  -- Lets the LB management UI surface "TLS handshake failed" /
  -- "HTTP 403" / "i/o timeout" without operators tailing server logs.
  last_error   VARCHAR(255) NOT NULL DEFAULT '',
  created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_group (group_id)
) ENGINE=InnoDB;

-- ─── Alert Subscribe ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS alert_subscribe_rules (
  id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name            VARCHAR(128) NOT NULL DEFAULT '',
  metric          VARCHAR(32)  NOT NULL DEFAULT 'QPS',
  operator        VARCHAR(4)   NOT NULL DEFAULT '>',
  threshold       DOUBLE       NOT NULL DEFAULT 0,
  unit            VARCHAR(16)  NOT NULL DEFAULT '',
  duration        INT          NOT NULL DEFAULT 5,
  channels        VARCHAR(255) NOT NULL DEFAULT '',
  contact_group_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
  silence_minutes INT          NOT NULL DEFAULT 0,
  status          VARCHAR(16)  NOT NULL DEFAULT '启用',
  trigger_count   INT          NOT NULL DEFAULT 0,
  last_triggered  VARCHAR(32)  NOT NULL DEFAULT '—',
  created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_contact_group (contact_group_id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS alert_contact_groups (
  id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name             VARCHAR(128) NOT NULL DEFAULT '',
  member_user_ids  TEXT,
  remark           VARCHAR(255) NOT NULL DEFAULT '',
  status           VARCHAR(16)  NOT NULL DEFAULT '启用',
  created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ─── Seed: admin user (password: admin123) ───────────────────────────────────
INSERT IGNORE INTO roles (id, name, remark) VALUES
  (1, '超级管理员', '全模块全权限'),
  (2, '运维管理员', '运维与配置管理'),
  (3, '只读用户',   '仅查看权限');

-- bcrypt hash of "admin123"  (cost=10, generated by golang.org/x/crypto/bcrypt)
INSERT IGNORE INTO users (id, username, password, real_name, role_id, role_name, status)
VALUES (1, 'admin', '$2a$10$dwkfJpWhDfAf89sYRCG0MuF3V1Py.WSXKbLTuT2mmmmB9mSgbXtmW', '系统管理员', 1, '超级管理员', '启用');

INSERT IGNORE INTO system_config (id) VALUES (1);
INSERT IGNORE INTO ddos_global (id) VALUES (1);
INSERT IGNORE INTO cache_global_strategy (id) VALUES (1);
INSERT IGNORE INTO monitor_qps_rule (id) VALUES (1);
INSERT IGNORE INTO monitor_nxdomain_rule (id) VALUES (1);
INSERT IGNORE INTO monitor_latency_rule (id) VALUES (1);
INSERT IGNORE INTO monitor_cache_hit_rule (id) VALUES (1);
INSERT IGNORE INTO forward_global (id) VALUES (1);

DROP PROCEDURE IF EXISTS drop_col_if_exists;
DELIMITER $$
CREATE PROCEDURE drop_col_if_exists(IN tbl VARCHAR(64), IN col VARCHAR(64))
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.COLUMNS
             WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = tbl AND COLUMN_NAME = col) THEN
    SET @s = CONCAT('ALTER TABLE ', tbl, ' DROP COLUMN ', col);
    PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;
  END IF;
END$$
DELIMITER ;

CALL drop_col_if_exists('cluster_nodes', 'status');
CALL drop_col_if_exists('cluster_nodes', 'state');
CALL drop_col_if_exists('cluster_nodes', 'cpu_usage');
CALL drop_col_if_exists('cluster_nodes', 'mem_usage');
CALL drop_col_if_exists('cluster_nodes', 'qps');
CALL drop_col_if_exists('cluster_nodes', 'sync_lag');
CALL drop_col_if_exists('cluster_nodes', 'up_since');
CALL drop_col_if_exists('cluster_nodes', 'last_heartbeat');
CALL drop_col_if_exists('cluster_nodes', 'last_seen');

CALL drop_col_if_exists('cluster_config_sync', 'node_name');
CALL drop_col_if_exists('cluster_config_sync', 'node_ip');
CALL drop_col_if_exists('cluster_config_sync', 'node_role');
CALL drop_col_if_exists('cluster_config_sync', 'zone');

DROP PROCEDURE IF EXISTS drop_col_if_exists;

DROP PROCEDURE IF EXISTS add_col_if_missing;
DELIMITER $$
CREATE PROCEDURE add_col_if_missing(IN tbl VARCHAR(64), IN col VARCHAR(64), IN col_def TEXT)
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.COLUMNS
                 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = tbl AND COLUMN_NAME = col) THEN
    SET @s = CONCAT('ALTER TABLE ', tbl, ' ADD COLUMN ', col, ' ', col_def);
    PREPARE stmt FROM @s; EXECUTE stmt; DEALLOCATE PREPARE stmt;
  END IF;
END$$
DELIMITER ;

CALL add_col_if_missing('zones', 'transport',      "VARCHAR(16) NOT NULL DEFAULT 'tcp'");
CALL add_col_if_missing('zones', 'axfr_insecure',  "TINYINT(1)  NOT NULL DEFAULT 0");
CALL add_col_if_missing('zones', 'last_synced_at', "DATETIME    NULL DEFAULT NULL");

DROP PROCEDURE IF EXISTS add_col_if_missing;

UPDATE zones SET status = '正常' WHERE status = '启用';
