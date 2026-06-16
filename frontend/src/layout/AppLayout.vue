<script setup lang="ts">
/**
 * Application chrome — re-built to align with the Modern-DHCP frontend
 * so the two products share a single visual identity:
 *
 *   ┌──────────────────────────────────────────────────────────────┐
 *   │  app-header (56px, white, sticky)                            │
 *   │  ├ brand + sidebar-toggle + breadcrumb                       │
 *   │  └ action-groups (bell, user dropdown), separated by         │
 *   │    left-border vertical dividers                             │
 *   ├──────────┬──────────────────────────────────────────────────┤
 *   │  sider   │  view-wrapper (16px padding)                      │
 *   │  240/64  │   <router-view/>                                  │
 *   │  #001529 │  ─────────────────────────────────────────────── │
 *   │  Ant Pro │  layout-footer (40px slogan + version)           │
 *   └──────────┴──────────────────────────────────────────────────┘
 *
 * Why a custom layout instead of <el-container>: the DHCP reference
 * uses plain divs because it gives precise control over the dark
 * sider's background continuity (no Element border-radius leaking
 * through), and easier sticky-header behaviour. We do the same.
 *
 * Compared to the previous DNS layout (blue 64px header, light
 * sidebar) this rewrite changes:
 *   - header background from --app-accent to white
 *   - sidebar background from --app-bg-secondary to #001529
 *   - removes the redundant page title under the breadcrumb (DHCP
 *     doesn't carry it; pages already have their own .page-header)
 *   - moves the brand mark from sidebar-top to header-left
 *   - adds a bottom footer with slogan + version
 */
import { computed, onBeforeUnmount, onMounted, ref, type Component } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Fold, Expand, Odometer, Connection, SwitchFilled, Lock, Monitor, Tools, Cpu, Setting } from '@element-plus/icons-vue'
import { useAppStore } from '../stores/app'
import { useAlertStore } from '../stores/alert'
import BrandLogo from '../components/BrandLogo.vue'
import { formatDateTime } from '../utils/datetime'

const route = useRoute()
const router = useRouter()
const { t } = useI18n()
const appStore = useAppStore()
const alertStore = useAlertStore()

// Sidebar icons — explicitly imported because <component :is="string">
// dynamic resolution can't be statically analysed by unplugin-vue-components.
const menuIcons: Record<string, Component> = {
  Odometer,
  Connection,
  SwitchFilled,
  Lock,
  Monitor,
  Tools,
  Cpu,
  Setting,
}

const breadcrumbs = computed(() =>
  route.matched.filter((item) => item.meta?.titleKey),
)

const activeRootMenu = computed(() => {
  const currentPath =
    typeof route.meta.menuPath === 'string' ? route.meta.menuPath : route.path
  return (
    appStore.menuTree.find(
      (group) =>
        currentPath === group.path || currentPath.startsWith(`${group.path}/`),
    )?.path || ''
  )
})

const openedMenus = computed(() =>
  appStore.collapsed || !activeRootMenu.value ? [] : [activeRootMenu.value],
)

const asideWidth = computed(() =>
  appStore.collapsed ? 'var(--app-aside-collapse-width)' : 'var(--app-aside-width)',
)

// — Notification bell —
const bellPopoverVisible = ref(false)
const unreadCount = computed(() => alertStore.unreadCount)
const hasAlertEvents = computed(() => unreadCount.value > 0)
const bellMarkAllRead = () => alertStore.markAllRead()
const bellMarkRead = (id: number) => alertStore.markRead(id)
const formatAlertTime = (value: string) => formatDateTime(value)
const goAlerts = () => {
  bellPopoverVisible.value = false
  router.push('/monitor/alert-notice')
}
alertStore.fetchAlerts()
let bellPollingTimer: number | null = null

onMounted(() => {
  bellPollingTimer = window.setInterval(() => {
    void alertStore.fetchAlerts()
  }, 30000)
})

onBeforeUnmount(() => {
  if (bellPollingTimer !== null) {
    window.clearInterval(bellPollingTimer)
    bellPollingTimer = null
  }
})

const handleCommand = (command: string) => {
  if (command === 'logout') {
    appStore.logout()
    ElMessage.success(t('layout.loggedOut'))
    router.replace('/login')
    return
  }
  if (command === 'profile') {
    router.push('/profile')
  }
}

const goHome = () => {
  router.push('/dashboard/overview')
}

// Footer slogan and version come from i18n; translations should
// include the version segment in their own locale style. We append
// nothing here so the string stays clean across languages.
const APP_VERSION = 'v1.6.0'
const footerSlogan = computed(() => {
  return `${t('layout.footerSlogan')} | ${t('layout.version')} ${APP_VERSION}`
})
</script>

<template>
  <div class="app-layout">
    <!-- ═══════════════════ Header ═══════════════════ -->
    <header class="app-header">
      <div class="header-left">
        <div class="brand" @click="goHome">
          <!-- BrandLogo paints its own dark rounded backdrop via :solid,
               so it sits cleanly on the white header. -->
          <BrandLogo :size="28" solid class="brand-logo" />
          <span class="brand-name">Modern DNS</span>
        </div>

        <el-button text class="icon-btn" :title="$t('layout.toggleSidebar')" @click="appStore.toggleCollapse()">
          <el-icon><Fold v-if="!appStore.collapsed" /><Expand v-else /></el-icon>
        </el-button>

        <el-breadcrumb v-if="breadcrumbs.length" separator="/" class="breadcrumb">
          <el-breadcrumb-item v-for="item in breadcrumbs" :key="item.path">
            {{ $t('menu.' + item.meta.titleKey) }}
          </el-breadcrumb-item>
        </el-breadcrumb>
      </div>

      <div class="header-right">
        <!-- Bell action-group -->
        <div class="action-group">
          <el-popover
            v-model:visible="bellPopoverVisible"
            placement="bottom-end"
            :width="340"
            trigger="click"
            popper-class="alert-popover"
          >
            <template #reference>
              <div class="bell-btn" :class="{ 'has-unread': hasAlertEvents }">
                <el-badge :is-dot="hasAlertEvents" :hidden="!hasAlertEvents">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="20" height="20"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
                </el-badge>
              </div>
            </template>
            <div class="alert-pop">
              <div class="alert-pop-header">
                <span class="alert-pop-title">{{ $t('monitor.alertNotice') }}</span>
                <el-button v-if="unreadCount > 0" link size="small" @click="bellMarkAllRead">{{ $t('common.markAllRead') }}</el-button>
              </div>
              <div class="alert-pop-list">
                <template v-if="alertStore.notices.length">
                  <div
                    v-for="item in alertStore.notices.slice(0, 8)"
                    :key="item.id"
                    class="alert-pop-item"
                    :class="{ 'is-read': item.read }"
                    @click="bellMarkRead(item.id)"
                  >
                    <span class="alert-dot" :class="'alert-dot--' + item.level"></span>
                    <div class="alert-pop-body">
                      <span class="alert-pop-msg">{{ item.content }}</span>
                      <span class="alert-pop-time">{{ formatAlertTime(item.triggeredAt) }}</span>
                    </div>
                  </div>
                </template>
                <div v-else class="alert-pop-empty">{{ $t('common.noData') }}</div>
              </div>
              <div class="alert-pop-footer">
                <el-button link size="small" @click="goAlerts">{{ $t('monitor.alertNotice') }} →</el-button>
              </div>
            </div>
          </el-popover>
        </div>

        <!-- User action-group -->
        <div class="action-group">
          <el-dropdown trigger="click" @command="handleCommand">
            <span class="user-info">
              <el-avatar :size="30">{{ appStore.user.name.slice(0, 1) }}</el-avatar>
              <div class="user-copy">
                <span class="username">{{ appStore.user.name }}</span>
                <span class="userrole">{{ appStore.user.role }}</span>
              </div>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="profile">{{ t('layout.profile') }}</el-dropdown-item>
                <el-dropdown-item divided command="logout">{{ t('layout.logout') }}</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </div>
    </header>

    <!-- ═══════════════════ Body ═══════════════════ -->
    <div class="app-body">
      <aside class="layout-aside" :style="{ width: asideWidth }">
        <el-scrollbar class="aside-scroll">
          <el-menu
            :key="`${activeRootMenu}-${appStore.collapsed ? 'collapsed' : 'expanded'}`"
            :default-active="appStore.activeMenu || route.path"
            :default-openeds="openedMenus"
            :collapse="appStore.collapsed"
            :collapse-transition="false"
            :unique-opened="true"
            mode="vertical"
            class="aside-menu"
            router
          >
            <el-sub-menu
              v-for="group in appStore.menuTree"
              :key="group.path"
              :index="group.path"
              :show-timeout="300"
              :hide-timeout="300"
            >
              <template #title>
                <el-icon><component :is="menuIcons[group.icon]" /></el-icon>
                <span>{{ $t('menu.' + group.titleKey) }}</span>
              </template>
              <el-menu-item
                v-for="item in group.children"
                :key="item.path"
                :index="item.path"
              >
                {{ $t('menu.' + item.titleKey) }}
              </el-menu-item>
            </el-sub-menu>
          </el-menu>
        </el-scrollbar>
      </aside>

      <main class="layout-main">
        <div class="view-wrapper">
          <div v-show="appStore.loading" class="route-loading">
            <el-icon class="is-loading"><Loading /></el-icon>
            <span>{{ t('layout.pageLoading') }}</span>
          </div>
          <router-view v-slot="{ Component }">
            <keep-alive :max="12">
              <component :is="Component" :key="route.name" />
            </keep-alive>
          </router-view>
        </div>
        <footer class="layout-footer">{{ footerSlogan }}</footer>
      </main>
    </div>
  </div>
</template>

<style scoped>
.app-layout {
  width: 100vw;
  height: 100vh;
  display: flex;
  flex-direction: column;
  background: var(--app-bg);
  color: var(--el-text-color-primary);
}

/* ═════════ Header ═════════ */
.app-header {
  height: var(--app-header-height);
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
  border-bottom: 1px solid var(--app-border);
  background: #ffffff;
  position: sticky;
  top: 0;
  z-index: 10;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 0;
}

.brand {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  user-select: none;
}

.brand-logo {
  flex-shrink: 0;
}

.brand-name {
  font-size: 16px;
  font-weight: 700;
  color: var(--app-text-main);
  white-space: nowrap;
}

.icon-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 4px 6px;
  color: var(--app-text-regular);
}

.icon-btn :deep(svg) {
  width: 18px;
  height: 18px;
}

.breadcrumb :deep(.el-breadcrumb__inner) {
  color: var(--app-text-regular);
  font-weight: 400;
}

.breadcrumb :deep(.el-breadcrumb__item:last-child .el-breadcrumb__inner) {
  color: var(--app-text-main);
  font-weight: 500;
}

.header-right {
  display: flex;
  align-items: center;
}

/* DHCP idiom — successive action-groups are visually separated by a
   1px vertical divider on the *left* of every group except the first.
   Implemented as an inset border so the divider lines up with the
   group's content box rather than the gap. */
.action-group {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 0 12px;
  height: 36px;
}
.action-group + .action-group {
  border-left: 1px solid var(--app-border);
}

/* — Bell button — */
.bell-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: 8px;
  cursor: pointer;
  color: var(--app-text-regular);
  transition: background 0.15s, color 0.15s;
}
.bell-btn:hover {
  background: var(--app-bg);
  color: var(--app-accent);
}
.bell-btn.has-unread {
  color: var(--app-accent);
}
.bell-btn :deep(.el-badge__content) {
  font-size: 10px;
  height: 16px;
  line-height: 16px;
  padding: 0 4px;
  min-width: 16px;
  transform: translateY(-4px) translateX(4px);
}

/* — User dropdown trigger — */
.user-info {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  padding: 4px 8px;
  border-radius: 8px;
  transition: background 0.15s;
}
.user-info:hover {
  background: var(--app-bg);
}
.user-copy {
  display: flex;
  flex-direction: column;
  line-height: 1.2;
}
.username {
  font-size: 13px;
  font-weight: 600;
  color: var(--app-text-main);
}
.userrole {
  font-size: 11px;
  color: var(--app-text-regular);
}

/* ═════════ Body ═════════ */
.app-body {
  flex: 1;
  display: flex;
  min-height: 0;
}

/* ═════════ Aside (dark) ═════════ */
.layout-aside {
  flex-shrink: 0;
  background: var(--app-sider-bg);
  color: var(--app-sider-text);
  border-right: 1px solid var(--app-sider-border);
  transition: width 0.2s ease;
  overflow: hidden;
}

.aside-scroll {
  height: calc(100vh - var(--app-header-height));
}
.aside-scroll :deep(.el-scrollbar__wrap) {
  scrollbar-width: none;
}
.aside-scroll :deep(.el-scrollbar__wrap::-webkit-scrollbar) {
  width: 6px;
}
.aside-scroll :deep(.el-scrollbar__wrap::-webkit-scrollbar-thumb) {
  background: rgba(255, 255, 255, 0.16);
  border-radius: 8px;
}
.aside-scroll :deep(.el-scrollbar__bar) {
  width: 0;
}

.aside-menu {
  padding: 8px 0;
  background: transparent;
  border-right: none;
  --el-menu-bg-color: transparent;
  --el-menu-text-color: var(--app-sider-text);
  --el-menu-hover-bg-color: var(--app-sider-hover-bg);
  --el-menu-active-color: var(--app-sider-active-text);
  --el-menu-icon-width: 22px;
  font-size: 14px;
}

:deep(.el-menu--collapse) {
  width: var(--app-aside-collapse-width);
}

:deep(.aside-menu .el-sub-menu__title),
:deep(.aside-menu .el-menu-item) {
  height: 44px;
  line-height: 44px;
  color: var(--app-sider-text);
  font-size: 14px;
}

:deep(.aside-menu .el-menu-item.is-active) {
  background-color: var(--app-sider-active-bg) !important;
  color: var(--app-sider-active-text) !important;
}

:deep(.aside-menu .el-menu-item:hover),
:deep(.aside-menu .el-sub-menu__title:hover) {
  background-color: var(--app-sider-hover-bg) !important;
  color: #ffffff !important;
}

:deep(.aside-menu .el-sub-menu .el-menu-item) {
  padding-left: 40px !important;
  font-size: 13px;
}

:deep(.aside-menu .el-sub-menu__icon-arrow) {
  right: 16px;
  color: var(--app-sider-text-muted);
}

/* When the menu is collapsed, Element renders submenus as a popup —
   override its default light background so the popup matches the
   dark sidebar instead of flashing to white on hover. */
:global(.el-menu--popup) {
  background: var(--app-sider-bg, #001529) !important;
  border-color: var(--app-sider-border) !important;
}
:global(.el-menu--popup .el-menu-item),
:global(.el-menu--popup .el-sub-menu__title) {
  color: var(--app-sider-text) !important;
}
:global(.el-menu--popup .el-menu-item.is-active) {
  background: var(--app-sider-active-bg) !important;
  color: #ffffff !important;
}
:global(.el-menu--popup .el-menu-item:hover),
:global(.el-menu--popup .el-sub-menu__title:hover) {
  background: var(--app-sider-hover-bg) !important;
  color: #ffffff !important;
}

/* ═════════ Main ═════════ */
.layout-main {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  background: var(--app-bg);
}

.view-wrapper {
  position: relative;
  flex: 1;
  padding: 16px;
  overflow: auto;
}

.route-loading {
  position: absolute;
  inset: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  background: rgba(245, 247, 250, 0.85);
  font-size: 14px;
  color: var(--app-text-regular);
}

.layout-footer {
  height: 40px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  border-top: 1px solid var(--app-border);
  font-size: 12px;
  color: var(--app-text-regular);
  background: var(--app-bg);
}

/* ═════════ Alert popover (preserved from previous layout) ═════════ */
.alert-pop { padding: 0; }
.alert-pop-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 14px 8px;
  border-bottom: 1px solid #f0f0f0;
}
.alert-pop-title { font-size: 14px; font-weight: 700; color: #1d2129; }
.alert-pop-list { max-height: 280px; overflow-y: auto; }
.alert-pop-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 14px;
  cursor: pointer;
  border-bottom: 1px solid #f5f5f5;
  transition: background 0.15s;
}
.alert-pop-item:hover { background: #f8faff; }
.alert-pop-item.is-read { opacity: 0.5; }
.alert-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
  margin-top: 5px;
}
.alert-dot--critical { background: var(--app-danger); }
.alert-dot--warning  { background: var(--app-warning); }
.alert-dot--info     { background: var(--app-accent); }
.alert-pop-body { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.alert-pop-msg  { font-size: 13px; color: #1d2129; line-height: 1.4; word-break: break-all; }
.alert-pop-time { font-size: 11px; color: #94a3b8; }
.alert-pop-empty { padding: 24px 14px; text-align: center; font-size: 13px; color: #94a3b8; }
.alert-pop-footer { padding: 8px 14px; text-align: center; border-top: 1px solid #f0f0f0; }

/* ═════════ Responsive ═════════ */
@media (max-width: 1024px) {
  .layout-aside {
    position: fixed;
    left: 0;
    top: var(--app-header-height);
    height: calc(100vh - var(--app-header-height));
    z-index: 9;
  }
  .userrole { display: none; }
}

@media (max-width: 768px) {
  .brand-name { display: none; }
  .breadcrumb { display: none; }
  .user-copy { display: none; }
}
</style>
