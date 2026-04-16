<template>
  <el-container class="layout">
    <!-- Sidebar -->
    <el-aside width="240px" class="sidebar">
      <div class="sidebar-logo">
        <el-icon size="28" color="#409EFF"><DataAnalysis /></el-icon>
        <span>PCAP Analyzer</span>
      </div>

      <el-menu
        :default-active="activeMenu"
        router
        background-color="#1a1a2e"
        text-color="#c8cdd6"
        active-text-color="#409EFF"
        class="sidebar-menu"
      >
        <el-menu-item index="/">
          <el-icon><HomeFilled /></el-icon>
          <span>Dashboard</span>
        </el-menu-item>
        <el-menu-item index="/work-queue">
          <el-icon><Files /></el-icon>
          <span>My Work</span>
        </el-menu-item>
        <el-menu-item index="/history">
          <el-icon><Tickets /></el-icon>
          <span>Analysis History</span>
        </el-menu-item>
        <el-menu-item index="/compare">
          <el-icon><ScaleToOriginal /></el-icon>
          <span>Compare</span>
        </el-menu-item>
        <el-menu-item index="/suppressions">
          <el-icon><CircleClose /></el-icon>
          <span>Suppressions</span>
        </el-menu-item>
        <el-menu-item index="/calibration">
          <el-icon><TrendCharts /></el-icon>
          <span>Calibration</span>
        </el-menu-item>
        <el-menu-item index="/monitoring">
          <el-icon><AlarmClock /></el-icon>
          <span>Monitoring</span>
        </el-menu-item>
        <el-menu-item index="/live-events">
          <el-icon><Monitor /></el-icon>
          <span>Live Events</span>
        </el-menu-item>
        <el-menu-item index="/live-flows">
          <el-icon><Connection /></el-icon>
          <span>Live Flows</span>
        </el-menu-item>
        <el-menu-item index="/live-incidents">
          <el-icon><Warning /></el-icon>
          <span>Incidents</span>
        </el-menu-item>
        <el-menu-item index="/correlation-rules">
          <el-icon><SetUp /></el-icon>
          <span>Correlation Rules</span>
        </el-menu-item>
        <el-menu-item index="/threat-intel">
          <el-icon><Aim /></el-icon>
          <span>Threat Intel</span>
        </el-menu-item>
        <el-menu-item index="/geo-map">
          <el-icon><MapLocation /></el-icon>
          <span>Geo Map</span>
        </el-menu-item>
      </el-menu>

      <div class="sidebar-footer">
        <div class="user-info">
          <el-avatar :size="32" class="user-avatar">
            {{ auth.user?.username?.charAt(0)?.toUpperCase() || 'U' }}
          </el-avatar>
          <span class="username">{{ auth.user?.username || 'User' }}</span>
        </div>
        <div class="footer-actions">
          <NotificationBell />
          <el-tooltip content="Sign Out" placement="right">
            <el-button
              link
              class="logout-btn"
              @click="handleLogout"
            >
              <el-icon size="18"><SwitchButton /></el-icon>
            </el-button>
          </el-tooltip>
        </div>
      </div>
    </el-aside>

    <!-- Main content -->
    <el-container>
      <el-main class="main-content">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAuthStore } from '../stores/auth'
import NotificationBell from '../components/NotificationBell.vue'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()

const activeMenu = computed(() => {
  if (route.path.startsWith('/analysis')) return '/history'
  return route.path
})

function handleLogout() {
  auth.logout()
  router.push('/login')
}
</script>

<style scoped>
.layout {
  min-height: 100vh;
}

.sidebar {
  background: #1a1a2e;
  display: flex;
  flex-direction: column;
  position: fixed;
  height: 100vh;
  z-index: 100;
  box-shadow: 4px 0 12px rgba(0,0,0,0.15);
}

.sidebar-logo {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 24px 20px;
  border-bottom: 1px solid rgba(255,255,255,0.08);
}

.sidebar-logo span {
  font-size: 16px;
  font-weight: 700;
  color: white;
  letter-spacing: 0.3px;
}

.sidebar-menu {
  flex: 1;
  border-right: none;
  padding: 12px 0;
}

.sidebar-menu :deep(.el-menu-item) {
  height: 48px;
  line-height: 48px;
  margin: 4px 8px;
  border-radius: 8px;
  font-size: 14px;
}

.sidebar-menu :deep(.el-menu-item.is-active) {
  background: rgba(64, 158, 255, 0.15) !important;
}

.sidebar-menu :deep(.el-menu-item:hover) {
  background: rgba(255, 255, 255, 0.06) !important;
}

.sidebar-footer {
  padding: 16px 20px;
  border-top: 1px solid rgba(255,255,255,0.08);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.user-info {
  display: flex;
  align-items: center;
  gap: 10px;
}

.user-avatar {
  background: #409EFF;
  color: white;
  font-weight: 600;
  font-size: 14px;
  flex-shrink: 0;
}

.username {
  color: #c8cdd6;
  font-size: 13px;
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 120px;
}

.footer-actions {
  display: flex;
  align-items: center;
  gap: 4px;
}

.logout-btn {
  color: #606266 !important;
}

.logout-btn:hover {
  color: #f56c6c !important;
}

.main-content {
  margin-left: 240px;
  min-height: 100vh;
  background: #f0f2f5;
  padding: 24px;
}
</style>
