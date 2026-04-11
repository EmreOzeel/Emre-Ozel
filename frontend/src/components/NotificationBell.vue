<template>
  <el-popover
    placement="top-start"
    :width="360"
    trigger="click"
    popper-class="notification-popover"
    @show="onOpen"
  >
    <template #reference>
      <el-tooltip content="Notifications" placement="right">
        <el-badge
          :value="unreadCount"
          :hidden="unreadCount === 0"
          :max="99"
          class="bell-badge"
        >
          <el-button link class="bell-button">
            <el-icon size="18"><Bell /></el-icon>
          </el-button>
        </el-badge>
      </el-tooltip>
    </template>

    <div class="notification-panel">
      <div class="notification-header">
        <span class="title">Notifications</span>
        <el-button
          v-if="notifications.length > 0 && unreadCount > 0"
          link
          size="small"
          @click="markAllRead"
        >
          Mark all read
        </el-button>
      </div>

      <div v-if="loading && notifications.length === 0" class="empty">
        Loading…
      </div>
      <div v-else-if="notifications.length === 0" class="empty">
        You have no notifications.
      </div>

      <ul v-else class="notification-list">
        <li
          v-for="n in notifications"
          :key="n.id"
          class="notification-item"
          :class="{ unread: !n.read_at }"
          @click="openNotification(n)"
        >
          <div class="row">
            <el-tag
              :type="typeTagType(n.type)"
              size="small"
              effect="dark"
              class="type-tag"
            >
              {{ typeLabel(n.type) }}
            </el-tag>
            <span class="when">{{ formatWhen(n.created_at) }}</span>
          </div>
          <div class="message">{{ n.message }}</div>
          <div v-if="n.actor_username" class="meta">
            by @{{ n.actor_username }}
          </div>
        </li>
      </ul>
    </div>
  </el-popover>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Bell } from '@element-plus/icons-vue'
import api from '@/api'
import type { NotificationItem, NotificationType } from '@/types/analysis'

const router = useRouter()

const notifications = ref<NotificationItem[]>([])
const unreadCount = ref(0)
const loading = ref(false)

// Poll every 30 s.
const POLL_MS = 30_000
let pollTimer: number | null = null

async function fetchUnreadCount() {
  try {
    const res = await api.get('/notifications/unread-count')
    unreadCount.value = res.data?.unread ?? 0
  } catch {
    // silent — keep last value
  }
}

async function fetchNotifications() {
  loading.value = true
  try {
    const res = await api.get('/notifications', { params: { limit: 20 } })
    notifications.value = res.data ?? []
  } catch {
    notifications.value = []
  } finally {
    loading.value = false
  }
}

async function onOpen() {
  // Refresh both on every open to show latest items.
  await fetchNotifications()
  await fetchUnreadCount()
}

async function markAllRead() {
  try {
    await api.post('/notifications/mark-read', { all: true })
    await fetchNotifications()
    await fetchUnreadCount()
  } catch {
    // silent
  }
}

async function openNotification(n: NotificationItem) {
  // Mark the single notification as read (best-effort)
  if (!n.read_at) {
    try {
      await api.post('/notifications/mark-read', { ids: [n.id] })
    } catch {
      // silent
    }
  }
  if (n.analysis_id) {
    router.push(`/analysis/${n.analysis_id}`)
  }
  await fetchUnreadCount()
  // Update local state so the badge drops immediately without another round-trip.
  if (!n.read_at) {
    n.read_at = new Date().toISOString()
  }
}

function typeLabel(t: NotificationType): string {
  switch (t) {
    case 'assignment':      return 'Assigned'
    case 'review_required': return 'Needs Review'
    case 'resolved':        return 'Resolved'
    case 'feedback_alert':  return 'Feedback'
    case 'mention':         return 'Mention'
    default:                return t
  }
}

function typeTagType(t: NotificationType): string {
  switch (t) {
    case 'assignment':      return 'info'
    case 'review_required': return 'danger'
    case 'resolved':        return 'success'
    case 'feedback_alert':  return 'warning'
    case 'mention':         return 'info'
    default:                return ''
  }
}

function formatWhen(iso: string | null): string {
  if (!iso) return ''
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return ''
  const diff = Date.now() - t
  const m = Math.floor(diff / 60_000)
  if (m < 1)    return 'just now'
  if (m < 60)   return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24)   return `${h}h ago`
  const d = Math.floor(h / 24)
  if (d < 30)   return `${d}d ago`
  return new Date(iso).toLocaleDateString()
}

onMounted(() => {
  fetchUnreadCount()
  pollTimer = window.setInterval(fetchUnreadCount, POLL_MS)
})

onBeforeUnmount(() => {
  if (pollTimer !== null) {
    window.clearInterval(pollTimer)
    pollTimer = null
  }
})
</script>

<style scoped>
.bell-button {
  color: #c8cdd6 !important;
  padding: 6px;
}
.bell-button:hover {
  color: #409EFF !important;
}
.bell-badge :deep(.el-badge__content) {
  font-size: 10px;
  padding: 0 5px;
  height: 16px;
  line-height: 16px;
}

.notification-panel {
  max-height: 440px;
  overflow-y: auto;
}
.notification-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 4px 4px 10px;
  border-bottom: 1px solid #ebeef5;
  margin-bottom: 6px;
}
.notification-header .title {
  font-weight: 600;
  font-size: 14px;
  color: #303133;
}
.empty {
  padding: 20px 8px;
  text-align: center;
  color: #909399;
  font-size: 13px;
}
.notification-list {
  list-style: none;
  padding: 0;
  margin: 0;
}
.notification-item {
  padding: 10px 8px;
  border-radius: 6px;
  cursor: pointer;
  border: 1px solid transparent;
  transition: background 0.15s;
}
.notification-item:hover {
  background: #f5f7fa;
}
.notification-item.unread {
  background: #ecf5ff;
  border-color: #d9ecff;
}
.notification-item .row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 4px;
}
.notification-item .type-tag {
  font-size: 11px;
}
.notification-item .when {
  font-size: 11px;
  color: #909399;
}
.notification-item .message {
  font-size: 13px;
  color: #303133;
  line-height: 1.4;
}
.notification-item .meta {
  font-size: 11px;
  color: #909399;
  margin-top: 2px;
}
</style>
