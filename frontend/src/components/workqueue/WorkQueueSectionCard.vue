<template>
  <el-card
    class="wq-section"
    shadow="never"
    :class="[`wq-section-${section.key}`]"
  >
    <template #header>
      <div class="section-header">
        <div class="section-title">
          <el-icon size="18" :color="accentColor">
            <component :is="sectionIcon" />
          </el-icon>
          <span class="label">{{ section.label }}</span>
          <el-badge
            v-if="section.count > 0"
            :value="section.count"
            :type="badgeType"
            class="count-badge"
          />
        </div>
        <span v-if="section.count === 0" class="empty-note">
          Nothing here
        </span>
      </div>
    </template>

    <div v-if="section.count === 0" class="section-empty">
      —
    </div>

    <ul v-else class="item-list">
      <li
        v-for="item in section.items"
        :key="item.analysis_id"
        class="item-row"
        @click="$emit('open', item)"
      >
        <div class="row-main">
          <div class="row-top">
            <span class="filename" :title="item.filename">{{ item.filename }}</span>
            <el-tag
              :type="workflowTag(item.workflow_state)"
              size="small"
              effect="light"
              class="state-tag"
            >
              {{ workflowLabel(item.workflow_state) }}
            </el-tag>
            <el-tag
              v-if="item.latest_feedback_verdict === 'incorrect'"
              type="warning"
              size="small"
              effect="dark"
              class="alert-tag"
            >
              Incorrect feedback
            </el-tag>
            <el-tag
              v-if="showNotifTag(item)"
              size="small"
              effect="plain"
              class="notif-tag"
            >
              {{ notifTypeLabel(item.latest_notification_type) }}
            </el-tag>
          </div>
          <div class="row-meta">
            <span v-if="item.owner_username" class="meta-chunk">
              Owner: <strong>@{{ item.owner_username }}</strong>
            </span>
            <span v-if="item.assignee_username" class="meta-chunk">
              Assignee: <strong>@{{ item.assignee_username }}</strong>
            </span>
            <span v-if="item.critical_count != null && item.critical_count > 0" class="meta-chunk">
              <el-tag type="danger" size="small" effect="light">
                {{ item.critical_count }} critical
              </el-tag>
            </span>
            <span v-else-if="item.issue_count != null && item.issue_count > 0" class="meta-chunk">
              {{ item.issue_count }} issue<span v-if="item.issue_count !== 1">s</span>
            </span>
            <span v-if="item.primary_impairment" class="meta-chunk">
              {{ formatImpairment(item.primary_impairment) }}
              <span v-if="item.path_confidence_score != null">
                · {{ item.path_confidence_score }}% conf
              </span>
            </span>
            <span class="meta-chunk meta-when">
              {{ formatWhen(latestTimestamp(item)) }}
            </span>
          </div>
        </div>
        <el-icon color="#c0c4cc"><ArrowRight /></el-icon>
      </li>
    </ul>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import {
  ArrowRight,
  Warning,
  Bell,
  User,
  Document,
  Loading,
  CircleCheck,
} from '@element-plus/icons-vue'
import type {
  NotificationType,
  WorkQueueItem,
  WorkQueueSection,
  WorkflowState,
} from '@/types/analysis'

const props = defineProps<{
  section: WorkQueueSection
}>()

defineEmits<{
  (e: 'open', item: WorkQueueItem): void
}>()

const accentColor = computed(() => {
  switch (props.section.key) {
    case 'needs_review':           return '#f56c6c'
    case 'recent_feedback_alerts': return '#e6a23c'
    case 'assigned_to_me':         return '#409eff'
    case 'new_analyses':           return '#909399'
    case 'unresolved_owned':       return '#409eff'
    case 'recent_resolved':        return '#67c23a'
    default:                       return '#606266'
  }
})

const sectionIcon = computed(() => {
  switch (props.section.key) {
    case 'needs_review':           return Warning
    case 'recent_feedback_alerts': return Bell
    case 'assigned_to_me':         return User
    case 'new_analyses':           return Document
    case 'unresolved_owned':       return Loading
    case 'recent_resolved':        return CircleCheck
    default:                       return Document
  }
})

const badgeType = computed(() => {
  switch (props.section.key) {
    case 'needs_review':           return 'danger'
    case 'recent_feedback_alerts': return 'warning'
    case 'recent_resolved':        return 'success'
    default:                       return 'primary'
  }
})

function workflowLabel(s: WorkflowState): string {
  switch (s) {
    case 'new':          return 'New'
    case 'in_progress':  return 'In progress'
    case 'needs_review': return 'Needs review'
    case 'resolved':     return 'Resolved'
    case 'dismissed':    return 'Dismissed'
    default:             return s
  }
}

function workflowTag(s: WorkflowState): string {
  switch (s) {
    case 'new':          return 'info'
    case 'in_progress':  return 'primary'
    case 'needs_review': return 'danger'
    case 'resolved':     return 'success'
    case 'dismissed':    return 'info'
    default:             return ''
  }
}

function notifTypeLabel(t: NotificationType | null): string {
  switch (t) {
    case 'assignment':      return 'Newly assigned'
    case 'review_required': return 'Review required'
    case 'resolved':        return 'Resolved'
    case 'feedback_alert':  return 'Feedback alert'
    case 'mention':         return 'Mention'
    default:                return ''
  }
}

function showNotifTag(item: WorkQueueItem): boolean {
  if (!item.latest_notification_type) return false
  // Avoid duplication with the incorrect-feedback tag.
  if (item.latest_notification_type === 'feedback_alert') return false
  // Avoid duplication with the section header for needs_review.
  if (
    props.section.key === 'needs_review' &&
    item.latest_notification_type === 'review_required'
  ) {
    return false
  }
  return true
}

function formatImpairment(s: string): string {
  return s
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

function latestTimestamp(item: WorkQueueItem): string | null {
  return (
    item.latest_feedback_at ||
    item.workflow_updated_at ||
    item.latest_notification_at ||
    item.created_at
  )
}

function formatWhen(iso: string | null): string {
  if (!iso) return ''
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return ''
  const diff = Date.now() - t
  const m = Math.floor(diff / 60_000)
  if (m < 1)  return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.floor(h / 24)
  if (d < 30) return `${d}d ago`
  return new Date(iso).toLocaleDateString()
}
</script>

<style scoped>
.wq-section {
  border-radius: 10px;
  border: 1px solid #e4e7ed;
}
.wq-section :deep(.el-card__header) {
  padding: 14px 18px;
  border-bottom: 1px solid #f0f2f5;
  background: #fafbfc;
}
.wq-section :deep(.el-card__body) {
  padding: 6px 10px 10px;
}

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.section-title {
  display: flex;
  align-items: center;
  gap: 8px;
}
.section-title .label {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
}
.count-badge :deep(.el-badge__content) {
  font-size: 11px;
  padding: 0 6px;
  height: 16px;
  line-height: 16px;
}
.empty-note {
  font-size: 12px;
  color: #909399;
}

.section-empty {
  padding: 14px 12px;
  color: #c0c4cc;
  font-size: 12px;
  text-align: center;
}

.item-list {
  list-style: none;
  padding: 0;
  margin: 0;
}

.item-row {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 8px;
  cursor: pointer;
  transition: background 0.15s;
}
.item-row + .item-row {
  border-top: 1px solid #f4f4f5;
}
.item-row:hover {
  background: #f5f7fa;
}

.row-main {
  flex: 1;
  min-width: 0;
}
.row-top {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.filename {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
  max-width: 360px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.state-tag,
.alert-tag,
.notif-tag {
  font-size: 11px;
}

.row-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 4px;
  font-size: 12px;
  color: #606266;
}
.row-meta .meta-chunk {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.row-meta strong {
  color: #303133;
  font-weight: 600;
}
.meta-when {
  color: #909399;
}

/* Accent stripe per section (subtle) */
.wq-section-needs_review :deep(.el-card__header) {
  border-left: 3px solid #f56c6c;
}
.wq-section-recent_feedback_alerts :deep(.el-card__header) {
  border-left: 3px solid #e6a23c;
}
.wq-section-assigned_to_me :deep(.el-card__header) {
  border-left: 3px solid #409eff;
}
.wq-section-new_analyses :deep(.el-card__header) {
  border-left: 3px solid #909399;
}
.wq-section-unresolved_owned :deep(.el-card__header) {
  border-left: 3px solid #409eff;
}
.wq-section-recent_resolved :deep(.el-card__header) {
  border-left: 3px solid #67c23a;
}
</style>
