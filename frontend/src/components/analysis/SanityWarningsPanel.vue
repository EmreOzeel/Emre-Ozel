<template>
  <div class="sanity-panel" v-if="warnings?.length">
    <div class="sanity-header">
      <el-icon><Warning /></el-icon>
      <span class="sanity-title">
        {{ warningCount }} Contradiction{{ warningCount !== 1 ? 's' : '' }} Detected
      </span>
      <span class="sanity-subtitle">
        — findings and raw statistics disagree on at least one data point
      </span>
      <span class="info-count" v-if="infoCount">
        + {{ infoCount }} informational note{{ infoCount !== 1 ? 's' : '' }}
      </span>
    </div>

    <div class="sanity-list">
      <div
        class="sanity-item"
        v-for="w in warnings"
        :key="w.check_id + w.message"
        :class="`sev-${w.severity}`"
      >
        <div class="sanity-item-header">
          <el-tag
            :type="w.severity === 'warning' ? 'warning' : 'info'"
            size="small"
            effect="plain"
            class="check-id-tag"
          >{{ w.check_id }}</el-tag>
          <span class="sanity-msg">{{ w.message }}</span>
        </div>

        <div class="sanity-detail" v-if="w.detail">{{ w.detail }}</div>

        <div class="sanity-links" v-if="w.related_finding || w.affected_host">
          <span
            v-if="w.related_finding"
            class="sanity-link"
            @click="emit('navigate-finding', w.related_finding!)"
            title="Jump to this finding"
          >
            → Finding: {{ w.related_finding }}
          </span>
          <span v-if="w.affected_host" class="sanity-host">
            Host: <code>{{ w.affected_host }}</code>
          </span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Warning } from '@element-plus/icons-vue'
import type { SanityWarning } from '@/types/analysis'

const props = defineProps<{ warnings: SanityWarning[] | null | undefined }>()
const emit = defineEmits<{
  (e: 'navigate-finding', ruleId: string): void
}>()

const warningCount = computed(() =>
  (props.warnings ?? []).filter(w => w.severity === 'warning').length
)
const infoCount = computed(() =>
  (props.warnings ?? []).filter(w => w.severity === 'info').length
)
</script>

<style scoped>
.sanity-panel {
  background: #fff;
  border: 1px solid #fde2cb;
  border-left: 4px solid #e6a23c;
  border-radius: 6px;
  padding: 12px 16px;
  margin-bottom: 16px;
}

.sanity-header {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  margin-bottom: 10px;
}
.sanity-title {
  font-size: 14px; font-weight: 700; color: #b88230;
}
.sanity-subtitle {
  font-size: 13px; color: #909399;
}
.info-count {
  font-size: 12px; color: #909399; margin-left: 4px;
}

.sanity-list {
  display: flex; flex-direction: column; gap: 8px;
}

.sanity-item {
  border-radius: 4px;
  padding: 8px 12px;
  font-size: 13px;
}
.sanity-item.sev-warning {
  background: #fdf6ec;
  border: 1px solid #f5dab1;
}
.sanity-item.sev-info {
  background: #f4f4f5;
  border: 1px solid #e9e9eb;
}

.sanity-item-header {
  display: flex; align-items: flex-start; gap: 8px;
}
.check-id-tag { flex-shrink: 0; margin-top: 1px; }
.sanity-msg { color: #303133; line-height: 1.5; flex: 1; }

.sanity-detail {
  margin-top: 4px;
  margin-left: 56px;
  font-size: 12px; color: #909399; line-height: 1.5;
}

.sanity-links {
  margin-top: 6px; margin-left: 56px;
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap;
}
.sanity-link {
  font-size: 12px; color: #409eff; cursor: pointer;
}
.sanity-link:hover { text-decoration: underline; }
.sanity-host {
  font-size: 12px; color: #606266;
}
.sanity-host code {
  background: #f5f7fa; padding: 1px 5px; border-radius: 3px; font-size: 11px;
}
</style>
