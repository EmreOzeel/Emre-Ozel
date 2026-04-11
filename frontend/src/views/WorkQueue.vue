<template>
  <div class="work-queue">
    <div class="page-header">
      <h2>My Work</h2>
      <p>
        <template v-if="loading">Loading your queue…</template>
        <template v-else-if="data && data.total_open > 0">
          You have <strong>{{ data.total_open }}</strong>
          open item<span v-if="data.total_open !== 1">s</span> that need attention.
        </template>
        <template v-else>
          You're all caught up. No open items.
        </template>
      </p>
    </div>

    <div v-if="loading && !data" class="empty-state">
      <el-icon class="spinning" size="22"><Loading /></el-icon>
      <span>Loading…</span>
    </div>

    <div v-else-if="error" class="empty-state error">
      Failed to load work queue: {{ error }}
    </div>

    <div v-else-if="data" class="sections">
      <WorkQueueSectionCard
        v-for="section in data.sections"
        :key="section.key"
        :section="section"
        @open="onOpen"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Loading } from '@element-plus/icons-vue'
import api from '@/api'
import type { WorkQueueResponse, WorkQueueItem } from '@/types/analysis'
import WorkQueueSectionCard from '@/components/workqueue/WorkQueueSectionCard.vue'

const router = useRouter()

const data = ref<WorkQueueResponse | null>(null)
const loading = ref(false)
const error = ref<string | null>(null)

async function fetchQueue() {
  loading.value = true
  error.value = null
  try {
    const res = await api.get<WorkQueueResponse>('/work-queue')
    data.value = res.data
  } catch (err: any) {
    error.value = err?.response?.data?.detail || err?.message || 'Unknown error'
  } finally {
    loading.value = false
  }
}

function onOpen(item: WorkQueueItem) {
  router.push(`/analysis/${item.analysis_id}`)
}

onMounted(fetchQueue)
</script>

<style scoped>
.work-queue {
  max-width: 1100px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 20px;
}
.page-header h2 {
  font-size: 24px;
  font-weight: 700;
  color: #1a1a2e;
  margin-bottom: 6px;
}
.page-header p {
  color: #909399;
  font-size: 14px;
}

.sections {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.empty-state {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 40px;
  background: white;
  border-radius: 10px;
  border: 1px solid #e4e7ed;
  color: #909399;
  font-size: 14px;
}
.empty-state.error {
  color: #f56c6c;
}

.spinning {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}
</style>
