<template>
  <div class="web-tab">
    <el-empty v-if="!http" description="No HTTP data captured" />

    <template v-else>
      <!-- Stats row -->
      <div class="summary-chips">
        <div class="chip">
          <span class="chip-val">{{ http.total_requests.toLocaleString() }}</span>
          <span class="chip-lbl">Requests</span>
        </div>
        <div class="chip" :class="http.error_4xx > 0 ? 'warn' : ''">
          <span class="chip-val">{{ http.error_4xx.toLocaleString() }}</span>
          <span class="chip-lbl">4xx Errors</span>
        </div>
        <div class="chip" :class="http.error_5xx > 0 ? 'danger' : ''">
          <span class="chip-val">{{ http.error_5xx.toLocaleString() }}</span>
          <span class="chip-lbl">5xx Errors</span>
        </div>
        <div class="chip">
          <span class="chip-val">{{ http.avg_latency_ms.toFixed(1) }} ms</span>
          <span class="chip-lbl">Avg Latency</span>
        </div>
      </div>

      <!-- Two-column grid -->
      <div class="grid-2">
        <!-- HTTP Methods -->
        <div class="grid-card">
          <div class="card-title">HTTP Methods</div>
          <el-table :data="methodRows" size="small" stripe>
            <el-table-column label="Method" min-width="100">
              <template #default="{ row }">
                <el-tag size="small" type="primary">{{ row.key }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="value" label="Count" width="80" align="right" />
          </el-table>
        </div>

        <!-- Status Codes -->
        <div class="grid-card">
          <div class="card-title">Status Codes</div>
          <el-table :data="statusRows" size="small" stripe>
            <el-table-column label="Code" width="80">
              <template #default="{ row }">
                <span :class="statusClass(row.key)">{{ row.key }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="value" label="Count" width="80" align="right" />
          </el-table>
        </div>

        <!-- Top Hosts -->
        <div class="grid-card">
          <div class="card-title">Top Hosts</div>
          <el-table :data="http.top_hosts" size="small" stripe>
            <el-table-column label="Host" min-width="200">
              <template #default="{ row }">
                <span class="mono">{{ row.host }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="Requests" width="90" align="right" />
          </el-table>
        </div>

        <!-- Top URIs -->
        <div class="grid-card">
          <div class="card-title">Top URIs</div>
          <el-table :data="http.top_uris" size="small" stripe>
            <el-table-column label="URI" min-width="200">
              <template #default="{ row }">
                <span class="mono uri-cell">{{ row.uri }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="Requests" width="90" align="right" />
          </el-table>
        </div>

        <!-- User Agents (only if data exists) -->
        <div v-if="http.top_user_agents.length" class="grid-card grid-full">
          <div class="card-title">User Agents</div>
          <el-table :data="http.top_user_agents" size="small" stripe>
            <el-table-column label="User Agent" min-width="300">
              <template #default="{ row }">
                <span class="mono ua-cell">{{ row.ua }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="Requests" width="90" align="right" />
          </el-table>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { HttpStats } from '@/types/analysis'

const props = defineProps<{
  http: HttpStats | null
}>()

interface KvRow {
  key: string
  value: number
}

const methodRows = computed<KvRow[]>(() => {
  if (!props.http) return []
  return Object.entries(props.http.method_counts)
    .map(([key, value]) => ({ key, value }))
    .sort((a, b) => b.value - a.value)
})

const statusRows = computed<KvRow[]>(() => {
  if (!props.http) return []
  return Object.entries(props.http.status_counts)
    .map(([key, value]) => ({ key, value }))
    .sort((a, b) => Number(a.key) - Number(b.key))
})

function statusClass(code: string): string {
  const n = parseInt(code, 10)
  if (n >= 500) return 'status-5xx'
  if (n >= 400) return 'status-4xx'
  return 'status-ok'
}
</script>

<style scoped>
.web-tab {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.summary-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.chip {
  background: #fff;
  border: 1px solid #ebeef5;
  border-radius: 6px;
  padding: 10px 16px;
  text-align: center;
  min-width: 110px;
}

.chip.warn {
  border-color: #f0c040;
}

.chip.danger {
  border-color: #f56c6c;
}

.chip-val {
  display: block;
  font-size: 20px;
  font-weight: 700;
  color: #303133;
}

.chip.warn .chip-val {
  color: #e6a23c;
}

.chip.danger .chip-val {
  color: #f56c6c;
}

.chip-lbl {
  font-size: 11px;
  color: #909399;
  margin-top: 2px;
  display: block;
}

.grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

@media (max-width: 900px) {
  .grid-2 {
    grid-template-columns: 1fr;
  }
}

.grid-card {
  background: #fff;
  border: 1px solid #ebeef5;
  border-radius: 8px;
  padding: 14px;
}

.grid-full {
  grid-column: 1 / -1;
}

.card-title {
  font-size: 13px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 10px;
}

.mono {
  font-family: monospace;
  font-size: 12px;
}

.uri-cell,
.ua-cell {
  word-break: break-all;
}

.status-ok {
  font-family: monospace;
  font-weight: 600;
  color: #67c23a;
}

.status-4xx {
  font-family: monospace;
  font-weight: 600;
  color: #e6a23c;
}

.status-5xx {
  font-family: monospace;
  font-weight: 600;
  color: #f56c6c;
}
</style>
