<template>
  <div class="dns-tab">
    <el-empty v-if="!dns" description="No DNS data captured" />

    <template v-else>
      <!-- Stats row -->
      <div class="summary-chips">
        <div class="chip">
          <span class="chip-val">{{ dns.total_queries.toLocaleString() }}</span>
          <span class="chip-lbl">Total Queries</span>
        </div>
        <div class="chip">
          <span class="chip-val">{{ dns.unique_domains.toLocaleString() }}</span>
          <span class="chip-lbl">Unique Domains</span>
        </div>
        <div class="chip" :class="dns.nxdomain_count > 0 ? 'warn' : ''">
          <span class="chip-val">{{ dns.nxdomain_count.toLocaleString() }}</span>
          <span class="chip-lbl">NXDOMAIN</span>
        </div>
        <div class="chip" :class="dns.servfail_count > 0 ? 'danger' : ''">
          <span class="chip-val">{{ dns.servfail_count.toLocaleString() }}</span>
          <span class="chip-lbl">SERVFAIL</span>
        </div>
        <div class="chip">
          <span class="chip-val">{{ dns.avg_rtt_ms.toFixed(1) }} ms</span>
          <span class="chip-lbl">Avg RTT</span>
        </div>
        <div class="chip" :class="dns.unanswered_count > 0 ? 'warn' : ''">
          <span class="chip-val">{{ dns.unanswered_count.toLocaleString() }}</span>
          <span class="chip-lbl">Unanswered</span>
        </div>
      </div>

      <!-- Two-column grid -->
      <div class="grid-2">
        <!-- Top Queried Domains -->
        <div class="grid-card">
          <div class="card-title">Top Queried Domains</div>
          <el-table :data="dns.top_queries" size="small" stripe>
            <el-table-column label="Domain" min-width="200">
              <template #default="{ row }">
                <span class="mono">{{ row.domain }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="Count" width="80" align="right" />
          </el-table>
        </div>

        <!-- NXDOMAIN table (only if data) -->
        <div v-if="dns.nxdomains.length" class="grid-card">
          <div class="card-title warn-title">NXDOMAIN Responses</div>
          <el-table :data="dns.nxdomains" size="small" stripe>
            <el-table-column label="Domain" min-width="200">
              <template #default="{ row }">
                <span class="mono">{{ row.domain }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="Count" width="80" align="right" />
          </el-table>
        </div>

        <!-- Query Types -->
        <div class="grid-card">
          <div class="card-title">Query Types</div>
          <el-table :data="queryTypeRows" size="small" stripe>
            <el-table-column label="Type" min-width="100">
              <template #default="{ row }">
                <el-tag size="small" type="info">{{ row.key }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="value" label="Count" width="80" align="right" />
          </el-table>
        </div>

        <!-- Top Resolvers -->
        <div class="grid-card">
          <div class="card-title">Top Resolvers</div>
          <el-table :data="dns.resolvers" size="small" stripe>
            <el-table-column label="IP" min-width="140">
              <template #default="{ row }">
                <span class="mono">{{ row.ip }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="Queries" width="80" align="right" />
          </el-table>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { DnsStats } from '@/types/analysis'

const props = defineProps<{
  dns: DnsStats | null
}>()

interface KvRow {
  key: string
  value: number
}

const queryTypeRows = computed<KvRow[]>(() => {
  if (!props.dns) return []
  return Object.entries(props.dns.query_types)
    .map(([key, value]) => ({ key, value }))
    .sort((a, b) => b.value - a.value)
})
</script>

<style scoped>
.dns-tab {
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
  min-width: 100px;
}

.chip.warn  { border-color: #f0c040; }
.chip.danger { border-color: #f56c6c; }

.chip-val {
  display: block;
  font-size: 20px;
  font-weight: 700;
  color: #303133;
}

.chip.warn  .chip-val { color: #e6a23c; }
.chip.danger .chip-val { color: #f56c6c; }

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
  .grid-2 { grid-template-columns: 1fr; }
}

.grid-card {
  background: #fff;
  border: 1px solid #ebeef5;
  border-radius: 8px;
  padding: 14px;
}

.card-title {
  font-size: 13px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 10px;
}

.warn-title { color: #e6a23c; }

.mono {
  font-family: monospace;
  font-size: 12px;
}
</style>
