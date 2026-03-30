<template>
  <div class="conversations-tab">
    <!-- Summary row -->
    <div class="summary-chips">
      <div class="chip">
        <span class="chip-val">{{ stats.total_sessions }}</span>
        <span class="chip-lbl">Sessions</span>
      </div>
      <div class="chip warn" v-if="stats.midstream > 0">
        <span class="chip-val">{{ stats.midstream }}</span>
        <span class="chip-lbl">Mid-stream</span>
      </div>
      <div class="chip danger" v-if="stats.failed_handshakes > 0">
        <span class="chip-val">{{ stats.failed_handshakes }}</span>
        <span class="chip-lbl">Failed Handshakes</span>
      </div>
      <div class="chip warn" v-if="stats.retransmissions > 0">
        <span class="chip-val">{{ stats.retransmissions }}</span>
        <span class="chip-lbl">Retransmissions</span>
      </div>
      <div class="chip danger" v-if="stats.resets > 0">
        <span class="chip-val">{{ stats.resets }}</span>
        <span class="chip-lbl">RST Closes</span>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters-row">
      <el-select v-model="filters.handshake" placeholder="All handshakes" clearable size="small" style="width:170px">
        <el-option label="Complete" value="complete" />
        <el-option label="Mid-stream" value="mid_stream" />
        <el-option label="Failed" value="failed" />
      </el-select>
      <el-input v-model="filters.search" placeholder="IP / port..." clearable size="small" style="width:180px" />
      <span class="result-count">{{ sessions.length }} session(s)</span>
    </div>

    <!-- Sessions table with expand -->
    <el-table
      :data="sessions"
      size="small"
      stripe
      row-key="stream_id"
    >
      <el-table-column type="expand" width="40">
        <template #default="{ row }">
          <FlowInterpretationCard :session="row" />
        </template>
      </el-table-column>

      <el-table-column prop="stream_id" label="#" width="55" />

      <el-table-column label="Protocol" width="100">
        <template #default="{ row }">
          <el-tag size="small" type="primary">{{ row.protocol_guess || '—' }}</el-tag>
        </template>
      </el-table-column>

      <el-table-column label="Source" min-width="140">
        <template #default="{ row }">{{ row.src_ip }}:{{ row.src_port }}</template>
      </el-table-column>

      <el-table-column label="Destination" min-width="140">
        <template #default="{ row }">{{ row.dst_ip }}:{{ row.dst_port }}</template>
      </el-table-column>

      <el-table-column label="Handshake" width="110">
        <template #default="{ row }">
          <el-tag :type="hsType(row.handshake_status)" size="small">
            {{ hsLabel(row.handshake_status) }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column label="Close" width="80">
        <template #default="{ row }">
          <el-tag :type="closeType(row.close_behavior)" size="small" plain>
            {{ row.close_behavior?.toUpperCase() || '?' }}
          </el-tag>
        </template>
      </el-table-column>

      <el-table-column label="Sent" width="90" sortable>
        <template #default="{ row }">{{ fmt(row.bytes_sent) }}</template>
      </el-table-column>

      <el-table-column label="Recv" width="90" sortable>
        <template #default="{ row }">{{ fmt(row.bytes_recv) }}</template>
      </el-table-column>

      <el-table-column label="Retrans" width="80">
        <template #default="{ row }">
          <span :style="row.retransmissions > 10 ? 'color:#f56c6c' : ''">
            {{ row.retransmissions || 0 }}
          </span>
        </template>
      </el-table-column>

      <el-table-column label="Confidence" width="100">
        <template #default="{ row }">
          <el-tag :type="confType(row.confidence)" size="small" plain>
            {{ row.confidence || '—' }}
          </el-tag>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup lang="ts">
import FlowInterpretationCard from './FlowInterpretationCard.vue'
import type { TCPSession, TCPStats } from '@/types/analysis'

defineProps<{
  sessions: TCPSession[]
  stats: Pick<TCPStats, 'total_sessions' | 'midstream' | 'failed_handshakes' | 'retransmissions' | 'resets'>
  filters: { handshake: string; search: string }
}>()

function hsType(s: string): string {
  if (s === 'complete') return 'success'
  if (s === 'failed') return 'danger'
  return 'warning'
}
function hsLabel(s: string): string {
  if (s === 'complete') return 'Complete'
  if (s === 'failed') return 'Failed'
  return 'Mid-stream'
}
function closeType(s: string): string {
  if (s === 'fin') return 'success'
  if (s === 'rst') return 'danger'
  return 'info'
}
function confType(s: string): string {
  if (s === 'high') return 'success'
  if (s === 'medium') return 'warning'
  return 'danger'
}
function fmt(b: number): string {
  if (!b) return '0'
  if (b < 1024) return b + 'B'
  if (b < 1024 ** 2) return (b / 1024).toFixed(1) + 'K'
  if (b < 1024 ** 3) return (b / 1024 ** 2).toFixed(1) + 'M'
  return (b / 1024 ** 3).toFixed(2) + 'G'
}
</script>

<style scoped>
.conversations-tab { display: flex; flex-direction: column; gap: 12px; }
.summary-chips { display: flex; flex-wrap: wrap; gap: 10px; }
.chip {
  background: #fff; border: 1px solid #ebeef5; border-radius: 6px;
  padding: 10px 16px; text-align: center; min-width: 90px;
}
.chip.warn  { border-color: #f0c040; }
.chip.danger { border-color: #f56c6c; }
.chip-val   { display: block; font-size: 20px; font-weight: 700; color: #303133; }
.chip.warn  .chip-val { color: #e6a23c; }
.chip.danger .chip-val { color: #f56c6c; }
.chip-lbl   { font-size: 11px; color: #909399; margin-top: 2px; display: block; }
.filters-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.result-count { font-size: 12px; color: #909399; }
</style>
