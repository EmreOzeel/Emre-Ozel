<template>
  <div class="tcp-issues-tab">
    <el-empty v-if="!tcp" description="No TCP data captured" />

    <template v-else>
      <!-- Stats row -->
      <div class="summary-chips">
        <div class="chip">
          <span class="chip-val">{{ tcp.total_sessions.toLocaleString() }}</span>
          <span class="chip-lbl">Total Sessions</span>
        </div>
        <div class="chip" :class="tcp.retransmissions > 0 ? 'warn' : ''">
          <span class="chip-val">{{ tcp.retransmissions.toLocaleString() }}</span>
          <span class="chip-lbl">Retransmissions</span>
        </div>
        <div class="chip" :class="tcp.resets > 0 ? 'danger' : ''">
          <span class="chip-val">{{ tcp.resets.toLocaleString() }}</span>
          <span class="chip-lbl">RST Closes</span>
        </div>
        <div class="chip" :class="tcp.failed_handshakes > 0 ? 'danger' : ''">
          <span class="chip-val">{{ tcp.failed_handshakes.toLocaleString() }}</span>
          <span class="chip-lbl">Failed Handshakes</span>
        </div>
        <div class="chip" :class="tcp.midstream > 0 ? 'warn' : ''">
          <span class="chip-val">{{ tcp.midstream.toLocaleString() }}</span>
          <span class="chip-lbl">Mid-stream</span>
        </div>
        <div class="chip" :class="tcp.duplicate_acks > 0 ? 'warn' : ''">
          <span class="chip-val">{{ tcp.duplicate_acks.toLocaleString() }}</span>
          <span class="chip-lbl">Dup ACKs</span>
        </div>
        <div class="chip" :class="tcp.zero_windows > 0 ? 'warn' : ''">
          <span class="chip-val">{{ tcp.zero_windows.toLocaleString() }}</span>
          <span class="chip-lbl">Zero Windows</span>
        </div>
      </div>

      <!-- Mid-stream info alert -->
      <el-alert
        v-if="tcp.midstream > 0"
        type="info"
        :closable="false"
        show-icon
      >
        <template #title>
          {{ tcp.midstream }} mid-stream session{{ tcp.midstream === 1 ? '' : 's' }} detected
        </template>
        <template #default>
          These sessions were already in progress when the capture started (no SYN observed).
          Analysis confidence is reduced — payload inspection and flow reconstruction may be incomplete.
        </template>
      </el-alert>

      <!-- Failed handshakes warning alert -->
      <el-alert
        v-if="tcp.failed_handshakes > 0"
        type="warning"
        :closable="false"
        show-icon
      >
        <template #title>
          {{ tcp.failed_handshakes }} failed handshake{{ tcp.failed_handshakes === 1 ? '' : 's' }} detected
        </template>
        <template #default>
          Failed handshakes indicate connection attempts that never completed the TCP 3-way handshake.
          This may signal port scans, service unavailability, firewall drops, or network connectivity issues.
        </template>
      </el-alert>

      <!-- Sessions table -->
      <el-table :data="tcp.sessions" size="small" stripe>
        <el-table-column prop="stream_id" label="#" width="55" />

        <el-table-column label="Source" min-width="150">
          <template #default="{ row }">
            <span class="mono">{{ row.src_ip }}:{{ row.src_port }}</span>
          </template>
        </el-table-column>

        <el-table-column label="Destination" min-width="150">
          <template #default="{ row }">
            <span class="mono">{{ row.dst_ip }}:{{ row.dst_port }}</span>
          </template>
        </el-table-column>

        <el-table-column label="State" width="90">
          <template #default="{ row }">
            <el-tag :type="stateType(row.state)" size="small">{{ row.state || '—' }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column label="Bytes" width="110" sortable>
          <template #default="{ row }">
            {{ fmtBytes(row.bytes_sent + row.bytes_recv) }}
          </template>
        </el-table-column>

        <el-table-column label="Retrans" width="80" sortable :sort-method="(a, b) => a.retransmissions - b.retransmissions">
          <template #default="{ row }">
            <span :class="row.retransmissions > 5 ? 'retrans-high' : ''">
              {{ row.retransmissions || 0 }}
            </span>
          </template>
        </el-table-column>

        <el-table-column label="Duration" width="90" sortable>
          <template #default="{ row }">
            {{ row.duration_sec.toFixed(2) }}s
          </template>
        </el-table-column>

        <el-table-column label="Handshake" width="110">
          <template #default="{ row }">
            <el-tag :type="hsType(row.handshake_status)" size="small">
              {{ hsLabel(row.handshake_status) }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>
    </template>
  </div>
</template>

<script setup lang="ts">
import type { TCPStats } from '@/types/analysis'

defineProps<{
  tcp: TCPStats | null
}>()

function stateType(state: string): string {
  if (!state) return 'info'
  const s = state.toLowerCase()
  if (s.includes('established') || s === 'open') return 'success'
  if (s.includes('close') || s.includes('fin')) return 'warning'
  if (s.includes('rst') || s.includes('reset') || s.includes('fail')) return 'danger'
  return 'info'
}

function hsType(s: string): string {
  if (s === 'complete') return 'success'
  if (s === 'failed') return 'danger'
  return 'warning'
}

function hsLabel(s: string): string {
  if (s === 'complete') return 'Complete'
  if (s === 'failed') return 'Failed'
  if (s === 'mid_stream') return 'Mid-stream'
  return s || '—'
}

function fmtBytes(b: number): string {
  if (!b) return '0'
  if (b < 1024) return b + 'B'
  if (b < 1024 ** 2) return (b / 1024).toFixed(1) + 'K'
  if (b < 1024 ** 3) return (b / 1024 ** 2).toFixed(1) + 'M'
  return (b / 1024 ** 3).toFixed(2) + 'G'
}
</script>

<style scoped>
.tcp-issues-tab {
  display: flex;
  flex-direction: column;
  gap: 14px;
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
  min-width: 90px;
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

.mono {
  font-family: monospace;
  font-size: 12px;
}

.retrans-high {
  color: #f56c6c;
  font-weight: 700;
}
</style>
