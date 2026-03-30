<template>
  <el-card shadow="never" class="host-card" :class="{ anomalous: host.anomaly_score >= 5 }">
    <div class="host-top">
      <div class="host-id">
        <span class="host-ip">{{ host.ip }}</span>
        <el-tag size="small" type="info">{{ host.role }}</el-tag>
        <el-tag size="small" v-if="host.is_internal" type="success" plain>internal</el-tag>
        <el-tag size="small" v-else type="warning" plain>external</el-tag>
      </div>
      <div class="anomaly-score" :style="{ color: scoreColor }">
        <span class="score-num">{{ host.anomaly_score.toFixed(1) }}</span>
        <span class="score-lbl">anomaly</span>
      </div>
    </div>

    <!-- Traffic stats -->
    <div class="host-stats">
      <div class="hstat"><span class="hstat-lbl">Sent</span><span>{{ fmt(host.bytes_sent) }}</span></div>
      <div class="hstat"><span class="hstat-lbl">Recv</span><span>{{ fmt(host.bytes_recv) }}</span></div>
      <div class="hstat"><span class="hstat-lbl">Peers</span><span>{{ host.unique_peers }}</span></div>
      <div class="hstat"><span class="hstat-lbl">Ports</span><span>{{ host.unique_dst_ports }}</span></div>
      <div class="hstat">
        <span class="hstat-lbl">TCP fail</span>
        <span :style="host.tcp_sessions_failed > 0 ? 'color:#f56c6c' : ''">
          {{ host.tcp_sessions_failed }}
        </span>
      </div>
    </div>

    <!-- Suspicious behaviors -->
    <div class="behaviors" v-if="host.suspicious_behaviors?.length">
      <div class="behaviors-label">Suspicious behaviors</div>
      <el-tag
        v-for="b in host.suspicious_behaviors"
        :key="b"
        type="danger"
        size="small"
        plain
        class="behavior-tag"
      >{{ b }}</el-tag>
    </div>

    <!-- Beaconing -->
    <div class="beacon-note" v-if="host.periodic_interval_sec > 0">
      <el-icon><WarningFilled /></el-icon>
      Periodic outbound activity every ~{{ host.periodic_interval_sec }}s
      (jitter={{ host.periodic_jitter.toFixed(2) }}) — possible beaconing
    </div>

    <!-- Top peers -->
    <div class="top-peers" v-if="host.top_peers?.length">
      <div class="section-label">Top peers</div>
      <div class="peer-row" v-for="p in host.top_peers.slice(0, 4)" :key="p.ip">
        <span class="peer-ip">{{ p.ip }}</span>
        <span class="peer-bytes">{{ fmt(p.bytes) }}</span>
      </div>
    </div>

    <!-- Top protocols -->
    <div class="protocols" v-if="Object.keys(host.protocols || {}).length">
      <div class="section-label">Protocols</div>
      <div class="proto-chips">
        <el-tag
          v-for="(cnt, proto) in topProtocols"
          :key="proto"
          size="small"
          plain
        >{{ proto }}: {{ cnt }}</el-tag>
      </div>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { WarningFilled } from '@element-plus/icons-vue'
import type { HostProfile } from '@/types/analysis'

const props = defineProps<{ host: HostProfile }>()

const scoreColor = computed(() => {
  if (props.host.anomaly_score >= 7) return '#f56c6c'
  if (props.host.anomaly_score >= 4) return '#e6a23c'
  return '#67c23a'
})

const topProtocols = computed(() => {
  return Object.fromEntries(
    Object.entries(props.host.protocols || {})
      .sort(([, a], [, b]) => (b as number) - (a as number))
      .slice(0, 5)
  )
})

function fmt(b: number): string {
  if (!b) return '0'
  if (b < 1024) return b + 'B'
  if (b < 1024 ** 2) return (b / 1024).toFixed(1) + 'KB'
  if (b < 1024 ** 3) return (b / 1024 ** 2).toFixed(1) + 'MB'
  return (b / 1024 ** 3).toFixed(2) + 'GB'
}
</script>

<style scoped>
.host-card { margin-bottom: 10px; }
.host-card.anomalous { border-color: #fde2e2; }

.host-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px; }
.host-id { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.host-ip { font-weight: 700; font-size: 15px; font-family: monospace; color: #303133; }

.anomaly-score { text-align: right; }
.score-num { display: block; font-size: 22px; font-weight: 700; }
.score-lbl { font-size: 10px; color: #909399; }

.host-stats { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 8px; }
.hstat { display: flex; flex-direction: column; align-items: center; }
.hstat-lbl { font-size: 10px; color: #909399; margin-bottom: 2px; }
.hstat span:last-child { font-size: 13px; font-weight: 600; }

.behaviors { margin: 8px 0; }
.behaviors-label { font-size: 11px; font-weight: 700; color: #909399; text-transform: uppercase; margin-bottom: 4px; }
.behavior-tag { margin: 2px; }

.beacon-note {
  display: flex; align-items: center; gap: 6px;
  background: #fdf6ec; border-radius: 4px; padding: 6px 10px;
  font-size: 12px; color: #b8741a; margin: 6px 0;
}

.top-peers, .protocols { margin-top: 8px; }
.section-label { font-size: 11px; font-weight: 700; color: #909399; text-transform: uppercase; margin-bottom: 4px; }
.peer-row { display: flex; justify-content: space-between; font-size: 12px; padding: 2px 0; }
.peer-ip { font-family: monospace; color: #409eff; }
.peer-bytes { color: #606266; }
.proto-chips { display: flex; flex-wrap: wrap; gap: 4px; }
</style>
