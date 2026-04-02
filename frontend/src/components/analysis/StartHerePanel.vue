<template>
  <div class="start-here-panel" v-if="hasContent">
    <div class="panel-header">
      <el-icon><Flag /></el-icon>
      <span>Start Here</span>
      <span class="panel-subtitle">— highest-priority items for this capture</span>
    </div>

    <!-- Critical findings -->
    <div class="section" v-if="criticalFindings.length">
      <div class="section-label danger">
        <el-icon><WarningFilled /></el-icon>
        {{ criticalFindings.length }} Critical Finding{{ criticalFindings.length > 1 ? 's' : '' }}
        <span class="low-conf-qualifier" v-if="lowConfCriticalCount > 0">
          — {{ lowConfCriticalCount }} with weak evidence
        </span>
      </div>
      <div class="item-list">
        <div
          class="finding-item"
          v-for="f in criticalFindings.slice(0, 5)"
          :key="f.id"
          @click="emit('navigate', 'findings', { severity: 'critical' })"
          :class="{ 'finding-item-lowconf': isLowConf(f) }"
        >
          <el-tag type="danger" size="small" effect="dark">CRITICAL</el-tag>
          <span class="item-title">{{ f.title }}</span>
          <span class="item-lowconf-badge" v-if="isLowConf(f)" title="Low evidence quality — treat as preliminary">
            low evidence
          </span>
          <span class="item-hosts" v-if="f.affected_hosts?.length">
            {{ f.affected_hosts.slice(0, 2).join(', ') }}
            <span v-if="f.affected_hosts.length > 2">+{{ f.affected_hosts.length - 2 }} more</span>
          </span>
        </div>
        <div class="show-more" v-if="criticalFindings.length > 5" @click="emit('navigate', 'findings', { severity: 'critical' })">
          View all {{ criticalFindings.length }} critical findings →
        </div>
      </div>
    </div>

    <!-- High-anomaly hosts -->
    <div class="section" v-if="anomalousHosts.length">
      <div class="section-label warning">
        <el-icon><Connection /></el-icon>
        Hosts with Elevated Anomaly Scores
      </div>
      <div class="item-list">
        <div
          class="host-item"
          v-for="h in anomalousHosts"
          :key="h.ip"
          @click="emit('navigate', 'hosts')"
        >
          <code class="host-ip">{{ h.ip }}</code>
          <el-tag :type="hostRoleTagType(h.role)" size="small" plain>{{ h.role }}</el-tag>
          <span class="anomaly-score" :class="scoreClass(h.anomaly_score)">
            score {{ h.anomaly_score.toFixed(1) }}
          </span>
          <span class="host-behaviors" v-if="h.suspicious_behaviors?.length">
            {{ h.suspicious_behaviors.slice(0, 2).join(' · ') }}
          </span>
        </div>
      </div>
    </div>

    <!-- Failed handshakes / connectivity issues -->
    <div class="section" v-if="showConnectivity">
      <div class="section-label info">
        <el-icon><Link /></el-icon>
        Connectivity Issues
      </div>
      <div class="item-list">
        <div class="stat-item" v-if="failedHandshakes > 0">
          <span class="stat-num">{{ failedHandshakes }}</span>
          <span class="stat-label">failed TCP handshake{{ failedHandshakes > 1 ? 's' : '' }}</span>
          <span class="stat-action" @click="emit('navigate', 'conversations', { handshake: 'failed' })">→ inspect</span>
        </div>
        <div class="stat-item" v-if="tcpStats?.resets > 0">
          <span class="stat-num">{{ tcpStats.resets }}</span>
          <span class="stat-label">TCP reset{{ tcpStats.resets > 1 ? 's' : '' }}</span>
          <span class="stat-action" @click="emit('navigate', 'tcp')">→ inspect</span>
        </div>
        <div class="stat-item" v-if="tcpStats?.retransmissions > 0">
          <span class="stat-num">{{ tcpStats.retransmissions }}</span>
          <span class="stat-label">retransmission{{ tcpStats.retransmissions > 1 ? 's' : '' }}</span>
          <span class="stat-action" @click="emit('navigate', 'tcp')">→ inspect</span>
        </div>
      </div>
    </div>

    <!-- Suggested next steps -->
    <div class="next-steps" v-if="nextSteps.length">
      <div class="section-label neutral">
        <el-icon><Aim /></el-icon>
        Suggested Investigation Path
      </div>
      <ol class="steps-list">
        <li v-for="(step, i) in nextSteps" :key="i" @click="step.navigate && emit('navigate', step.tab, step.filters)">
          <span class="step-num">{{ i + 1 }}</span>
          <span class="step-text" :class="{ clickable: step.navigate }">{{ step.text }}</span>
        </li>
      </ol>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { Finding, HostProfile } from '@/types/analysis'

interface TCPStats {
  failed_handshakes: number
  resets: number
  retransmissions: number
}

interface Props {
  findings: Finding[]
  hosts: HostProfile[]
  tcpStats: TCPStats | null
}

const props = defineProps<Props>()
const emit = defineEmits<{
  (e: 'navigate', tab: string, filters?: Record<string, string>): void
}>()

const criticalFindings = computed(() =>
  props.findings.filter(f => f.severity === 'critical' && !f.suppressed)
)

const LOW_CONF_THRESHOLD = 45

function isLowConf(f: Finding): boolean {
  return (f.confidence_score ?? 50) < LOW_CONF_THRESHOLD
}

const lowConfCriticalCount = computed(() =>
  criticalFindings.value.filter(isLowConf).length
)

const highFindings = computed(() =>
  props.findings.filter(f => f.severity === 'high' && !f.suppressed)
)

const anomalousHosts = computed(() =>
  props.hosts
    .filter(h => h.anomaly_score >= 3.0)
    .slice(0, 5)
)

const failedHandshakes = computed(() => props.tcpStats?.failed_handshakes ?? 0)

const showConnectivity = computed(() =>
  failedHandshakes.value > 0 ||
  (props.tcpStats?.resets ?? 0) > 0 ||
  (props.tcpStats?.retransmissions ?? 0) > 0
)

const hasContent = computed(() =>
  criticalFindings.value.length > 0 ||
  anomalousHosts.value.length > 0 ||
  showConnectivity.value
)

const nextSteps = computed(() => {
  const steps: { text: string; navigate?: boolean; tab?: string; filters?: Record<string, string> }[] = []

  if (criticalFindings.value.length > 0) {
    steps.push({
      text: `Review ${criticalFindings.value.length} critical finding${criticalFindings.value.length > 1 ? 's' : ''} and their evidence`,
      navigate: true, tab: 'findings', filters: { severity: 'critical' },
    })
  }

  if (anomalousHosts.value.length > 0) {
    const topHost = anomalousHosts.value[0]
    steps.push({
      text: `Investigate ${topHost.ip} (anomaly score ${topHost.anomaly_score.toFixed(1)}) — check peer connections and traffic patterns`,
      navigate: true, tab: 'hosts',
    })
  }

  if (failedHandshakes.value > 0) {
    steps.push({
      text: `Examine ${failedHandshakes.value} failed TCP handshake${failedHandshakes.value > 1 ? 's' : ''} — may indicate scanning, port blocks, or service outage`,
      navigate: true, tab: 'conversations', filters: { handshake: 'failed' },
    })
  }

  if (highFindings.value.length > 0 && criticalFindings.value.length === 0) {
    steps.push({
      text: `Review ${highFindings.value.length} high-severity finding${highFindings.value.length > 1 ? 's' : ''}`,
      navigate: true, tab: 'findings', filters: { severity: 'high' },
    })
  }

  if (steps.length > 0) {
    steps.push({ text: 'Export JSON or generate report for full evidence record' })
  }

  return steps
})

function hostRoleTagType(role: string): string {
  if (role === 'server' || role === 'web_server') return 'success'
  if (role === 'dns_resolver') return 'warning'
  if (role === 'gateway') return 'info'
  return ''
}

function scoreClass(score: number): string {
  if (score >= 6) return 'score-critical'
  if (score >= 3) return 'score-high'
  return 'score-ok'
}
</script>

<style scoped>
.start-here-panel {
  background: #fff;
  border: 1px solid #ebeef5;
  border-left: 4px solid #409eff;
  border-radius: 6px;
  padding: 16px 20px;
  margin-bottom: 20px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.panel-header {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 15px;
  font-weight: 700;
  color: #303133;
}
.panel-subtitle { font-size: 13px; font-weight: 400; color: #909399; }

.section { display: flex; flex-direction: column; gap: 6px; }

.section-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .05em;
}
.section-label.danger  { color: #f56c6c; }
.section-label.warning { color: #e6a23c; }
.section-label.info    { color: #409eff; }
.section-label.neutral { color: #606266; }

.item-list { display: flex; flex-direction: column; gap: 4px; padding-left: 4px; }

.finding-item {
  display: flex; align-items: center; gap: 8px;
  padding: 6px 10px; background: #fff5f5; border-radius: 4px;
  cursor: pointer; font-size: 13px;
}
.finding-item:hover { background: #fee; }
.finding-item-lowconf { opacity: 0.85; border: 1px dashed #f5dab1; background: #fffaf0; }
.finding-item-lowconf:hover { background: #fef5e0; }
.item-title { flex: 1; color: #303133; font-weight: 500; }
.item-hosts { font-size: 11px; color: #909399; font-family: monospace; }
.item-lowconf-badge {
  font-size: 10px; font-weight: 700; padding: 1px 5px;
  background: #fdf6ec; color: #b88230; border: 1px solid #f5dab1;
  border-radius: 3px; white-space: nowrap;
}
.low-conf-qualifier {
  font-size: 11px; font-weight: 400; color: #b88230; margin-left: 2px;
}

.host-item {
  display: flex; align-items: center; gap: 8px;
  padding: 6px 10px; background: #fdf6ec; border-radius: 4px;
  cursor: pointer; font-size: 13px;
}
.host-item:hover { background: #faecd8; }
.host-ip { background: #f5f7fa; padding: 1px 6px; border-radius: 3px; font-size: 12px; }
.host-behaviors { font-size: 11px; color: #909399; flex: 1; }
.anomaly-score { font-size: 11px; font-weight: 700; padding: 1px 6px; border-radius: 10px; }
.score-critical { background: #fef0f0; color: #f56c6c; }
.score-high     { background: #fdf6ec; color: #e6a23c; }
.score-ok       { background: #f0f9eb; color: #67c23a; }

.stat-item {
  display: flex; align-items: center; gap: 8px;
  padding: 4px 10px; font-size: 13px;
}
.stat-num { font-weight: 700; color: #303133; min-width: 30px; text-align: right; }
.stat-label { color: #606266; flex: 1; }
.stat-action { font-size: 12px; color: #409eff; cursor: pointer; }
.stat-action:hover { text-decoration: underline; }

.show-more {
  font-size: 12px; color: #409eff; cursor: pointer;
  padding: 2px 10px;
}
.show-more:hover { text-decoration: underline; }

.next-steps { display: flex; flex-direction: column; gap: 6px; }
.steps-list { margin: 0; padding: 0; list-style: none; display: flex; flex-direction: column; gap: 4px; }
.steps-list li { display: flex; align-items: flex-start; gap: 8px; font-size: 13px; color: #606266; padding: 4px 10px; }
.step-num {
  background: #409eff; color: #fff;
  width: 18px; height: 18px; border-radius: 50%;
  display: flex; align-items: center; justify-content: center;
  font-size: 11px; font-weight: 700; flex-shrink: 0; margin-top: 1px;
}
.step-text.clickable { color: #409eff; cursor: pointer; }
.step-text.clickable:hover { text-decoration: underline; }
</style>
