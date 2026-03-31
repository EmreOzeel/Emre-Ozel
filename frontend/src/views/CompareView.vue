<template>
  <div class="compare-page">
    <div class="compare-header">
      <h2>Baseline vs. Incident Compare</h2>
      <p class="subtitle">
        Select two completed analyses to compare findings, protocol distributions, and host changes.
      </p>
    </div>

    <!-- Selector -->
    <el-card shadow="never" class="selector-card">
      <div class="selector-row">
        <div class="selector-col">
          <div class="sel-label">Baseline (A)</div>
          <el-select
            v-model="selectedA"
            placeholder="Select baseline analysis"
            filterable
            :loading="loadingList"
            style="width: 100%"
          >
            <el-option
              v-for="a in completedAnalyses"
              :key="a.id"
              :label="`${a.filename} (${fmtDate(a.created_at)})`"
              :value="a.id"
              :disabled="a.id === selectedB"
            />
          </el-select>
        </div>
        <div class="vs-divider">VS</div>
        <div class="selector-col">
          <div class="sel-label">Incident (B)</div>
          <el-select
            v-model="selectedB"
            placeholder="Select incident analysis"
            filterable
            :loading="loadingList"
            style="width: 100%"
          >
            <el-option
              v-for="a in completedAnalyses"
              :key="a.id"
              :label="`${a.filename} (${fmtDate(a.created_at)})`"
              :value="a.id"
              :disabled="a.id === selectedA"
            />
          </el-select>
        </div>
        <el-button
          type="primary"
          :disabled="!selectedA || !selectedB"
          :loading="loadingCompare"
          @click="runCompare"
        >
          Compare
        </el-button>
      </div>
    </el-card>

    <!-- Error -->
    <el-alert v-if="error" type="error" :title="error" show-icon style="margin-top:12px" />

    <!-- Results -->
    <template v-if="result">

      <!-- Summary banner -->
      <el-alert
        :type="bannerType"
        :title="result.comparison_summary"
        show-icon
        :closable="false"
        class="summary-banner"
      />

      <!-- File comparison row -->
      <div class="two-col">
        <el-card shadow="never" class="file-card">
          <div class="file-label">A — {{ result.file_comparison.a.filename }}</div>
          <div class="file-stats">
            <span>{{ result.file_comparison.a.packets.toLocaleString() }} pkts</span>
            <span>{{ fmtDur(result.file_comparison.a.duration_sec) }}</span>
            <span>{{ fmtBytes(result.file_comparison.a.size_bytes) }}</span>
          </div>
          <div class="issue-badge">{{ result.issue_delta.a_total }} findings</div>
        </el-card>
        <el-card shadow="never" class="file-card">
          <div class="file-label">B — {{ result.file_comparison.b.filename }}</div>
          <div class="file-stats">
            <span>{{ result.file_comparison.b.packets.toLocaleString() }} pkts</span>
            <span>{{ fmtDur(result.file_comparison.b.duration_sec) }}</span>
            <span>{{ fmtBytes(result.file_comparison.b.size_bytes) }}</span>
          </div>
          <div class="issue-badge" :class="{ worse: result.issue_delta.b_total > result.issue_delta.a_total }">
            {{ result.issue_delta.b_total }} findings
            <span v-if="result.issue_delta.total !== 0" class="delta">
              {{ result.issue_delta.total > 0 ? '+' : '' }}{{ result.issue_delta.total }}
            </span>
          </div>
        </el-card>
      </div>

      <!-- Severity delta chips -->
      <div class="delta-chips">
        <div class="delta-chip" :class="critDeltaClass">
          <span class="dc-label">CRITICAL</span>
          <span class="dc-val">{{ fmtDelta(result.issue_delta.critical) }}</span>
        </div>
        <div class="delta-chip" :class="highDeltaClass">
          <span class="dc-label">HIGH</span>
          <span class="dc-val">{{ fmtDelta(result.issue_delta.high) }}</span>
        </div>
      </div>

      <!-- New findings in B -->
      <section v-if="result.new_findings?.length" class="diff-section">
        <h3 class="section-title danger">
          New findings in B ({{ result.new_findings.length }})
        </h3>
        <FindingCard
          v-for="f in result.new_findings"
          :key="f.id"
          :finding="f"
          class="diff-finding"
        />
      </section>

      <!-- Resolved findings (in A, not in B) -->
      <section v-if="result.resolved_findings?.length" class="diff-section">
        <h3 class="section-title success">
          Resolved since baseline ({{ result.resolved_findings.length }})
        </h3>
        <FindingCard
          v-for="f in result.resolved_findings"
          :key="f.id"
          :finding="f"
          class="diff-finding resolved"
        />
      </section>

      <!-- Protocol delta -->
      <section v-if="Object.keys(result.protocol_delta || {}).length" class="diff-section">
        <h3 class="section-title">Protocol distribution changes</h3>
        <div class="proto-delta-table">
          <div class="pdt-header">
            <span>Protocol</span><span>A</span><span>B</span><span>Change</span>
          </div>
          <div
            v-for="(d, proto) in result.protocol_delta"
            :key="proto"
            class="pdt-row"
          >
            <span class="pdt-proto">{{ proto }}</span>
            <span>{{ d.a.toLocaleString() }}</span>
            <span>{{ d.b.toLocaleString() }}</span>
            <span :class="d.b > d.a ? 'up' : 'down'">{{ d.change }}</span>
          </div>
        </div>
      </section>

      <!-- TCP quality delta -->
      <section class="diff-section" v-if="result.tcp_delta">
        <h3 class="section-title">TCP quality delta</h3>
        <div class="tcp-delta-grid">
          <div class="tdg-item">
            <span class="tdg-label">Retransmissions</span>
            <span>A: {{ result.tcp_delta.retransmissions.a }}</span>
            <span>B: {{ result.tcp_delta.retransmissions.b }}</span>
            <span :class="result.tcp_delta.retransmissions.b > result.tcp_delta.retransmissions.a ? 'up' : 'down'">
              {{ result.tcp_delta.retransmissions.change }}
            </span>
          </div>
          <div class="tdg-item">
            <span class="tdg-label">Failed handshakes</span>
            <span>A: {{ result.tcp_delta.failed_handshakes.a }}</span>
            <span>B: {{ result.tcp_delta.failed_handshakes.b }}</span>
          </div>
          <div class="tdg-item">
            <span class="tdg-label">Zero windows</span>
            <span>A: {{ result.tcp_delta.zero_windows.a }}</span>
            <span>B: {{ result.tcp_delta.zero_windows.b }}</span>
          </div>
        </div>
      </section>

      <!-- Host changes -->
      <section v-if="result.new_hosts?.length || result.removed_hosts?.length" class="diff-section">
        <h3 class="section-title">Host changes</h3>
        <div class="host-diff">
          <div v-if="result.new_hosts?.length" class="hd-group">
            <div class="hd-label danger">New hosts in B ({{ result.new_hosts.length }})</div>
            <el-tag v-for="h in result.new_hosts" :key="h" type="danger" size="small" plain>{{ h }}</el-tag>
          </div>
          <div v-if="result.removed_hosts?.length" class="hd-group">
            <div class="hd-label success">No longer seen ({{ result.removed_hosts.length }})</div>
            <el-tag v-for="h in result.removed_hosts" :key="h" type="success" size="small" plain>{{ h }}</el-tag>
          </div>
        </div>
      </section>

    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import api from '@/api/index.js'
import type { CompareResult } from '@/types/analysis'
import FindingCard from '@/components/analysis/FindingCard.vue'

interface AnalysisSummary {
  id: string
  filename: string
  status: string
  created_at: string
}

const completedAnalyses = ref<AnalysisSummary[]>([])
const loadingList = ref(false)
const loadingCompare = ref(false)
const selectedA = ref('')
const selectedB = ref('')
const result = ref<CompareResult | null>(null)
const error = ref('')

onMounted(async () => {
  loadingList.value = true
  try {
    const res = await api.get('/analyses')
    completedAnalyses.value = (res.data || []).filter(
      (a: AnalysisSummary) => a.status === 'completed'
    )
  } catch (e) {
    error.value = 'Failed to load analyses list.'
  } finally {
    loadingList.value = false
  }
})

async function runCompare() {
  if (!selectedA.value || !selectedB.value) return
  error.value = ''
  result.value = null
  loadingCompare.value = true
  try {
    const res = await api.get('/analyses/compare', {
      params: { a: selectedA.value, b: selectedB.value },
    })
    result.value = res.data
  } catch (e: any) {
    error.value = e?.response?.data?.detail || 'Compare failed.'
  } finally {
    loadingCompare.value = false
  }
}

const bannerType = computed(() => {
  if (!result.value) return 'info'
  if (result.value.issue_delta.critical > 0) return 'error'
  if (result.value.issue_delta.high > 0) return 'warning'
  if (result.value.issue_delta.total < 0) return 'success'
  return 'info'
})

const critDeltaClass = computed(() => {
  const d = result.value?.issue_delta.critical ?? 0
  return d > 0 ? 'chip-danger' : d < 0 ? 'chip-success' : 'chip-neutral'
})

const highDeltaClass = computed(() => {
  const d = result.value?.issue_delta.high ?? 0
  return d > 0 ? 'chip-warning' : d < 0 ? 'chip-success' : 'chip-neutral'
})

function fmtDelta(n: number): string {
  if (n === 0) return '±0'
  return (n > 0 ? '+' : '') + n
}

function fmtDate(iso: string | null): string {
  if (!iso) return ''
  return new Date(iso).toLocaleDateString()
}

function fmtDur(s: number): string {
  if (!s) return '—'
  if (s < 60) return `${s.toFixed(1)}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}

function fmtBytes(b: number): string {
  if (!b) return '0 B'
  if (b < 1024) return b + ' B'
  if (b < 1024 ** 2) return (b / 1024).toFixed(1) + ' KB'
  if (b < 1024 ** 3) return (b / 1024 ** 2).toFixed(1) + ' MB'
  return (b / 1024 ** 3).toFixed(2) + ' GB'
}
</script>

<style scoped>
.compare-page { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
.compare-header h2 { margin: 0 0 4px; font-size: 20px; }
.subtitle { color: #909399; margin: 0 0 16px; font-size: 13px; }

.selector-card { margin-bottom: 16px; }
.selector-row { display: flex; align-items: flex-end; gap: 12px; flex-wrap: wrap; }
.selector-col { flex: 1; min-width: 220px; }
.sel-label { font-size: 12px; font-weight: 600; color: #606266; margin-bottom: 4px; }
.vs-divider { font-weight: 700; color: #909399; padding: 0 4px; margin-bottom: 2px; }

.summary-banner { margin: 12px 0; }

.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 12px 0; }
.file-card { padding: 4px; }
.file-label { font-weight: 700; font-size: 13px; margin-bottom: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-stats { display: flex; gap: 12px; font-size: 12px; color: #606266; margin-bottom: 6px; }
.issue-badge {
  display: inline-flex; align-items: center; gap: 4px;
  font-size: 13px; font-weight: 700; color: #606266;
}
.issue-badge.worse { color: #f56c6c; }
.delta { font-size: 11px; color: #f56c6c; }

.delta-chips { display: flex; gap: 8px; margin: 8px 0 16px; }
.delta-chip {
  display: flex; align-items: center; gap: 8px; padding: 6px 12px;
  border-radius: 6px; font-size: 12px; font-weight: 700;
}
.chip-danger  { background: #fef0f0; color: #f56c6c; }
.chip-warning { background: #fdf6ec; color: #e6a23c; }
.chip-success { background: #f0f9eb; color: #67c23a; }
.chip-neutral { background: #f4f4f5; color: #909399; }
.dc-label { letter-spacing: .05em; font-size: 10px; }
.dc-val { font-size: 16px; }

.diff-section { margin: 20px 0; }
.section-title {
  font-size: 14px; font-weight: 700; margin: 0 0 10px;
  color: #303133; padding-bottom: 6px; border-bottom: 1px solid #ebeef5;
}
.section-title.danger { color: #f56c6c; }
.section-title.success { color: #67c23a; }

.diff-finding { margin-bottom: 10px; }
.diff-finding.resolved { opacity: 0.65; filter: grayscale(40%); }

/* Protocol delta table */
.proto-delta-table { font-size: 12px; }
.pdt-header {
  display: grid; grid-template-columns: 2fr 1fr 1fr 1fr;
  font-weight: 700; color: #909399; padding: 4px 0; border-bottom: 1px solid #ebeef5;
}
.pdt-row {
  display: grid; grid-template-columns: 2fr 1fr 1fr 1fr;
  padding: 4px 0; border-bottom: 1px solid #f5f5f5;
}
.pdt-proto { font-family: monospace; color: #409eff; }
.up { color: #f56c6c; }
.down { color: #67c23a; }

/* TCP delta */
.tcp-delta-grid { display: flex; gap: 20px; flex-wrap: wrap; }
.tdg-item { display: flex; flex-direction: column; gap: 2px; font-size: 12px; }
.tdg-label { font-weight: 700; color: #606266; margin-bottom: 2px; }

/* Host diff */
.host-diff { display: flex; gap: 24px; flex-wrap: wrap; }
.hd-group { display: flex; flex-direction: column; gap: 6px; }
.hd-label { font-size: 11px; font-weight: 700; text-transform: uppercase; }
.hd-label.danger { color: #f56c6c; }
.hd-label.success { color: #67c23a; }
</style>
