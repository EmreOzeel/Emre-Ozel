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

    <!-- ══════════════════════════════════════════════════════════════════════
         Path Compare Mode
         ══════════════════════════════════════════════════════════════════ -->
    <el-divider>
      <span class="path-compare-divider-label">Path Compare Mode</span>
    </el-divider>

    <div class="compare-header" style="margin-top: 0">
      <p class="subtitle">
        Trace the same src → dst path across both captures and surface exactly what changed.
      </p>
    </div>

    <!-- Path inputs -->
    <el-card shadow="never" class="selector-card">
      <el-form :inline="true" size="small" class="path-form">
        <el-form-item label="Source IP" required>
          <el-input
            v-model="pathForm.source_ip"
            placeholder="e.g. 10.0.0.5"
            clearable
            style="width: 160px"
          />
        </el-form-item>
        <el-form-item label="Destination IP" required>
          <el-input
            v-model="pathForm.destination_ip"
            placeholder="e.g. 10.0.0.1"
            clearable
            style="width: 160px"
          />
        </el-form-item>
        <el-form-item label="Port">
          <el-input
            v-model="pathForm.destination_port_raw"
            placeholder="optional"
            clearable
            style="width: 90px"
          />
        </el-form-item>
        <el-form-item>
          <el-button
            type="primary"
            :disabled="!selectedA || !selectedB || !pathForm.source_ip.trim() || !pathForm.destination_ip.trim()"
            :loading="loadingPathCompare"
            @click="runPathCompare"
          >
            Compare Path
          </el-button>
          <el-button
            v-if="pathResult"
            plain
            @click="pathResult = null; pathError = ''"
          >Clear</el-button>
        </el-form-item>
      </el-form>
      <p v-if="!selectedA || !selectedB" class="path-hint">
        Select baseline and incident analyses above first.
      </p>
      <el-alert
        v-if="pathError"
        type="error"
        :title="pathError"
        show-icon
        :closable="false"
        style="margin-top: 8px"
      />
    </el-card>

    <!-- Path compare results -->
    <template v-if="pathResult">

      <!-- Regression alert -->
      <el-alert
        v-if="pathResult.outcome_regression"
        type="error"
        show-icon
        :closable="false"
        class="regression-alert"
      >
        <template #title>
          <span class="regression-title">Regression detected</span>
        </template>
        <template #default>
          <p v-if="pathResult.most_likely_regression_point" class="regression-point">
            {{ pathResult.most_likely_regression_point }}
          </p>
          <ul class="regression-diffs">
            <li v-for="(d, i) in pathResult.key_differences" :key="i">{{ d }}</li>
          </ul>
        </template>
      </el-alert>

      <!-- Improvement notice -->
      <el-alert
        v-else-if="pathResult.outcome_changed"
        type="success"
        title="Outcome changed (improvement)"
        show-icon
        :closable="false"
        style="margin-bottom: 8px"
      >
        <template #default>
          <ul class="regression-diffs">
            <li v-for="(d, i) in pathResult.key_differences" :key="i">{{ d }}</li>
          </ul>
        </template>
      </el-alert>

      <!-- No change notice -->
      <el-alert
        v-else
        type="info"
        title="No significant change detected"
        show-icon
        :closable="false"
        style="margin-bottom: 8px"
      />

      <!-- Side-by-side summary -->
      <div class="path-side-by-side">
        <el-card shadow="never" class="path-side-card baseline-side">
          <template #header>
            <span class="psc-title">Baseline</span>
            <span class="psc-sub">{{ selectedALabel }}</span>
          </template>
          <div class="psc-row">
            <span class="psc-label">Outcome</span>
            <span class="psc-val" :class="outcomeClass(pathResult.baseline_summary.connection_outcome)">
              {{ fmtOutcome(pathResult.baseline_summary.connection_outcome) }}
            </span>
          </div>
          <div class="psc-row">
            <span class="psc-label">Primary Impairment</span>
            <span class="psc-val">
              {{ pathResult.baseline_summary.primary_impairment
                 ? fmtToken(pathResult.baseline_summary.primary_impairment)
                 : '—' }}
            </span>
          </div>
          <div class="psc-row">
            <span class="psc-label">Confidence</span>
            <span class="psc-val">{{ pathResult.baseline_summary.path_confidence_score }}%</span>
          </div>
          <p class="psc-summary">{{ pathResult.baseline_summary.path_summary }}</p>
        </el-card>

        <div class="path-vs-col">
          <div class="path-vs-badge">VS</div>
          <div
            v-if="pathResult.outcome_regression"
            class="path-arrow-badge danger"
            title="Regression"
          >▼</div>
          <div
            v-else-if="pathResult.outcome_changed"
            class="path-arrow-badge success"
            title="Improvement"
          >▲</div>
        </div>

        <el-card shadow="never" class="path-side-card incident-side"
          :class="{ 'incident-regressed': pathResult.outcome_regression }">
          <template #header>
            <span class="psc-title">Incident</span>
            <span class="psc-sub">{{ selectedBLabel }}</span>
          </template>
          <div class="psc-row">
            <span class="psc-label">Outcome</span>
            <span class="psc-val" :class="outcomeClass(pathResult.incident_summary.connection_outcome)">
              {{ fmtOutcome(pathResult.incident_summary.connection_outcome) }}
            </span>
          </div>
          <div class="psc-row">
            <span class="psc-label">Primary Impairment</span>
            <span class="psc-val" :class="pathResult.incident_summary.primary_impairment ? 'impairment-val' : ''">
              {{ pathResult.incident_summary.primary_impairment
                 ? fmtToken(pathResult.incident_summary.primary_impairment)
                 : '—' }}
            </span>
          </div>
          <div class="psc-row">
            <span class="psc-label">Confidence</span>
            <span class="psc-val"
              :class="pathResult.confidence_changes.worsened ? 'conf-worse' : 'conf-same'"
            >
              {{ pathResult.incident_summary.path_confidence_score }}%
              <span v-if="pathResult.confidence_changes.delta !== 0" class="conf-delta">
                ({{ pathResult.confidence_changes.delta > 0 ? '+' : '' }}{{ pathResult.confidence_changes.delta }})
              </span>
            </span>
          </div>
          <p class="psc-summary">{{ pathResult.incident_summary.path_summary }}</p>
        </el-card>
      </div>

      <!-- Impairment changes -->
      <el-card
        v-if="pathResult.impairment_changes.new.length || pathResult.impairment_changes.resolved.length || pathResult.impairment_changes.persisting.length"
        shadow="never"
        class="path-result-card"
      >
        <template #header><span class="card-title">Impairment Changes</span></template>
        <div class="imp-groups">
          <div v-if="pathResult.impairment_changes.new.length" class="imp-group">
            <div class="imp-group-label danger">New (incident only)</div>
            <div class="imp-tags">
              <el-tag
                v-for="imp in pathResult.impairment_changes.new"
                :key="imp"
                type="danger"
                size="small"
                effect="dark"
                style="margin: 3px"
              >{{ fmtToken(imp) }}</el-tag>
            </div>
          </div>
          <div v-if="pathResult.impairment_changes.resolved.length" class="imp-group">
            <div class="imp-group-label success">Resolved (baseline only)</div>
            <div class="imp-tags">
              <el-tag
                v-for="imp in pathResult.impairment_changes.resolved"
                :key="imp"
                type="success"
                size="small"
                style="margin: 3px"
              >{{ fmtToken(imp) }}</el-tag>
            </div>
          </div>
          <div v-if="pathResult.impairment_changes.persisting.length" class="imp-group">
            <div class="imp-group-label warning">Persisting (both)</div>
            <div class="imp-tags">
              <el-tag
                v-for="imp in pathResult.impairment_changes.persisting"
                :key="imp"
                type="warning"
                size="small"
                style="margin: 3px"
              >{{ fmtToken(imp) }}</el-tag>
            </div>
          </div>
        </div>
      </el-card>

      <!-- Timing deltas -->
      <el-card
        v-if="Object.keys(pathResult.timing_differences).length"
        shadow="never"
        class="path-result-card"
      >
        <template #header><span class="card-title">Timing Deltas</span></template>
        <div class="timing-table">
          <div class="timing-header">
            <span>Metric</span>
            <span>Baseline (ms)</span>
            <span>Incident (ms)</span>
            <span>Delta</span>
          </div>
          <div
            v-for="(td, key) in pathResult.timing_differences"
            :key="key"
            class="timing-row"
            :class="{ 'timing-worsened': td.worsened }"
          >
            <span class="timing-key">{{ fmtTimingKey(key) }}</span>
            <span>{{ td.baseline }}</span>
            <span>{{ td.incident }}</span>
            <span :class="td.worsened ? 'timing-delta-bad' : 'timing-delta-good'">
              {{ td.delta > 0 ? '+' : '' }}{{ td.delta }}
            </span>
          </div>
        </div>
      </el-card>

      <!-- Evidence differences -->
      <el-card
        v-if="pathResult.evidence_differences.incident_only.length || pathResult.evidence_differences.baseline_only.length"
        shadow="never"
        class="path-result-card"
      >
        <template #header><span class="card-title">Evidence Changes</span></template>
        <div class="imp-groups">
          <div v-if="pathResult.evidence_differences.incident_only.length" class="imp-group">
            <div class="imp-group-label danger">New evidence in incident</div>
            <div class="imp-tags">
              <el-tag
                v-for="t in pathResult.evidence_differences.incident_only"
                :key="t"
                type="warning"
                size="small"
                style="margin: 3px"
              >{{ fmtToken(t) }}</el-tag>
            </div>
          </div>
          <div v-if="pathResult.evidence_differences.baseline_only.length" class="imp-group">
            <div class="imp-group-label">Evidence no longer seen</div>
            <div class="imp-tags">
              <el-tag
                v-for="t in pathResult.evidence_differences.baseline_only"
                :key="t"
                type="info"
                size="small"
                style="margin: 3px"
              >{{ fmtToken(t) }}</el-tag>
            </div>
          </div>
        </div>
      </el-card>

    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted } from 'vue'
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

// ── Path compare ──────────────────────────────────────────────────────────────

interface PathCompareResult {
  baseline_analysis_id: string
  incident_analysis_id: string
  source_ip: string
  destination_ip: string
  destination_port: number | null
  baseline_summary: {
    connection_outcome: string
    primary_impairment: string | null
    path_impairments: string[]
    path_confidence_score: number
    path_summary: string
    likely_failure_point: string
  }
  incident_summary: {
    connection_outcome: string
    primary_impairment: string | null
    path_impairments: string[]
    path_confidence_score: number
    path_summary: string
    likely_failure_point: string
  }
  outcome_changed: boolean
  outcome_regression: boolean
  key_differences: string[]
  impairment_changes: {
    new: string[]
    resolved: string[]
    persisting: string[]
  }
  timing_differences: Record<string, {
    baseline: number
    incident: number
    delta: number
    worsened: boolean
  }>
  confidence_changes: {
    baseline: number
    incident: number
    delta: number
    worsened: boolean
  }
  evidence_differences: {
    baseline_only: string[]
    incident_only: string[]
  }
  most_likely_regression_point: string | null
}

const pathForm = reactive({
  source_ip: '',
  destination_ip: '',
  destination_port_raw: '',
})

const loadingPathCompare = ref(false)
const pathResult = ref<PathCompareResult | null>(null)
const pathError = ref('')

const selectedALabel = computed(() => {
  const a = completedAnalyses.value.find(x => x.id === selectedA.value)
  return a ? a.filename : selectedA.value
})
const selectedBLabel = computed(() => {
  const b = completedAnalyses.value.find(x => x.id === selectedB.value)
  return b ? b.filename : selectedB.value
})

async function runPathCompare() {
  if (!selectedA.value || !selectedB.value) return
  if (!pathForm.source_ip.trim() || !pathForm.destination_ip.trim()) return

  pathError.value  = ''
  pathResult.value = null
  loadingPathCompare.value = true

  const payload: Record<string, any> = {
    baseline_analysis_id: selectedA.value,
    incident_analysis_id: selectedB.value,
    source_ip:            pathForm.source_ip.trim(),
    destination_ip:       pathForm.destination_ip.trim(),
  }
  const port = parseInt(pathForm.destination_port_raw, 10)
  if (!isNaN(port) && port > 0 && port <= 65535) payload.destination_port = port

  try {
    const res = await api.post('/path-analysis/compare', payload)
    pathResult.value = res.data
  } catch (e: any) {
    pathError.value = e?.response?.data?.detail || 'Path compare failed.'
  } finally {
    loadingPathCompare.value = false
  }
}

function fmtOutcome(o: string): string {
  const map: Record<string, string> = {
    success: 'Success', partial_success: 'Partial Success',
    failure: 'Failure', unknown: 'Unknown',
  }
  return map[o] ?? o
}

function outcomeClass(o: string): string {
  if (o === 'success')         return 'outcome-success'
  if (o === 'failure')         return 'outcome-failure'
  if (o === 'partial_success') return 'outcome-warning'
  return ''
}

function fmtToken(tok: string): string {
  return tok.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function fmtTimingKey(key: string): string {
  return key.replace(/_ms$/, '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
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

/* ── Path Compare ───────────────────────────────────────────────────────── */
.path-compare-divider-label {
  font-size: 13px; font-weight: 700; color: #409eff; letter-spacing: .04em;
}

.path-form { display: flex; flex-wrap: wrap; align-items: flex-end; gap: 4px; }
.path-hint { margin: 6px 0 0; font-size: 12px; color: #c0c4cc; }

/* regression alert */
.regression-alert { margin-bottom: 12px; }
.regression-title { font-size: 14px; font-weight: 700; }
.regression-point {
  margin: 4px 0 6px; font-size: 13px; font-weight: 600; color: #f56c6c;
}
.regression-diffs {
  margin: 0; padding-left: 18px; font-size: 13px; color: #606266;
}
.regression-diffs li { margin-bottom: 3px; }

/* side-by-side cards */
.path-side-by-side {
  display: grid;
  grid-template-columns: 1fr auto 1fr;
  gap: 0;
  align-items: start;
  margin: 12px 0;
}

.path-side-card { height: 100%; }
.path-side-card :deep(.el-card__header) {
  display: flex; flex-direction: column; gap: 2px;
  padding: 10px 16px;
}
.psc-title  { font-weight: 700; font-size: 13px; }
.psc-sub    { font-size: 11px; color: #909399; word-break: break-all; }
.psc-row    { display: flex; justify-content: space-between; align-items: baseline;
              font-size: 12px; padding: 5px 0; border-bottom: 1px solid #f4f4f5; }
.psc-row:last-of-type { border-bottom: none; }
.psc-label  { color: #909399; }
.psc-val    { font-weight: 600; font-size: 13px; }
.psc-summary { font-size: 12px; color: #606266; margin: 8px 0 0; line-height: 1.5; }

.outcome-success { color: #67c23a !important; }
.outcome-failure { color: #f56c6c !important; }
.outcome-warning { color: #e6a23c !important; }
.impairment-val  { color: #f56c6c !important; }
.conf-worse  { color: #f56c6c !important; }
.conf-same   { color: #303133; }
.conf-delta  { font-size: 11px; font-weight: 400; }

.incident-regressed { border-color: #f56c6c !important; }
.incident-regressed :deep(.el-card__header) { background: #fff0f0; }

/* VS column */
.path-vs-col {
  display: flex; flex-direction: column; align-items: center;
  justify-content: center; gap: 8px; padding: 0 12px;
  min-width: 48px;
}
.path-vs-badge {
  font-weight: 700; font-size: 13px; color: #c0c4cc;
}
.path-arrow-badge {
  font-size: 20px; font-weight: 900;
}
.path-arrow-badge.danger  { color: #f56c6c; }
.path-arrow-badge.success { color: #67c23a; }

/* path result cards */
.path-result-card { margin-top: 12px; }
.path-result-card :deep(.el-card__header) { padding: 10px 16px; }
.card-title { font-weight: 600; font-size: 14px; }

/* impairment groups */
.imp-groups { display: flex; flex-direction: column; gap: 12px; }
.imp-group  { display: flex; flex-direction: column; gap: 6px; }
.imp-group-label {
  font-size: 11px; font-weight: 700; text-transform: uppercase; color: #606266;
}
.imp-group-label.danger  { color: #f56c6c; }
.imp-group-label.success { color: #67c23a; }
.imp-group-label.warning { color: #e6a23c; }
.imp-tags { display: flex; flex-wrap: wrap; }

/* timing table */
.timing-table  { font-size: 12px; }
.timing-header {
  display: grid; grid-template-columns: 2fr 1fr 1fr 1fr;
  font-weight: 700; color: #909399;
  padding: 4px 0; border-bottom: 1px solid #ebeef5;
}
.timing-row {
  display: grid; grid-template-columns: 2fr 1fr 1fr 1fr;
  padding: 5px 0; border-bottom: 1px solid #f5f5f5;
}
.timing-row.timing-worsened { background: #fff9f9; }
.timing-key      { font-family: monospace; color: #409eff; }
.timing-delta-bad  { color: #f56c6c; font-weight: 700; }
.timing-delta-good { color: #67c23a; font-weight: 700; }
</style>
