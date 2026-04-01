<template>
  <div class="finding-card" :class="`sev-${finding.severity}`">
    <!-- Header row -->
    <div class="finding-header">
      <el-tag :type="sevType" effect="dark" size="small">
        {{ finding.severity.toUpperCase() }}
      </el-tag>
      <el-tag size="small" type="info">{{ finding.category }}</el-tag>
      <el-tag size="small" :type="confType" plain>
        Confidence: {{ finding.confidence }}
      </el-tag>
      <el-tag size="small" plain>Score {{ finding.score?.toFixed(1) }}</el-tag>
      <span class="finding-title">{{ finding.title }}</span>
    </div>

    <!-- Short description -->
    <p class="finding-desc">{{ finding.description }}</p>

    <!-- What is happening -->
    <div class="interp-block blue" v-if="finding.explanation">
      <div class="iblock-label">What is happening</div>
      <p>{{ finding.explanation }}</p>
    </div>

    <!-- Confidence reasoning -->
    <div class="interp-block slate" v-if="finding.confidence_note">
      <div class="iblock-label">Confidence reasoning</div>
      <p>{{ finding.confidence_note }}</p>
    </div>

    <!-- Evidence block — metrics, time window, packet refs, samples -->
    <div class="evidence-block" v-if="hasEvidence">
      <div class="iblock-label">Evidence</div>

      <!-- Metrics table -->
      <div class="metrics-table" v-if="evidenceMetrics.length">
        <div class="metric-row" v-for="m in evidenceMetrics" :key="m.key">
          <span class="metric-key">{{ m.key }}</span>
          <span class="metric-val">{{ m.value }}</span>
        </div>
      </div>

      <!-- Time window -->
      <div class="evidence-meta" v-if="finding.evidence.time_first">
        <span class="meta-badge">
          Window: {{ fmtTs(finding.evidence.time_first) }} – {{ fmtTs(finding.evidence.time_last) }}
        </span>
        <span class="meta-badge" v-if="finding.evidence.packet_nums?.length">
          {{ finding.evidence.packet_nums.length }} packet ref(s)
        </span>
        <span class="meta-badge" v-if="finding.evidence.flow_keys?.length">
          {{ finding.evidence.flow_keys.length }} flow(s)
        </span>
      </div>

      <!-- Samples -->
      <div class="samples-row" v-if="finding.evidence.samples?.length">
        <code v-for="(s, i) in finding.evidence.samples.slice(0, 6)" :key="i">{{ s }}</code>
      </div>
    </div>

    <!-- Affected hosts -->
    <div class="affected-row" v-if="finding.affected_hosts?.length">
      <span class="iblock-label">Affected hosts:</span>
      <el-tag
        v-for="h in finding.affected_hosts.slice(0, 6)"
        :key="h" size="small" type="danger" plain
      >{{ h }}</el-tag>
    </div>

    <!-- MITRE ATT&CK -->
    <div class="mitre-row" v-if="finding.mitre?.length">
      <a
        v-for="m in finding.mitre.slice(0, 4)"
        :key="m.technique_id"
        :href="m.url"
        target="_blank"
        class="mitre-badge"
      >
        {{ m.technique_id }}: {{ m.technique_name }}
      </a>
    </div>

    <!-- Likely root causes -->
    <div class="interp-block amber" v-if="finding.possible_causes?.length">
      <div class="iblock-label">Likely root causes</div>
      <ul>
        <li v-for="(c, i) in finding.possible_causes" :key="i">{{ c }}</li>
      </ul>
    </div>

    <!-- Recommended actions -->
    <div class="actions-block" v-if="finding.recommended_actions?.length">
      <div class="iblock-label">Recommended actions</div>
      <ul>
        <li v-for="(a, i) in finding.recommended_actions" :key="i">{{ a }}</li>
      </ul>
    </div>

    <!-- Analyst triage -->
    <div class="triage-row" v-if="analysisId">
      <span class="triage-label">Triage:</span>
      <el-select
        v-model="triageStatus"
        size="small"
        style="width: 160px"
        :class="`triage-sel triage-${triageStatus}`"
        @change="saveTriage"
      >
        <el-option value="new" label="New" />
        <el-option value="acknowledged" label="Acknowledged" />
        <el-option value="in_progress" label="In Progress" />
        <el-option value="resolved" label="Resolved" />
        <el-option value="false_positive" label="False Positive" />
      </el-select>
      <el-input
        v-if="showTriageNote"
        v-model="triageNote"
        size="small"
        placeholder="Analyst note…"
        style="flex: 1; min-width: 180px"
        @blur="saveTriage"
      />
      <el-button size="small" plain text @click="showTriageNote = !showTriageNote">
        {{ showTriageNote ? 'Hide note' : 'Add note' }}
      </el-button>
    </div>

    <!-- Quick suppress -->
    <div class="suppress-row" v-if="!finding.suppressed && finding.rule_id">
      <el-button size="small" plain type="info" @click="emit('suppress', finding)">
        Suppress this rule ({{ finding.rule_id }})
      </el-button>
    </div>
    <div class="suppressed-badge" v-if="finding.suppressed">
      <el-tag type="info" size="small" effect="plain">Suppressed</el-tag>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import api from '@/api'
import type { Finding, FindingTriage, TriageStatus } from '@/types/analysis'

const props = defineProps<{
  finding: Finding
  analysisId?: string
  initialTriage?: FindingTriage | null
}>()
const emit = defineEmits<{ (e: 'suppress', finding: Finding): void }>()

// ── Triage state ──────────────────────────────────────────────────────────────
const findingKey = computed(() => {
  const host = props.finding.affected_hosts?.[0] ?? 'unknown'
  return `${props.finding.rule_id}|${host}`
})

const triageStatus = ref<TriageStatus>(props.initialTriage?.status ?? 'new')
const triageNote = ref<string>(props.initialTriage?.note ?? '')
const showTriageNote = ref(false)

async function saveTriage() {
  if (!props.analysisId) return
  try {
    await api.put(
      `/analyses/${props.analysisId}/triage/${encodeURIComponent(findingKey.value)}`,
      { status: triageStatus.value, note: triageNote.value || null },
    )
  } catch {
    ElMessage.error('Failed to save triage state')
  }
}

const sevType = computed(() => {
  const m: Record<string, string> = {
    critical: 'danger', high: 'warning', medium: 'warning', low: 'info', info: 'info',
  }
  return m[props.finding.severity] ?? 'info'
})

const confType = computed(() => {
  if (props.finding.confidence === 'high') return 'success'
  if (props.finding.confidence === 'medium') return 'warning'
  return 'info'
})

const hasEvidence = computed(() => {
  const ev = props.finding.evidence
  if (!ev) return false
  return (
    Object.keys(ev.metrics || {}).length > 0 ||
    ev.samples?.length > 0 ||
    ev.time_first > 0 ||
    ev.packet_nums?.length > 0
  )
})

const evidenceMetrics = computed(() => {
  const m = props.finding.evidence?.metrics || {}
  return Object.entries(m).map(([key, value]) => ({
    key: key.replace(/_/g, ' '),
    value: typeof value === 'number' && !Number.isInteger(value)
      ? (value as number).toFixed(4)
      : String(value),
  }))
})

function fmtTs(epoch: number): string {
  if (!epoch) return '—'
  return new Date(epoch * 1000).toISOString().replace('T', ' ').slice(0, 19) + 'Z'
}
</script>

<style scoped>
.finding-card {
  border: 1px solid #ebeef5; border-left: 4px solid #dcdfe6;
  border-radius: 6px; padding: 14px 16px; background: #fff;
}
.sev-critical { border-left-color: #f56c6c; }
.sev-high     { border-left-color: #e6a23c; }
.sev-medium   { border-left-color: #f0c040; }
.sev-low      { border-left-color: #409eff; }
.sev-info     { border-left-color: #909399; }

.finding-header { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
.finding-title  { font-weight: 600; font-size: 14px; flex: 1; min-width: 200px; }
.finding-desc   { font-size: 13px; color: #606266; margin: 0 0 10px; line-height: 1.6; }

.interp-block { border-radius: 0 4px 4px 0; padding: 8px 12px; margin: 8px 0; font-size: 13px; line-height: 1.7; }
.interp-block.blue  { background: #f0f9ff; border-left: 3px solid #409eff; }
.interp-block.amber { background: #fdf6ec; border-left: 3px solid #e6a23c; }
.interp-block.slate { background: #f4f4f5; border-left: 3px solid #909399; }
.interp-block p { margin: 0; }
.interp-block ul { margin: 0; padding-left: 18px; color: #606266; }
.interp-block li { margin: 2px 0; }

.iblock-label {
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .05em; color: #909399; margin-bottom: 4px;
}

/* ── Evidence block ─────────────────────────────────────────── */
.evidence-block {
  background: #fafafa; border: 1px solid #ebeef5; border-radius: 4px;
  padding: 8px 12px; margin: 8px 0;
}

.metrics-table { display: grid; grid-template-columns: auto 1fr; gap: 2px 16px; margin-bottom: 6px; }
.metric-row { display: contents; }
.metric-key {
  font-size: 12px; color: #909399; font-family: monospace; white-space: nowrap;
}
.metric-val {
  font-size: 12px; color: #303133; font-weight: 600; font-family: monospace;
}

.evidence-meta { display: flex; flex-wrap: wrap; gap: 6px; margin: 4px 0; }
.meta-badge {
  font-size: 11px; color: #606266; background: #ecf5ff;
  border: 1px solid #c6e2ff; border-radius: 3px; padding: 1px 6px;
}

.samples-row { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }
.samples-row code {
  background: #f5f7fa; padding: 2px 6px; border-radius: 3px;
  font-size: 11px; color: #606266; font-family: monospace;
  max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}

/* ── Affected hosts ─────────────────────────────────────────── */
.affected-row { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; margin: 6px 0; }
.affected-row .iblock-label { margin-bottom: 0; }

/* ── MITRE ──────────────────────────────────────────────────── */
.mitre-row { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
.mitre-badge {
  display: inline-flex; padding: 2px 8px; background: #ecf5ff;
  border: 1px solid #c6e2ff; border-radius: 3px; font-size: 11px;
  color: #409eff; text-decoration: none;
}
.mitre-badge:hover { background: #c6e2ff; }

/* ── Actions ────────────────────────────────────────────────── */
.actions-block { background: #f0f9eb; border-radius: 4px; padding: 8px 12px; margin-top: 8px; font-size: 13px; }
.actions-block ul { margin: 0; padding-left: 18px; color: #529b2e; line-height: 1.8; }

/* ── Triage ─────────────────────────────────────────────────── */
.triage-row {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  margin-top: 10px; padding: 6px 10px;
  background: #f9f9fb; border: 1px solid #ebeef5; border-radius: 4px;
}
.triage-label { font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .05em; color: #909399; white-space: nowrap; }

/* Triage select accent colors */
.triage-sel.triage-resolved :deep(.el-input__wrapper) { border-color: #67c23a; }
.triage-sel.triage-false_positive :deep(.el-input__wrapper) { border-color: #909399; }
.triage-sel.triage-in_progress :deep(.el-input__wrapper) { border-color: #e6a23c; }
.triage-sel.triage-acknowledged :deep(.el-input__wrapper) { border-color: #409eff; }

/* ── Suppress ───────────────────────────────────────────────── */
.suppress-row { margin-top: 10px; }
.suppressed-badge { margin-top: 8px; }
</style>
