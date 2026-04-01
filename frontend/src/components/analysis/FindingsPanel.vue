<template>
  <div class="findings-panel">
    <!-- Filters -->
    <div class="filters-row">
      <el-select v-model="filters.severity" placeholder="All severities" clearable size="small" style="width:150px">
        <el-option label="Critical" value="critical" />
        <el-option label="High" value="high" />
        <el-option label="Medium" value="medium" />
        <el-option label="Low" value="low" />
        <el-option label="Info" value="info" />
      </el-select>
      <el-select v-model="filters.category" placeholder="All categories" clearable size="small" style="width:170px">
        <el-option v-for="c in categories" :key="c" :label="c" :value="c" />
      </el-select>
      <el-input
        v-model="filters.search"
        placeholder="Search findings..."
        size="small"
        clearable
        style="width:220px"
      />
      <span class="result-count">{{ filtered.length }} finding(s)</span>
    </div>

    <!-- Empty state -->
    <div class="empty-state" v-if="!filtered.length">
      <el-icon size="48" color="#67c23a"><CircleCheck /></el-icon>
      <p>No findings match the current filters.</p>
    </div>

    <!-- Grouped by severity -->
    <template v-else>
      <div
        v-for="sev in severityOrder"
        :key="sev"
      >
        <div
          v-if="bySeverity[sev]?.length"
          class="sev-group"
        >
          <div class="sev-group-header">
            <el-tag :type="sevTagType(sev)" effect="dark" size="small">
              {{ sev.toUpperCase() }}
            </el-tag>
            <span class="group-count">{{ bySeverity[sev].length }} finding(s)</span>
          </div>
          <div class="group-cards">
            <FindingCard
              v-for="f in bySeverity[sev]"
              :key="f.id"
              :finding="f"
              :analysis-id="analysisId"
              :initial-triage="triageMap[`${f.rule_id}|${f.affected_hosts?.[0] ?? 'unknown'}`] ?? null"
              @suppress="openSuppressDialog"
            />
          </div>
        </div>
      </div>
    </template>
    <!-- Suppress dialog -->
    <el-dialog v-model="suppressDialog.visible" title="Suppress Rule" width="440px" :close-on-click-modal="false">
      <p class="suppress-desc">
        Creating a suppression for <el-tag size="small" type="warning">{{ suppressDialog.ruleId }}</el-tag>.
        This will hide matching findings in future analyses.
      </p>
      <el-form :model="suppressDialog" label-width="80px">
        <el-form-item label="Src IP">
          <el-input v-model="suppressDialog.srcIp" placeholder="leave blank to match any" clearable />
        </el-form-item>
        <el-form-item label="Dst IP">
          <el-input v-model="suppressDialog.dstIp" placeholder="leave blank to match any" clearable />
        </el-form-item>
        <el-form-item label="Reason">
          <el-input v-model="suppressDialog.reason" placeholder="Why is this a false positive?" />
        </el-form-item>
      </el-form>
      <el-alert v-if="suppressDialog.error" type="error" :title="suppressDialog.error" :closable="false" style="margin-top:8px" />
      <template #footer>
        <el-button @click="suppressDialog.visible = false">Cancel</el-button>
        <el-button type="primary" :loading="suppressDialog.saving" @click="submitSuppress">Suppress</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, reactive } from 'vue'
import { CircleCheck } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import FindingCard from './FindingCard.vue'
import api from '@/api'
import type { Finding, FindingTriage } from '@/types/analysis'

// FindingFilters lives in composable but re-declare for prop typing clarity
interface Filters { severity: string; category: string; search: string }

const props = defineProps<{
  findings: Finding[]
  filters: Filters
  analysisId?: string
  triageRecords?: FindingTriage[]
}>()

const triageMap = computed<Record<string, FindingTriage>>(() => {
  if (!props.triageRecords) return {}
  const m: Record<string, FindingTriage> = {}
  for (const t of props.triageRecords) m[t.finding_key] = t
  return m
})

const suppressDialog = reactive({
  visible: false,
  ruleId: '',
  srcIp: '',
  dstIp: '',
  reason: '',
  saving: false,
  error: '',
})

function openSuppressDialog(finding: Finding) {
  suppressDialog.ruleId = finding.rule_id ?? ''
  suppressDialog.srcIp = ''
  suppressDialog.dstIp = ''
  suppressDialog.reason = ''
  suppressDialog.error = ''
  suppressDialog.visible = true
}

async function submitSuppress() {
  suppressDialog.error = ''
  suppressDialog.saving = true
  try {
    await api.post('/suppressions', {
      rule_id: suppressDialog.ruleId || null,
      src_ip: suppressDialog.srcIp || null,
      dst_ip: suppressDialog.dstIp || null,
      reason: suppressDialog.reason,
    })
    suppressDialog.visible = false
    ElMessage.success('Suppression rule created. It will apply to the next analysis run.')
  } catch (e: any) {
    suppressDialog.error = e.response?.data?.detail || 'Failed to create suppression rule.'
  } finally {
    suppressDialog.saving = false
  }
}

const severityOrder = ['critical', 'high', 'medium', 'low', 'info'] as const

const categories = computed(() =>
  [...new Set(props.findings.map(f => f.category))].sort()
)

const filtered = computed(() => {
  let list = props.findings
  if (props.filters.severity) list = list.filter(f => f.severity === props.filters.severity)
  if (props.filters.category) list = list.filter(f => f.category === props.filters.category)
  if (props.filters.search) {
    const q = props.filters.search.toLowerCase()
    list = list.filter(f =>
      f.title.toLowerCase().includes(q) ||
      f.description.toLowerCase().includes(q) ||
      f.explanation?.toLowerCase().includes(q)
    )
  }
  return list
})

const bySeverity = computed(() => {
  const groups: Record<string, Finding[]> = {}
  for (const sev of severityOrder) {
    groups[sev] = filtered.value.filter(f => f.severity === sev)
  }
  return groups
})

function sevTagType(sev: string): string {
  const m: Record<string, string> = {
    critical: 'danger', high: 'warning', medium: 'warning', low: 'info', info: 'info',
  }
  return m[sev] ?? 'info'
}
</script>

<style scoped>
.findings-panel { display: flex; flex-direction: column; gap: 12px; }
.filters-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 4px; }
.result-count { font-size: 12px; color: #909399; margin-left: 4px; }

.empty-state { text-align: center; padding: 60px 20px; }
.empty-state p { color: #909399; margin-top: 8px; }

.sev-group { margin-bottom: 16px; }
.sev-group-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.group-count { font-size: 12px; color: #909399; }
.group-cards { display: flex; flex-direction: column; gap: 10px; }

.suppress-desc { margin: 0 0 14px; font-size: 13px; color: #606266; line-height: 1.6; }
</style>
