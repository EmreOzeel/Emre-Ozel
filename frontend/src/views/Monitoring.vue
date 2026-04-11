<template>
  <div class="monitoring">
    <div class="page-header">
      <div>
        <h2>Path Monitoring</h2>
        <p>
          Re-runs your saved path queries on a schedule and alerts you when
          a previously healthy path drifts.
        </p>
      </div>
      <div class="header-actions">
        <el-button @click="fetchAll" :loading="loading">Refresh</el-button>
        <el-button type="primary" @click="openCreate">
          <el-icon><Plus /></el-icon>
          New Monitor
        </el-button>
      </div>
    </div>

    <div v-if="error" class="empty-state error">{{ error }}</div>

    <div v-else-if="loading && !monitors.length" class="empty-state">
      <el-icon class="spinning"><Loading /></el-icon>
      <span>Loading monitors…</span>
    </div>

    <div v-else-if="!monitors.length" class="empty-state">
      <p>No monitored paths yet.</p>
      <p class="hint">
        Save a path-analysis query first, then create a monitor here to watch
        for drift.
      </p>
    </div>

    <div v-else class="monitor-list">
      <div
        v-for="m in monitors"
        :key="m.id"
        class="monitor-card"
        :class="severityClass(m.last_drift_severity)"
      >
        <div class="card-head">
          <div class="card-head-left">
            <h3>{{ m.saved_query_name || `Query #${m.saved_query_id}` }}</h3>
            <div class="path-line">
              <code>{{ m.source_ip }}</code>
              <span class="arrow">→</span>
              <code>
                {{ m.destination_ip
                }}<template v-if="m.destination_port">:{{ m.destination_port }}</template>
              </code>
            </div>
            <div class="sub-line">
              on <strong>{{ m.analysis_filename || m.analysis_id }}</strong>
              · every {{ m.schedule_interval_minutes }} min
            </div>
          </div>
          <div class="card-head-right">
            <el-tag
              v-if="!m.enabled"
              type="info"
              effect="plain"
              size="small"
            >Paused</el-tag>
            <el-tag
              v-else-if="m.last_drift_severity && m.last_drift_severity !== 'none'"
              :type="severityTagType(m.last_drift_severity)"
              effect="dark"
              size="small"
            >{{ m.last_drift_severity.toUpperCase() }}</el-tag>
            <el-tag
              v-else-if="m.has_baseline"
              type="success"
              effect="plain"
              size="small"
            >Healthy</el-tag>
            <el-tag
              v-else
              type="info"
              effect="plain"
              size="small"
            >No baseline yet</el-tag>
          </div>
        </div>

        <div class="card-meta">
          <div>
            <span class="meta-label">Last run</span>
            <span class="meta-value">{{ formatTime(m.last_run_at) || '—' }}</span>
          </div>
          <div>
            <span class="meta-label">Last change</span>
            <span class="meta-value">{{ formatTime(m.last_change_at) || '—' }}</span>
          </div>
        </div>

        <div
          v-if="m.last_change_summary && m.last_change_summary.changes?.length"
          class="change-block"
        >
          <div class="change-title">
            What changed
            <span
              v-if="m.last_change_summary.severity"
              class="severity-pill"
              :class="severityClass(m.last_change_summary.severity)"
            >{{ m.last_change_summary.severity.toUpperCase() }}</span>
          </div>
          <ul>
            <li
              v-for="(c, i) in m.last_change_summary.changes"
              :key="i"
            >{{ c }}</li>
          </ul>
          <div
            v-if="actionRequired(m.last_change_summary.severity)"
            class="action-required"
          >
            <el-icon><Warning /></el-icon>
            Review needed — analysis was moved to
            <strong>needs review</strong>.
          </div>
        </div>

        <div class="card-actions">
          <el-button size="small" @click="runNow(m)" :loading="runningId === m.id">
            <el-icon><VideoPlay /></el-icon>
            Run Now
          </el-button>
          <el-button size="small" @click="toggleEnabled(m)">
            {{ m.enabled ? 'Pause' : 'Resume' }}
          </el-button>
          <el-button
            size="small"
            type="danger"
            plain
            @click="deleteMonitor(m)"
          >Delete</el-button>
          <el-button
            size="small"
            link
            @click="$router.push(`/analysis/${m.analysis_id}`)"
          >Open analysis →</el-button>
        </div>
      </div>
    </div>

    <!-- Create dialog -->
    <el-dialog
      v-model="createOpen"
      title="New monitored path"
      width="520px"
    >
      <el-form :model="createForm" label-position="top">
        <el-form-item label="Saved query">
          <el-select
            v-model="createForm.saved_query_id"
            placeholder="Pick a saved path query"
            style="width: 100%"
          >
            <el-option
              v-for="q in savedQueries"
              :key="q.id"
              :label="`${q.name} (${q.source_ip} → ${q.destination_ip})`"
              :value="q.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="Target analysis (PCAP to re-run against)">
          <el-select
            v-model="createForm.analysis_id"
            placeholder="Pick a completed analysis"
            filterable
            style="width: 100%"
          >
            <el-option
              v-for="a in analyses"
              :key="a.id"
              :label="`${a.filename} — ${a.id.slice(0, 8)}`"
              :value="a.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="Poll interval (minutes)">
          <el-input-number
            v-model="createForm.schedule_interval_minutes"
            :min="1"
            :max="10080"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createOpen = false">Cancel</el-button>
        <el-button
          type="primary"
          :disabled="!canCreate"
          :loading="creating"
          @click="submitCreate"
        >Create</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import {
  Loading, Plus, VideoPlay, Warning,
} from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import api from '@/api'

const monitors = ref([])
const savedQueries = ref([])
const analyses = ref([])
const loading = ref(false)
const error = ref(null)
const runningId = ref(null)

const createOpen = ref(false)
const creating = ref(false)
const createForm = ref({
  saved_query_id: null,
  analysis_id: null,
  schedule_interval_minutes: 60,
})
const canCreate = computed(
  () => !!createForm.value.saved_query_id && !!createForm.value.analysis_id,
)

async function fetchAll() {
  loading.value = true
  error.value = null
  try {
    const [m, q, a] = await Promise.all([
      api.get('/path-monitors'),
      api.get('/path-analysis/saved-queries'),
      api.get('/analyses'),
    ])
    monitors.value = m.data
    savedQueries.value = q.data
    // Only completed analyses can be monitored
    analyses.value = (a.data || []).filter(x => x.status === 'completed')
  } catch (e) {
    error.value = e?.response?.data?.detail || e?.message || 'Failed to load'
  } finally {
    loading.value = false
  }
}

function openCreate() {
  createForm.value = {
    saved_query_id: savedQueries.value[0]?.id || null,
    analysis_id: analyses.value[0]?.id || null,
    schedule_interval_minutes: 60,
  }
  createOpen.value = true
}

async function submitCreate() {
  creating.value = true
  try {
    await api.post('/path-monitors', createForm.value)
    createOpen.value = false
    ElMessage.success('Monitor created')
    await fetchAll()
  } catch (e) {
    ElMessage.error(
      e?.response?.data?.detail || e?.message || 'Failed to create monitor',
    )
  } finally {
    creating.value = false
  }
}

async function runNow(m) {
  runningId.value = m.id
  try {
    const res = await api.post(`/path-monitors/${m.id}/run`)
    const sev = res.data?.report?.severity || 'none'
    if (sev === 'none') {
      ElMessage.success('Run complete — no drift detected')
    } else if (sev === 'info') {
      ElMessage.info('Run complete — minor change recorded')
    } else if (sev === 'warning') {
      ElMessage.warning('Drift detected — review the path')
    } else {
      ElMessage.error('Critical drift detected — immediate review needed')
    }
    await fetchAll()
  } catch (e) {
    ElMessage.error(
      e?.response?.data?.detail || e?.message || 'Run failed',
    )
  } finally {
    runningId.value = null
  }
}

async function toggleEnabled(m) {
  try {
    await api.put(`/path-monitors/${m.id}`, { enabled: !m.enabled })
    await fetchAll()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || 'Failed to update monitor')
  }
}

async function deleteMonitor(m) {
  try {
    await ElMessageBox.confirm(
      `Delete monitor for "${m.saved_query_name}"?`,
      'Delete monitor',
      { confirmButtonText: 'Delete', type: 'warning' },
    )
  } catch {
    return
  }
  try {
    await api.delete(`/path-monitors/${m.id}`)
    await fetchAll()
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || 'Failed to delete')
  }
}

function formatTime(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  return d.toLocaleString()
}

function severityClass(sev) {
  if (sev === 'critical') return 'sev-critical'
  if (sev === 'warning')  return 'sev-warning'
  if (sev === 'info')     return 'sev-info'
  return ''
}

function severityTagType(sev) {
  if (sev === 'critical') return 'danger'
  if (sev === 'warning')  return 'warning'
  if (sev === 'info')     return 'info'
  return 'success'
}

function actionRequired(sev) {
  return sev === 'warning' || sev === 'critical'
}

onMounted(fetchAll)
</script>

<style scoped>
.monitoring {
  max-width: 1100px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 20px;
}
.page-header h2 {
  font-size: 24px;
  font-weight: 700;
  color: #1a1a2e;
  margin-bottom: 6px;
}
.page-header p {
  color: #909399;
  font-size: 14px;
  max-width: 640px;
}

.header-actions {
  display: flex;
  gap: 8px;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
  padding: 60px 20px;
  background: white;
  border-radius: 10px;
  border: 1px solid #e4e7ed;
  color: #909399;
}
.empty-state.error { color: #f56c6c; }
.empty-state .hint { font-size: 13px; }

.monitor-list {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.monitor-card {
  background: white;
  border-radius: 10px;
  border: 1px solid #e4e7ed;
  padding: 18px 20px;
  border-left: 4px solid #d3d6dc;
}
.monitor-card.sev-critical { border-left-color: #f56c6c; }
.monitor-card.sev-warning  { border-left-color: #e6a23c; }
.monitor-card.sev-info     { border-left-color: #409eff; }

.card-head {
  display: flex;
  justify-content: space-between;
  gap: 12px;
}
.card-head h3 {
  font-size: 16px;
  font-weight: 700;
  color: #1a1a2e;
  margin: 0 0 4px 0;
}
.path-line {
  font-size: 13px;
  color: #606266;
  display: flex;
  align-items: center;
  gap: 6px;
}
.path-line code {
  background: #f4f6fa;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 12px;
}
.path-line .arrow { color: #909399; }
.sub-line {
  font-size: 12px;
  color: #909399;
  margin-top: 4px;
}
.card-head-right { flex-shrink: 0; }

.card-meta {
  display: flex;
  gap: 24px;
  margin-top: 12px;
  font-size: 12px;
}
.meta-label {
  color: #909399;
  margin-right: 6px;
}
.meta-value { color: #606266; font-weight: 500; }

.change-block {
  margin-top: 14px;
  padding: 12px 14px;
  background: #fafbfd;
  border-radius: 8px;
  border: 1px solid #ebeef5;
}
.change-title {
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  color: #606266;
  margin-bottom: 6px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.severity-pill {
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 10px;
  background: #e4e7ed;
  color: #606266;
}
.severity-pill.sev-critical { background: #fde2e2; color: #f56c6c; }
.severity-pill.sev-warning  { background: #faecd8; color: #e6a23c; }
.severity-pill.sev-info     { background: #d9ecff; color: #409eff; }
.change-block ul {
  margin: 0;
  padding-left: 18px;
  color: #303133;
  font-size: 13px;
  line-height: 1.6;
}
.action-required {
  margin-top: 8px;
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #e6a23c;
}

.card-actions {
  display: flex;
  gap: 8px;
  margin-top: 14px;
  flex-wrap: wrap;
}

.spinning {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}
</style>
