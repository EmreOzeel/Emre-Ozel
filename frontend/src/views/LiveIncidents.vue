<template>
  <div class="live-incidents-page">
    <!-- Stats bar -->
    <div class="stats-bar" v-if="statsLoaded">
      <div class="stat-card">
        <div class="stat-value">{{ totalCount }}</div>
        <div class="stat-label">Total Incidents</div>
      </div>
      <div class="stat-card si-open">
        <div class="stat-value">{{ statusCounts.open || 0 }}</div>
        <div class="stat-label">Open</div>
      </div>
      <div class="stat-card si-investigating">
        <div class="stat-value">{{ statusCounts.investigating || 0 }}</div>
        <div class="stat-label">Investigating</div>
      </div>
      <div class="stat-card si-critical">
        <div class="stat-value">{{ sevCounts.critical || 0 }}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card si-high">
        <div class="stat-value">{{ sevCounts.high || 0 }}</div>
        <div class="stat-label">High</div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filter-bar">
      <el-select v-model="filters.status" placeholder="Status" clearable size="small" style="width:135px" @change="resetAndFetch">
        <el-option label="All statuses" value="" />
        <el-option v-for="s in ['open','investigating','resolved','dismissed']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-select v-model="filters.severity" placeholder="Severity" clearable size="small" style="width:120px" @change="resetAndFetch">
        <el-option label="All severities" value="" />
        <el-option v-for="s in ['critical','high','medium','low']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-select v-model="filters.behavior_type" placeholder="Behavior" clearable size="small" style="width:150px" @change="resetAndFetch">
        <el-option label="All behaviors" value="" />
        <el-option v-for="b in ['scanning','lateral_movement','unstable','suspicious']" :key="b" :label="b.replace(/_/g,' ')" :value="b" />
      </el-select>
      <el-input v-model="filters.source_ip" placeholder="Source IP" clearable size="small" style="width:150px" @clear="resetAndFetch" @keyup.enter="resetAndFetch" />
      <el-button size="small" @click="resetAndFetch" :loading="loading">Search</el-button>
      <div class="filter-right">
        <el-switch v-model="autoRefresh" active-text="Auto" size="small" />
      </div>
    </div>

    <!-- Table -->
    <div class="table-wrap">
      <el-table
        :data="incidents"
        stripe size="small"
        v-loading="loading && !incidents.length"
        empty-text="No incidents found"
        style="width:100%"
        @row-click="onRowClick"
        highlight-current-row
      >
        <el-table-column label="Severity" width="90" align="center">
          <template #default="{ row }">
            <span class="sev-badge" :class="`sev-${row.severity}`">{{ row.severity }}</span>
          </template>
        </el-table-column>
        <el-table-column label="Behavior" width="140">
          <template #default="{ row }">
            <span class="btype">{{ row.behavior_type.replace(/_/g, ' ') }}</span>
          </template>
        </el-table-column>
        <el-table-column label="Source IP" min-width="130">
          <template #default="{ row }">
            <span class="mono">{{ row.source_ip }}</span>
          </template>
        </el-table-column>
        <el-table-column label="Detections" width="90" align="center" prop="event_count" />
        <el-table-column label="Destinations" width="100" align="center" prop="total_distinct_destinations" />
        <el-table-column label="Top Ports" width="140">
          <template #default="{ row }">
            <span class="port-list">{{ (row.top_ports || []).slice(0, 3).join(', ') || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="First Seen" width="145">
          <template #default="{ row }">
            <span class="mono ts">{{ fmtTime(row.first_seen) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="Last Seen" width="145">
          <template #default="{ row }">
            <span class="mono ts">{{ fmtTime(row.last_seen) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="Status" width="110" align="center">
          <template #default="{ row }">
            <span class="status-badge" :class="`st-${row.status}`">{{ row.status }}</span>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="pagination-bar">
      <span class="page-info">Showing {{ incidents.length }} of {{ total }}</span>
      <el-button v-if="incidents.length < total" size="small" :loading="loadingMore" @click="loadMore">Load more</el-button>
    </div>

    <!-- Detail panel -->
    <Transition name="panel">
      <div v-if="selected" class="detail-overlay" @click.self="selected = null">
        <div class="detail-panel">
          <!-- 1. Header -->
          <div class="dp-header">
            <div class="dp-header-left">
              <span class="sev-badge large" :class="`sev-${selected.severity}`">{{ selected.severity }}</span>
              <div>
                <div class="dp-behavior">{{ selected.behavior_type.replace(/_/g, ' ') }}</div>
                <div class="dp-ip mono">{{ selected.source_ip }}</div>
              </div>
            </div>
            <button class="dp-close" @click="selected = null">&times;</button>
          </div>
          <div class="dp-status-row">
            <span class="status-badge" :class="`st-${selected.status}`">{{ selected.status }}</span>
            <el-select
              :model-value="selected.status"
              size="small"
              style="width:140px; margin-left:8px"
              @change="updateStatus"
            >
              <el-option v-for="s in ['open','investigating','resolved','dismissed']" :key="s" :label="s" :value="s" />
            </el-select>
          </div>

          <!-- 2. Summary -->
          <div class="dp-section" v-if="selected.last_activity_summary || selected.summary">
            <div class="dp-label">Summary</div>
            <div class="dp-activity" v-if="selected.last_activity_summary">{{ selected.last_activity_summary }}</div>
            <div class="dp-summary">{{ selected.summary }}</div>
          </div>

          <!-- 3. Scope -->
          <div class="dp-section">
            <div class="dp-label">Scope</div>
            <div class="dp-grid">
              <span>Distinct destinations</span><span class="mono dp-bold">{{ selected.total_distinct_destinations ?? '—' }}</span>
              <span>Distinct ports</span><span class="mono dp-bold">{{ selected.total_distinct_ports ?? '—' }}</span>
            </div>
            <div class="dp-pills" v-if="selected.top_destination_ips?.length">
              <span class="dp-pill-label">Top IPs</span>
              <span v-for="ip in selected.top_destination_ips.slice(0, 5)" :key="ip" class="dp-pill ip-pill">{{ ip }}</span>
            </div>
            <div class="dp-pills" v-if="selected.top_ports?.length">
              <span class="dp-pill-label">Top Ports</span>
              <span
                v-for="p in selected.top_ports.slice(0, 5)" :key="p"
                class="dp-pill" :class="portClass(p)"
              >{{ p }}</span>
            </div>
          </div>

          <!-- 4. Timeline -->
          <div class="dp-section">
            <div class="dp-label">Timeline</div>
            <div class="dp-grid">
              <span>First seen</span><span class="mono">{{ fmtTime(selected.first_seen) }}</span>
              <span>Last seen</span><span class="mono">{{ fmtTime(selected.last_seen) }}</span>
              <span>Duration</span><span class="mono">{{ fmtDuration(selected.first_seen, selected.last_seen) }}</span>
              <span>Detections</span><span class="mono dp-bold">{{ selected.event_count }}</span>
              <span>Linked flows</span><span class="mono">{{ selected.linked_flow_count }}</span>
              <span>Confidence</span>
              <span class="mono" :class="confClass(selected.latest_confidence)">
                {{ selected.latest_confidence != null ? (selected.latest_confidence * 100).toFixed(0) + '%' : '—' }}
              </span>
            </div>
          </div>

          <!-- 5. Sample flows -->
          <div class="dp-section">
            <div class="dp-label">Representative Flows</div>
            <div v-if="selected.sample_flows?.length" class="sample-list">
              <div v-for="(f, i) in selected.sample_flows.slice(0, 3)" :key="i" class="sample-row">
                <span class="mono">{{ f.src }} → {{ f.dst }}</span>
                <span class="status-badge mini" :class="`st-${f.state || 'expired'}`">{{ f.state }}</span>
                <span class="sample-dur">{{ f.duration_ms != null ? f.duration_ms + 'ms' : '' }}</span>
              </div>
            </div>
            <div v-else class="empty-hint">No flow samples available</div>
          </div>

          <!-- 6. Actions -->
          <div class="dp-actions">
            <el-button size="small" type="primary" @click="$router.push(`/live-flows?source_ip=${selected.source_ip}`); selected = null">
              View source IP flows
            </el-button>
            <el-button size="small" @click="$router.push(`/live-events?source_ip=${selected.source_ip}`); selected = null">
              View related events
            </el-button>
          </div>
        </div>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import api from '@/api'

const router = useRouter()
const PAGE_SIZE = 50

const incidents = ref([])
const total = ref(0)
const offset = ref(0)
const loading = ref(false)
const loadingMore = ref(false)
const autoRefresh = ref(true)
const statsLoaded = ref(false)
const selected = ref(null)
let timer = null

const filters = reactive({
  status: '', severity: '', behavior_type: '', source_ip: '',
})

const allIncidents = ref([])
const totalCount = computed(() => allIncidents.value.length)
const statusCounts = computed(() => {
  const c = {}
  for (const i of allIncidents.value) c[i.status] = (c[i.status] || 0) + 1
  return c
})
const sevCounts = computed(() => {
  const c = {}
  for (const i of allIncidents.value) c[i.severity] = (c[i.severity] || 0) + 1
  return c
})

function buildParams(extra = {}) {
  const p = { limit: PAGE_SIZE, ...extra }
  if (filters.status) p.status = filters.status
  if (filters.severity) p.severity = filters.severity
  if (filters.behavior_type) p.behavior_type = filters.behavior_type
  if (filters.source_ip) p.source_ip = filters.source_ip.trim()
  return p
}

async function fetchIncidents(append = false) {
  if (append) loadingMore.value = true; else loading.value = true
  try {
    const res = await api.get('/live-incidents', { params: buildParams({ offset: offset.value }) })
    if (append) incidents.value = [...incidents.value, ...res.data.incidents]
    else incidents.value = res.data.incidents
    total.value = res.data.total
  } catch {} finally { loading.value = false; loadingMore.value = false }
}

async function fetchStats() {
  try {
    const res = await api.get('/live-incidents', { params: { limit: 500 } })
    allIncidents.value = res.data.incidents || []
    statsLoaded.value = true
  } catch {}
}

function resetAndFetch() { offset.value = 0; fetchIncidents(); fetchStats() }
function loadMore() { offset.value = incidents.value.length; fetchIncidents(true) }

function onRowClick(row) { selected.value = { ...row } }

async function updateStatus(newStatus) {
  if (!selected.value) return
  try {
    const res = await api.put(`/live-incidents/${selected.value.id}/status`, { status: newStatus })
    selected.value = { ...selected.value, ...res.data }
    // Update in the table too
    const idx = incidents.value.findIndex(i => i.id === selected.value.id)
    if (idx !== -1) incidents.value[idx] = { ...incidents.value[idx], status: newStatus }
    ElMessage.success(`Status updated to ${newStatus}`)
  } catch (e) {
    ElMessage.error(e?.response?.data?.detail || 'Failed to update status')
  }
}

function fmtTime(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  })
}

function fmtDuration(from, to) {
  if (!from || !to) return '—'
  const ms = new Date(to) - new Date(from)
  if (ms < 0) return '—'
  const mins = Math.floor(ms / 60000)
  if (mins < 60) return `${mins}m`
  const hrs = Math.floor(mins / 60)
  const rm = mins % 60
  if (hrs < 24) return `${hrs}h ${rm}m`
  return `${Math.floor(hrs / 24)}d ${hrs % 24}h`
}

const _RISKY_PORTS = new Set([22, 23, 445, 3389, 1433, 3306, 5432, 5900])
const _COMMON_PORTS = new Set([80, 443, 8080, 8443])
function portClass(p) {
  if (_RISKY_PORTS.has(Number(p))) return 'port-risky'
  if (_COMMON_PORTS.has(Number(p))) return 'port-common'
  return 'port-other'
}

function confClass(c) {
  if (c == null) return ''
  if (c >= 0.8) return 'conf-high'
  if (c >= 0.6) return 'conf-med'
  return ''
}

function startTimer() {
  stopTimer()
  if (autoRefresh.value) timer = setInterval(resetAndFetch, 30000)
}
function stopTimer() { if (timer) { clearInterval(timer); timer = null } }
watch(autoRefresh, (on) => { if (on) startTimer(); else stopTimer() })

onMounted(() => { fetchIncidents(); fetchStats(); startTimer() })
onUnmounted(stopTimer)
</script>

<style scoped>
.live-incidents-page { max-width: 1400px; margin: 0 auto; }

/* Stats */
.stats-bar { display: flex; gap: 10px; margin-bottom: 14px; flex-wrap: wrap; }
.stat-card { background: white; border-radius: 8px; border: 1px solid #e4e7ed; padding: 12px 16px; min-width: 100px; flex: 1; }
.stat-value { font-size: 20px; font-weight: 700; color: #1a1a2e; }
.stat-label { font-size: 11px; color: #909399; text-transform: uppercase; margin-top: 2px; }
.si-open .stat-value { color: #409eff; }
.si-investigating .stat-value { color: #7c3aed; }
.si-critical .stat-value { color: #f56c6c; }
.si-high .stat-value { color: #f97316; }

/* Filters */
.filter-bar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; padding: 10px 14px; background: white; border-radius: 8px; border: 1px solid #e4e7ed; }
.filter-right { margin-left: auto; display: flex; align-items: center; gap: 8px; }

/* Table */
.table-wrap { background: white; border-radius: 8px; border: 1px solid #e4e7ed; overflow: hidden; }
.mono { font-family: 'SF Mono', 'Menlo', monospace; font-size: 12px; }
.ts { color: #606266; white-space: nowrap; font-size: 11px; }

.sev-badge { display: inline-block; min-width: 50px; text-align: center; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
.sev-badge.large { font-size: 14px; padding: 4px 14px; }
.sev-critical { background: #fde2e2; color: #f56c6c; }
.sev-high     { background: #faecd8; color: #f97316; }
.sev-medium   { background: #fef9c3; color: #a16207; }
.sev-low      { background: #ebeef5; color: #909399; }

.status-badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
.status-badge.mini { font-size: 9px; padding: 1px 6px; }
.st-open          { background: #d9ecff; color: #409eff; }
.st-investigating { background: #e8def8; color: #7c3aed; }
.st-resolved      { background: #e1f3d8; color: #67c23a; }
.st-dismissed     { background: #ebeef5; color: #909399; }

.btype { font-weight: 500; color: #303133; text-transform: capitalize; }
.port-list { font-size: 12px; color: #606266; font-family: monospace; }

.pagination-bar { display: flex; justify-content: space-between; align-items: center; margin-top: 10px; padding: 8px 4px; }
.page-info { font-size: 12px; color: #909399; }

/* ── Detail panel ──────────────────────────────────────────────────────── */
.detail-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.15); z-index: 200; display: flex; justify-content: flex-end; }
.detail-panel { width: 480px; max-width: 95vw; background: white; height: 100vh; overflow-y: auto; padding: 24px; box-shadow: -4px 0 20px rgba(0,0,0,0.08); }
.panel-enter-active, .panel-leave-active { transition: transform 0.25s ease; }
.panel-enter-from, .panel-leave-to { transform: translateX(100%); }

.dp-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; }
.dp-header-left { display: flex; gap: 12px; align-items: center; }
.dp-behavior { font-size: 18px; font-weight: 700; color: #1a1a2e; text-transform: capitalize; }
.dp-ip { font-size: 14px; color: #606266; margin-top: 2px; }
.dp-close { background: none; border: none; font-size: 26px; cursor: pointer; color: #909399; line-height: 1; }
.dp-close:hover { color: #303133; }

.dp-status-row { display: flex; align-items: center; margin-bottom: 16px; }

.dp-section { margin-bottom: 16px; }
.dp-label { font-size: 11px; font-weight: 600; text-transform: uppercase; color: #909399; margin-bottom: 6px; }
.dp-activity { font-style: italic; color: #606266; font-size: 13px; margin-bottom: 4px; }
.dp-summary { font-size: 13px; color: #303133; }

.dp-grid { display: grid; grid-template-columns: auto 1fr; gap: 3px 14px; font-size: 12px; color: #606266; margin-bottom: 8px; }
.dp-bold { font-weight: 700; color: #303133; }

.dp-pills { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-top: 6px; }
.dp-pill-label { font-size: 11px; color: #909399; margin-right: 2px; }
.dp-pill { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; }
.ip-pill { background: #ebeef5; color: #606266; font-family: monospace; }
.port-risky { background: #fde2e2; color: #f56c6c; }
.port-common { background: #d9ecff; color: #409eff; }
.port-other { background: #ebeef5; color: #606266; }

.conf-high { color: #f56c6c !important; font-weight: 700; }
.conf-med { color: #f97316 !important; font-weight: 700; }

.sample-list { display: flex; flex-direction: column; gap: 4px; }
.sample-row { display: flex; align-items: center; gap: 8px; font-size: 12px; padding: 4px 0; }
.sample-dur { color: #909399; font-size: 11px; }
.empty-hint { font-size: 12px; color: #909399; text-align: center; padding: 8px 0; }

.dp-actions { display: flex; gap: 8px; margin-top: 16px; padding-top: 12px; border-top: 1px solid #ebeef5; }
</style>
