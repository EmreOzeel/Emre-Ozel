<template>
  <div class="live-events">
    <!-- Stats bar -->
    <div class="stats-bar" v-if="stats">
      <div class="stat-card">
        <div class="stat-value">{{ stats.total_events.toLocaleString() }}</div>
        <div class="stat-label">Total Events</div>
      </div>
      <div class="stat-card stat-allow">
        <div class="stat-value">{{ (stats.by_action.allow || 0).toLocaleString() }}</div>
        <div class="stat-label">Allow</div>
      </div>
      <div class="stat-card stat-deny">
        <div class="stat-value">{{ (stats.by_action.deny || 0).toLocaleString() }}</div>
        <div class="stat-label">Deny</div>
      </div>
      <div class="stat-card stat-drop">
        <div class="stat-value">{{ (stats.by_action.drop || 0).toLocaleString() }}</div>
        <div class="stat-label">Drop</div>
      </div>
      <div class="stat-card stat-denied-src" v-if="topDeniedSource">
        <div class="stat-value mono">{{ topDeniedSource.ip }}</div>
        <div class="stat-label">Top Denied Source ({{ topDeniedSource.count }})</div>
      </div>
      <div class="stat-card stat-collector">
        <div class="stat-value">
          <span
            class="collector-dot"
            :class="stats.collector?.running ? 'dot-on' : 'dot-off'"
          ></span>
          {{ stats.collector?.running ? 'Collecting' : 'Offline' }}
        </div>
        <div class="stat-label">Collector</div>
      </div>
    </div>

    <!-- Timeline chart -->
    <div class="timeline-chart-wrap" v-if="timelineBuckets.length">
      <div class="chart-header">
        <span class="chart-title">Activity — last 60 minutes</span>
        <div class="chart-legend">
          <span class="legend-item"><span class="leg-dot" style="background:#22c55e"></span>Allow</span>
          <span class="legend-item"><span class="leg-dot" style="background:#ef4444"></span>Deny</span>
          <span class="legend-item"><span class="leg-dot" style="background:#f97316"></span>Drop</span>
        </div>
      </div>
      <canvas ref="chartCanvas" class="timeline-canvas" @mousemove="onChartHover"></canvas>
    </div>

    <!-- Risk scores panel -->
    <div class="risk-panel" v-if="riskEntries.length">
      <div class="risk-panel-header">
        <span class="risk-panel-title">Source IP Risk Scores</span>
        <span class="risk-panel-sub">{{ riskEntries.length }} IPs above threshold</span>
      </div>
      <table class="risk-table">
        <thead>
          <tr>
            <th>Source IP</th>
            <th>Risk</th>
            <th>Level</th>
            <th>Top Driver</th>
            <th>Events</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="r in riskEntries"
            :key="r.source_ip"
            class="risk-row clickable"
            @click="filterByRiskIP(r.source_ip)"
          >
            <td class="mono">{{ r.source_ip }}</td>
            <td>
              <span class="risk-badge" :class="`risk-${r.risk_level}`">
                {{ r.risk_score }}
              </span>
            </td>
            <td>
              <span class="risk-level-tag" :class="`risk-${r.risk_level}`">
                {{ r.risk_level }}
              </span>
            </td>
            <td class="driver-cell">{{ (r.drivers[0] || '—').replace(/_/g, ' ') }}</td>
            <td class="mono">{{ r.event_count.toLocaleString() }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Filters -->
    <div class="filter-bar">
      <el-select
        v-model="filters.action"
        placeholder="Action"
        clearable
        size="small"
        style="width: 120px"
        @change="resetAndFetch"
      >
        <el-option label="All actions" value="" />
        <el-option label="Allow" value="allow" />
        <el-option label="Deny" value="deny" />
        <el-option label="Drop" value="drop" />
        <el-option label="Reset" value="reset" />
      </el-select>

      <el-input
        v-model="filters.source_ip"
        placeholder="Source IP"
        clearable
        size="small"
        style="width: 160px"
        @clear="resetAndFetch"
        @keyup.enter="resetAndFetch"
      />

      <el-input
        v-model="filters.destination_ip"
        placeholder="Destination IP"
        clearable
        size="small"
        style="width: 160px"
        @clear="resetAndFetch"
        @keyup.enter="resetAndFetch"
      />

      <el-select
        v-model="filters.protocol"
        placeholder="Protocol"
        clearable
        size="small"
        style="width: 120px"
        @change="resetAndFetch"
      >
        <el-option label="All protocols" value="" />
        <el-option label="TCP" value="TCP" />
        <el-option label="UDP" value="UDP" />
        <el-option label="ICMP" value="ICMP" />
      </el-select>

      <el-button size="small" @click="resetAndFetch" :loading="loading">
        Search
      </el-button>

      <div class="filter-right">
        <el-switch
          v-model="autoRefresh"
          active-text="Auto-refresh"
          size="small"
        />
        <el-button size="small" link @click="fetchStats">
          <el-icon><Refresh /></el-icon>
        </el-button>
      </div>
    </div>

    <!-- Table -->
    <div class="table-wrap">
      <el-table
        :data="events"
        stripe
        size="small"
        :row-class-name="rowClass"
        v-loading="loading && !events.length"
        empty-text="No events found"
        style="width: 100%"
      >
        <el-table-column label="Time" width="170" prop="event_time">
          <template #default="{ row }">
            <span class="mono time-cell">{{ formatTime(row.event_time) }}</span>
          </template>
        </el-table-column>

        <el-table-column label="Source IP" min-width="130">
          <template #default="{ row }">
            <span class="mono">{{ row.source_ip }}</span>
            <span v-if="row.source_port" class="port-hint">:{{ row.source_port }}</span>
          </template>
        </el-table-column>

        <el-table-column label="Destination IP" min-width="130">
          <template #default="{ row }">
            <span class="mono">{{ row.destination_ip }}</span>
          </template>
        </el-table-column>

        <el-table-column label="Port" width="70" align="center">
          <template #default="{ row }">
            <span class="mono">{{ row.destination_port ?? '—' }}</span>
          </template>
        </el-table-column>

        <el-table-column label="Proto" width="65" align="center">
          <template #default="{ row }">
            {{ row.protocol || '—' }}
          </template>
        </el-table-column>

        <el-table-column label="Action" width="90" align="center">
          <template #default="{ row }">
            <span class="action-badge" :class="`action-${row.action}`">
              {{ row.action }}
            </span>
          </template>
        </el-table-column>

        <el-table-column label="Application" width="120">
          <template #default="{ row }">
            {{ row.application || '—' }}
          </template>
        </el-table-column>

        <el-table-column label="Bytes In/Out" width="130" align="right">
          <template #default="{ row }">
            <span v-if="row.bytes_in != null || row.bytes_out != null" class="bytes-cell">
              <span class="bytes-in">↓{{ formatBytes(row.bytes_in) }}</span>
              <span class="bytes-out">↑{{ formatBytes(row.bytes_out) }}</span>
            </span>
            <span v-else>—</span>
          </template>
        </el-table-column>

        <el-table-column label="Device" width="110">
          <template #default="{ row }">
            <span class="device-cell">{{ row.source_id }}</span>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Pagination -->
    <div class="pagination-bar">
      <span class="page-info">
        Showing {{ events.length }} of {{ total }} events
      </span>
      <el-button
        v-if="events.length < total"
        size="small"
        :loading="loadingMore"
        @click="loadMore"
      >Load more</el-button>
    </div>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import api from '@/api'

const PAGE_SIZE = 100
const REFRESH_MS = 5000
const CHART_REFRESH_MS = 30000

const events = ref([])
const total = ref(0)
const offset = ref(0)
const loading = ref(false)
const loadingMore = ref(false)
const stats = ref(null)
const autoRefresh = ref(true)
let timer = null
let chartTimer = null

// Timeline chart
const timelineBuckets = ref([])
const chartCanvas = ref(null)

// Risk scores
const riskEntries = ref([])

const filters = reactive({
  action: '',
  source_ip: '',
  destination_ip: '',
  protocol: '',
})

const topDeniedSource = computed(() => {
  if (!stats.value?.top_denied_sources?.length) return null
  return stats.value.top_denied_sources[0]
})

function buildParams(extra = {}) {
  const p = { limit: PAGE_SIZE, ...extra }
  if (filters.action)         p.action = filters.action
  if (filters.source_ip)      p.source_ip = filters.source_ip.trim()
  if (filters.destination_ip) p.destination_ip = filters.destination_ip.trim()
  if (filters.protocol)       p.protocol = filters.protocol
  return p
}

async function fetchEvents(append = false) {
  if (append) {
    loadingMore.value = true
  } else {
    loading.value = true
  }
  try {
    const res = await api.get('/live-events', {
      params: buildParams({ offset: offset.value }),
    })
    if (append) {
      events.value = [...events.value, ...res.data.events]
    } else {
      events.value = res.data.events
    }
    total.value = res.data.total
  } catch {
    // silently fail on auto-refresh
  } finally {
    loading.value = false
    loadingMore.value = false
  }
}

async function fetchStats() {
  try {
    const res = await api.get('/live-events/stats')
    stats.value = res.data
  } catch {
    // non-critical
  }
}

function resetAndFetch() {
  offset.value = 0
  fetchEvents()
  fetchStats()
  fetchTimeline()
}

function loadMore() {
  offset.value = events.value.length
  fetchEvents(true)
}

function formatTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString(undefined, {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  })
}

function formatBytes(n) {
  if (n == null) return '0'
  if (n < 1024) return `${n}B`
  if (n < 1048576) return `${(n / 1024).toFixed(1)}K`
  return `${(n / 1048576).toFixed(1)}M`
}

function rowClass({ row }) {
  if (row.action === 'deny' || row.action === 'drop' || row.action === 'reset') {
    return 'row-blocked'
  }
  return ''
}

function startTimer() {
  stopTimer()
  if (autoRefresh.value) {
    timer = setInterval(() => {
      offset.value = 0
      fetchEvents()
      fetchStats()
    }, REFRESH_MS)
  }
}

function stopTimer() {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
}

async function fetchRiskScores() {
  try {
    const res = await api.get('/live-events/risk-scores', {
      params: { min_risk_score: 30 },
    })
    riskEntries.value = res.data || []
  } catch {
    // non-critical
  }
}

function filterByRiskIP(ip) {
  filters.source_ip = ip
  resetAndFetch()
}

async function fetchTimeline() {
  try {
    const params = { minutes: 60 }
    if (filters.source_ip) params.source_ip = filters.source_ip.trim()
    if (filters.destination_ip) params.destination_ip = filters.destination_ip.trim()
    const res = await api.get('/live-events/timeline', { params })
    timelineBuckets.value = res.data || []
    await nextTick()
    drawChart()
  } catch {
    // non-critical
  }
}

function drawChart() {
  const canvas = chartCanvas.value
  if (!canvas) return
  const data = timelineBuckets.value
  if (!data.length) return

  const dpr = window.devicePixelRatio || 1
  const rect = canvas.getBoundingClientRect()
  const W = rect.width
  const H = 180
  canvas.width = W * dpr
  canvas.height = H * dpr
  canvas.style.height = H + 'px'
  const ctx = canvas.getContext('2d')
  ctx.scale(dpr, dpr)
  ctx.clearRect(0, 0, W, H)

  const pad = { top: 10, right: 12, bottom: 28, left: 42 }
  const cw = W - pad.left - pad.right
  const ch = H - pad.top - pad.bottom

  // Compute max Y across all series
  let maxY = 1
  for (const b of data) {
    maxY = Math.max(maxY, b.allow || 0, b.deny || 0, b.drop || 0)
  }
  maxY = Math.ceil(maxY * 1.15) || 1

  const stepX = data.length > 1 ? cw / (data.length - 1) : cw

  // Grid lines
  ctx.strokeStyle = '#ebeef5'
  ctx.lineWidth = 1
  const gridLines = 4
  for (let i = 0; i <= gridLines; i++) {
    const y = pad.top + ch - (ch * i / gridLines)
    ctx.beginPath()
    ctx.moveTo(pad.left, y)
    ctx.lineTo(pad.left + cw, y)
    ctx.stroke()
    // Y labels
    ctx.fillStyle = '#909399'
    ctx.font = '10px sans-serif'
    ctx.textAlign = 'right'
    ctx.fillText(String(Math.round(maxY * i / gridLines)), pad.left - 6, y + 3)
  }

  // Draw series
  const series = [
    { key: 'allow', color: '#22c55e' },
    { key: 'deny',  color: '#ef4444' },
    { key: 'drop',  color: '#f97316' },
  ]
  for (const s of series) {
    ctx.beginPath()
    ctx.strokeStyle = s.color
    ctx.lineWidth = 2
    ctx.lineJoin = 'round'
    for (let i = 0; i < data.length; i++) {
      const x = pad.left + i * stepX
      const v = data[i][s.key] || 0
      const y = pad.top + ch - (v / maxY) * ch
      if (i === 0) ctx.moveTo(x, y)
      else ctx.lineTo(x, y)
    }
    ctx.stroke()
    // Semi-transparent fill
    ctx.lineTo(pad.left + (data.length - 1) * stepX, pad.top + ch)
    ctx.lineTo(pad.left, pad.top + ch)
    ctx.closePath()
    ctx.fillStyle = s.color + '18'
    ctx.fill()
  }

  // X-axis labels (every ~10 buckets)
  ctx.fillStyle = '#909399'
  ctx.font = '10px sans-serif'
  ctx.textAlign = 'center'
  const labelEvery = Math.max(1, Math.floor(data.length / 8))
  for (let i = 0; i < data.length; i += labelEvery) {
    const x = pad.left + i * stepX
    const b = data[i].bucket || ''
    // Extract HH:MM from ISO-ish string
    const hm = b.includes('T') ? b.split('T')[1]?.substring(0, 5) : b.substring(11, 16)
    ctx.fillText(hm || '', x, H - 6)
  }
}

// Tooltip on hover (lightweight — shows values near cursor)
function onChartHover(e) {
  const canvas = chartCanvas.value
  if (!canvas || !timelineBuckets.value.length) return
  const rect = canvas.getBoundingClientRect()
  const data = timelineBuckets.value
  const pad = { left: 42, right: 12 }
  const cw = rect.width - pad.left - pad.right
  const stepX = data.length > 1 ? cw / (data.length - 1) : cw
  const mx = e.clientX - rect.left - pad.left
  const idx = Math.round(mx / stepX)
  if (idx < 0 || idx >= data.length) {
    canvas.title = ''
    return
  }
  const b = data[idx]
  const hm = (b.bucket || '').includes('T')
    ? b.bucket.split('T')[1]?.substring(0, 5)
    : ''
  canvas.title = `${hm}  allow: ${b.allow}  deny: ${b.deny}  drop: ${b.drop}`
}

function startChartTimer() {
  stopChartTimer()
  chartTimer = setInterval(() => {
    fetchTimeline()
    fetchRiskScores()
  }, CHART_REFRESH_MS)
}
function stopChartTimer() {
  if (chartTimer) { clearInterval(chartTimer); chartTimer = null }
}

watch(autoRefresh, (on) => {
  if (on) { startTimer(); startChartTimer() }
  else { stopTimer(); stopChartTimer() }
})

onMounted(() => {
  fetchEvents()
  fetchStats()
  fetchTimeline()
  fetchRiskScores()
  startTimer()
  startChartTimer()
})

onUnmounted(() => { stopTimer(); stopChartTimer() })
</script>

<style scoped>
.live-events {
  max-width: 1400px;
  margin: 0 auto;
}

/* ── Stats bar ─────────────────────────────────────────────────────────── */
.stats-bar {
  display: flex;
  gap: 10px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}
.stat-card {
  background: white;
  border-radius: 8px;
  border: 1px solid #e4e7ed;
  padding: 12px 16px;
  min-width: 110px;
  flex: 1;
}
.stat-value {
  font-size: 20px;
  font-weight: 700;
  color: #1a1a2e;
  display: flex;
  align-items: center;
  gap: 6px;
}
.stat-label {
  font-size: 11px;
  color: #909399;
  text-transform: uppercase;
  margin-top: 2px;
}
.stat-allow .stat-value { color: #67c23a; }
.stat-deny  .stat-value { color: #f56c6c; }
.stat-drop  .stat-value { color: #e6a23c; }
.stat-denied-src .stat-value { font-size: 14px; }

.collector-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.dot-on  { background: #67c23a; }
.dot-off { background: #909399; }

/* ── Timeline chart ────────────────────────────────────────────────────── */
.timeline-chart-wrap {
  background: white;
  border-radius: 8px;
  border: 1px solid #e4e7ed;
  padding: 12px 16px;
  margin-bottom: 12px;
}
.chart-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}
.chart-title {
  font-size: 13px;
  font-weight: 600;
  color: #303133;
}
.chart-legend {
  display: flex;
  gap: 14px;
  font-size: 11px;
  color: #606266;
}
.legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
}
.leg-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.timeline-canvas {
  width: 100%;
  height: 180px;
  cursor: crosshair;
}

/* ── Risk panel ────────────────────────────────────────────────────────── */
.risk-panel {
  background: white;
  border-radius: 8px;
  border: 1px solid #e4e7ed;
  margin-bottom: 12px;
  overflow: hidden;
}
.risk-panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 16px;
  border-bottom: 1px solid #f0f2f5;
  background: #fafbfd;
}
.risk-panel-title {
  font-size: 13px;
  font-weight: 600;
  color: #303133;
}
.risk-panel-sub {
  font-size: 11px;
  color: #909399;
}
.risk-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
}
.risk-table th {
  text-align: left;
  padding: 6px 12px;
  background: #fafbfd;
  color: #606266;
  font-weight: 600;
  border-bottom: 1px solid #ebeef5;
}
.risk-table td {
  padding: 6px 12px;
  border-bottom: 1px solid #f4f6fa;
}
.risk-row.clickable {
  cursor: pointer;
}
.risk-row.clickable:hover td {
  background: #f5f7fa;
}
.risk-badge {
  display: inline-block;
  min-width: 32px;
  text-align: center;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 700;
  font-size: 11px;
}
.risk-badge.risk-critical { background: #fde2e2; color: #f56c6c; }
.risk-badge.risk-high     { background: #faecd8; color: #e6a23c; }
.risk-badge.risk-medium   { background: #fdf6ec; color: #c68a19; }
.risk-badge.risk-low      { background: #e1f3d8; color: #67c23a; }
.risk-level-tag {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}
.risk-level-tag.risk-critical { color: #f56c6c; }
.risk-level-tag.risk-high     { color: #e6a23c; }
.risk-level-tag.risk-medium   { color: #c68a19; }
.risk-level-tag.risk-low      { color: #67c23a; }
.driver-cell {
  color: #606266;
  text-transform: capitalize;
}

/* ── Filter bar ────────────────────────────────────────────────────────── */
.filter-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
  padding: 10px 14px;
  background: white;
  border-radius: 8px;
  border: 1px solid #e4e7ed;
}
.filter-right {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 10px;
}

/* ── Table ──────────────────────────────────────────────────────────────── */
.table-wrap {
  background: white;
  border-radius: 8px;
  border: 1px solid #e4e7ed;
  overflow: hidden;
}
.mono { font-family: 'SF Mono', 'Menlo', 'Consolas', monospace; font-size: 12px; }
.time-cell { color: #606266; white-space: nowrap; }
.port-hint { color: #c0c4cc; font-size: 11px; margin-left: 2px; }

.action-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.3px;
}
.action-allow  { background: #e1f3d8; color: #67c23a; }
.action-deny   { background: #fde2e2; color: #f56c6c; }
.action-drop   { background: #faecd8; color: #e6a23c; }
.action-reset  { background: #fdf6ec; color: #c68a19; }

.bytes-cell {
  display: flex;
  flex-direction: column;
  font-size: 11px;
  font-family: 'SF Mono', monospace;
  line-height: 1.4;
}
.bytes-in  { color: #67c23a; }
.bytes-out { color: #409eff; }

.device-cell {
  font-size: 12px;
  color: #606266;
}

:deep(.row-blocked td) {
  background: #fef6f6 !important;
}

/* ── Pagination ────────────────────────────────────────────────────────── */
.pagination-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-top: 10px;
  padding: 8px 4px;
}
.page-info {
  font-size: 12px;
  color: #909399;
}
</style>
