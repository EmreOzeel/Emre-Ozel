<template>
  <div class="live-flows">
    <!-- Stats bar -->
    <div class="stats-bar" v-if="stats">
      <div class="stat-card">
        <div class="stat-value">{{ stats.total_flows.toLocaleString() }}</div>
        <div class="stat-label">Total Flows</div>
      </div>
      <div class="stat-card sb-active">
        <div class="stat-value">{{ (stats.active_flows || 0).toLocaleString() }}</div>
        <div class="stat-label">Active</div>
      </div>
      <div class="stat-card sb-completed">
        <div class="stat-value">{{ (stats.completed_flows || 0).toLocaleString() }}</div>
        <div class="stat-label">Completed</div>
      </div>
      <div class="stat-card sb-denied">
        <div class="stat-value">{{ (stats.denied_flows || 0).toLocaleString() }}</div>
        <div class="stat-label">Denied</div>
      </div>
      <div class="stat-card sb-reset">
        <div class="stat-value">{{ (stats.reset_flows || 0).toLocaleString() }}</div>
        <div class="stat-label">Reset</div>
      </div>
      <div class="stat-card sb-dropped">
        <div class="stat-value">{{ (stats.dropped_flows || 0).toLocaleString() }}</div>
        <div class="stat-label">Dropped</div>
      </div>
      <div class="stat-card sb-scanning" v-if="stats.flow_type_counts?.scanning">
        <div class="stat-value">{{ stats.flow_type_counts.scanning }}</div>
        <div class="stat-label">Scanning</div>
      </div>
      <div class="stat-card sb-suspicious" v-if="stats.flow_type_counts?.suspicious">
        <div class="stat-value">{{ stats.flow_type_counts.suspicious }}</div>
        <div class="stat-label">Suspicious</div>
      </div>
      <div class="stat-card" v-if="stats.top_talkers?.[0]">
        <div class="stat-value mono">{{ stats.top_talkers[0].ip }}</div>
        <div class="stat-label">Top Talker ({{ stats.top_talkers[0].flow_count }})</div>
      </div>
      <div class="stat-card" v-if="stats.top_reset_sources?.[0]">
        <div class="stat-value mono">{{ stats.top_reset_sources[0].ip }}</div>
        <div class="stat-label">Top Reset ({{ stats.top_reset_sources[0].count }})</div>
      </div>
    </div>

    <!-- Timeline chart -->
    <div class="timeline-chart-wrap" v-if="timelineBuckets.length">
      <div class="chart-header">
        <span class="chart-title">Flow Activity — last 60 minutes</span>
        <div class="chart-legend">
          <span class="legend-item"><span class="leg-dot" style="background:#22c55e"></span>Completed</span>
          <span class="legend-item"><span class="leg-dot" style="background:#ef4444"></span>Denied</span>
          <span class="legend-item"><span class="leg-dot" style="background:#f97316"></span>Reset</span>
          <span class="legend-item"><span class="leg-dot" style="background:#991b1b"></span>Dropped</span>
        </div>
      </div>
      <canvas ref="chartCanvas" class="timeline-canvas" @mousemove="onChartHover"></canvas>
    </div>

    <!-- Filters -->
    <div class="filter-bar">
      <el-select v-model="filters.state" placeholder="State" clearable size="small" style="width:120px" @change="resetAndFetch">
        <el-option label="All states" value="" />
        <el-option v-for="s in ['active','completed','denied','reset','dropped','expired']" :key="s" :label="s" :value="s" />
      </el-select>
      <el-input v-model="filters.source_ip" placeholder="Source IP" clearable size="small" style="width:140px" @clear="resetAndFetch" @keyup.enter="resetAndFetch" />
      <el-input v-model="filters.destination_ip" placeholder="Dest IP" clearable size="small" style="width:140px" @clear="resetAndFetch" @keyup.enter="resetAndFetch" />
      <el-select v-model="filters.protocol" placeholder="Protocol" clearable size="small" style="width:100px" @change="resetAndFetch">
        <el-option label="All" value="" /><el-option label="TCP" value="TCP" /><el-option label="UDP" value="UDP" /><el-option label="ICMP" value="ICMP" />
      </el-select>
      <el-input v-model="filters.application" placeholder="Application" clearable size="small" style="width:120px" @clear="resetAndFetch" @keyup.enter="resetAndFetch" />
      <el-select v-model="filters.action_summary" placeholder="Action" clearable size="small" style="width:130px" @change="resetAndFetch">
        <el-option label="All" value="" /><el-option v-for="a in ['mostly_allow','mostly_deny','mixed','reset_seen']" :key="a" :label="a.replace(/_/g,' ')" :value="a" />
      </el-select>
      <el-select v-model="filters.flow_type" placeholder="Flow type" clearable size="small" style="width:120px" @change="resetAndFetch">
        <el-option label="All types" value="" /><el-option v-for="t in ['normal','unstable','blocked','suspicious','scanning']" :key="t" :label="t" :value="t" />
      </el-select>
      <el-switch v-model="filters.show_suppressed" active-text="Suppressed" size="small" @change="resetAndFetch" />
      <el-button size="small" @click="resetAndFetch" :loading="loading">Search</el-button>
      <div class="filter-right">
        <el-switch v-model="autoRefresh" active-text="Auto" size="small" />
      </div>
    </div>

    <!-- Table -->
    <div class="table-wrap">
      <el-table :data="flows" stripe size="small" v-loading="loading && !flows.length" empty-text="No flows found" style="width:100%" @row-click="openDetail" highlight-current-row>
        <el-table-column label="First Seen" width="150"><template #default="{row}"><span class="mono ts">{{ fmtTime(row.first_seen) }}</span></template></el-table-column>
        <el-table-column label="Last Seen" width="150"><template #default="{row}"><span class="mono ts">{{ fmtTime(row.last_seen) }}</span></template></el-table-column>
        <el-table-column label="Source" min-width="140"><template #default="{row}"><span class="mono">{{ row.source_ip }}<span class="port-hint" v-if="row.source_port">:{{ row.source_port }}</span></span></template></el-table-column>
        <el-table-column label="" width="30" align="center"><template #default>→</template></el-table-column>
        <el-table-column label="Destination" min-width="140"><template #default="{row}"><span class="mono">{{ row.destination_ip }}<span class="port-hint" v-if="row.destination_port">:{{ row.destination_port }}</span></span></template></el-table-column>
        <el-table-column label="Proto" width="60" align="center" prop="protocol" />
        <el-table-column label="State" width="90" align="center"><template #default="{row}"><span class="state-badge" :class="`st-${row.state}`">{{ row.state }}</span></template></el-table-column>
        <el-table-column label="Type" width="95" align="center"><template #default="{row}"><span v-if="row.flow_type && row.flow_type !== 'normal'" class="ft-badge" :class="`ft-${row.flow_type}`">{{ row.flow_type }}</span><span v-else class="ft-normal">normal</span></template></el-table-column>
        <el-table-column label="Action" width="110"><template #default="{row}">{{ (row.action_summary||'').replace(/_/g,' ') }}</template></el-table-column>
        <el-table-column label="App" width="100" prop="application" />
        <el-table-column label="Duration" width="80" align="right"><template #default="{row}">{{ fmtDur(row.duration_ms) }}</template></el-table-column>
        <el-table-column label="Events" width="65" align="right" prop="event_count" />
        <el-table-column label="Bytes" width="100" align="right"><template #default="{row}">{{ fmtBytes(row.total_bytes_in + row.total_bytes_out) }}</template></el-table-column>
      </el-table>
    </div>

    <div class="pagination-bar">
      <span class="page-info">Showing {{ flows.length }} of {{ total }}</span>
      <el-button v-if="flows.length < total" size="small" :loading="loadingMore" @click="loadMore">Load more</el-button>
    </div>

    <!-- Detail panel -->
    <Transition name="panel">
      <div v-if="selected" class="detail-overlay" @click.self="selected = null">
        <div class="detail-panel">
          <div class="dp-header">
            <span class="state-badge large" :class="`st-${selected.state}`">{{ selected.state }}</span>
            <span v-if="selected.flow_type && selected.flow_type !== 'normal'" class="ft-badge large" :class="`ft-${selected.flow_type}`">{{ selected.flow_type }}</span>
            <button class="dp-close" @click="selected = null">&times;</button>
          </div>

          <div class="dp-section">
            <div class="dp-label">5-Tuple</div>
            <div class="dp-tuple mono">
              {{ selected.source_ip }}:{{ selected.source_port || '*' }}
              → {{ selected.destination_ip }}:{{ selected.destination_port || '*' }}
              ({{ selected.protocol || '?' }})
            </div>
          </div>

          <div class="dp-section" v-if="selected.nat_source_ip">
            <div class="dp-label">NAT</div>
            <div class="mono">{{ selected.nat_source_ip }} → {{ selected.nat_destination_ip || '—' }}</div>
          </div>

          <div class="dp-section">
            <div class="dp-label">Timing</div>
            <div class="dp-grid">
              <span>First seen</span><span class="mono">{{ fmtTime(selected.first_seen) }}</span>
              <span>Last seen</span><span class="mono">{{ fmtTime(selected.last_seen) }}</span>
              <span>Duration</span><span class="mono">{{ fmtDur(selected.duration_ms) }}</span>
            </div>
          </div>

          <div class="dp-section">
            <div class="dp-label">Counters</div>
            <div class="dp-grid">
              <span>Events</span><span class="mono">{{ selected.event_count }}</span>
              <span>Bytes in</span><span class="mono">{{ fmtBytes(selected.total_bytes_in) }}</span>
              <span>Bytes out</span><span class="mono">{{ fmtBytes(selected.total_bytes_out) }}</span>
              <span>Packets in</span><span class="mono">{{ selected.total_packets_in }}</span>
              <span>Packets out</span><span class="mono">{{ selected.total_packets_out }}</span>
            </div>
          </div>

          <div class="dp-section">
            <div class="dp-label">Action Breakdown</div>
            <div class="action-bars">
              <div v-for="a in actionBreakdown" :key="a.label" class="ab-row">
                <span class="ab-label">{{ a.label }}</span>
                <div class="ab-track"><div class="ab-fill" :class="a.cls" :style="{width: a.pct + '%'}"></div></div>
                <span class="ab-count">{{ a.count }}</span>
              </div>
            </div>
          </div>

          <div class="dp-section">
            <div class="dp-label">Summary</div>
            <div class="dp-grid">
              <span>Action</span><span>{{ (selected.action_summary||'').replace(/_/g,' ') }}</span>
              <span>Reason</span><span>{{ selected.reason_summary || '—' }}</span>
              <span>App</span><span>{{ selected.application || '—' }}</span>
              <span>Service</span><span>{{ selected.service || '—' }}</span>
              <span v-if="selected.backend_ip">Backend</span><span v-if="selected.backend_ip" class="mono">{{ selected.backend_ip }}:{{ selected.backend_port }}</span>
            </div>
          </div>

          <div class="dp-section">
            <div class="dp-label">Device</div>
            <div class="dp-grid">
              <span>Source ID</span><span class="mono">{{ selected.source_id }}</span>
              <span>Type</span><span>{{ selected.device_type }}</span>
              <span>Role</span><span>{{ selected.device_role || '—' }}</span>
              <span>Parser</span><span>{{ selected.parser_id }}</span>
            </div>
          </div>

          <div class="dp-section" v-if="selected.suspicious_reasons?.length">
            <div class="dp-label">Classification Reasons</div>
            <div class="dp-pills">
              <span
                v-for="(r, i) in selected.suspicious_reasons"
                :key="i"
                class="reason-pill"
              >{{ r }}</span>
            </div>
          </div>

          <div class="dp-section" v-if="selected.reset_ratio != null">
            <div class="dp-label">Behavioral Metrics</div>
            <div class="dp-grid">
              <span>Reset ratio</span>
              <span class="mono" :class="{ 'metric-danger': selected.reset_ratio > 0.3 }">
                {{ (selected.reset_ratio * 100).toFixed(1) }}%
              </span>
              <span>Deny ratio</span>
              <span class="mono" :class="{ 'metric-danger': selected.deny_ratio > 0.5 }">
                {{ (selected.deny_ratio * 100).toFixed(1) }}%
              </span>
              <span>Burst score</span>
              <span class="mono">{{ selected.burst_score?.toFixed(1) }} eps</span>
              <span>Asymmetric</span>
              <span>
                <span v-if="selected.asymmetric_behavior" class="asym-badge yes">Yes</span>
                <span v-else class="asym-badge no">No</span>
              </span>
            </div>
          </div>

          <div class="dp-suppressed" v-if="selected.suppressed">
            <el-icon><Warning /></el-icon> This flow is suppressed by an active rule.
          </div>

          <el-button size="small" type="primary" @click="viewRelated" style="margin-top:12px">
            View related events →
          </el-button>
        </div>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { Warning } from '@element-plus/icons-vue'
import api from '@/api'

const router = useRouter()
const PAGE_SIZE = 100

const flows = ref([])
const total = ref(0)
const offset = ref(0)
const loading = ref(false)
const loadingMore = ref(false)
const stats = ref(null)
const autoRefresh = ref(true)
const selected = ref(null)

const timelineBuckets = ref([])
const chartCanvas = ref(null)

let tableTimer = null
let statsTimer = null
let chartTimer = null

const filters = reactive({
  state: '', source_ip: '', destination_ip: '', protocol: '',
  application: '', action_summary: '', flow_type: '', show_suppressed: false,
})

const actionBreakdown = computed(() => {
  if (!selected.value) return []
  const s = selected.value
  const items = [
    { label: 'allow', count: s.allow_count || 0, cls: 'ab-allow' },
    { label: 'deny',  count: s.deny_count || 0, cls: 'ab-deny' },
    { label: 'drop',  count: s.drop_count || 0, cls: 'ab-drop' },
    { label: 'reset', count: s.reset_count || 0, cls: 'ab-reset' },
    { label: 'alert', count: s.alert_count || 0, cls: 'ab-alert' },
  ]
  const max = Math.max(...items.map(i => i.count), 1)
  return items.map(i => ({ ...i, pct: (i.count / max) * 100 }))
})

function buildParams(extra = {}) {
  const p = { limit: PAGE_SIZE, ...extra }
  if (filters.state) p.state = filters.state
  if (filters.source_ip) p.source_ip = filters.source_ip.trim()
  if (filters.destination_ip) p.destination_ip = filters.destination_ip.trim()
  if (filters.protocol) p.protocol = filters.protocol
  if (filters.application) p.application = filters.application.trim()
  if (filters.action_summary) p.action_summary = filters.action_summary
  if (filters.flow_type) p.flow_type = filters.flow_type
  if (filters.show_suppressed) p.suppressed = true
  return p
}

async function fetchFlows(append = false) {
  if (append) loadingMore.value = true; else loading.value = true
  try {
    const res = await api.get('/live-flows', { params: buildParams({ offset: offset.value }) })
    if (append) flows.value = [...flows.value, ...res.data.flows]
    else flows.value = res.data.flows
    total.value = res.data.total
  } catch {} finally { loading.value = false; loadingMore.value = false }
}
async function fetchStats() { try { stats.value = (await api.get('/live-flows/stats')).data } catch {} }
async function fetchTimeline() {
  try {
    timelineBuckets.value = (await api.get('/live-flows/timeline', { params: { minutes: 60 } })).data || []
    await nextTick(); drawChart()
  } catch {}
}
function resetAndFetch() { offset.value = 0; fetchFlows(); fetchStats(); fetchTimeline() }
function loadMore() { offset.value = flows.value.length; fetchFlows(true) }

function openDetail(row) { selected.value = row }
function viewRelated() {
  if (!selected.value) return
  router.push(`/live-events?source_ip=${selected.value.source_ip}&destination_ip=${selected.value.destination_ip}`)
}

function fmtTime(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, { month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false })
}
function fmtDur(ms) {
  if (ms == null) return '—'
  if (ms < 1000) return `${ms}ms`
  return `${(ms/1000).toFixed(1)}s`
}
function fmtBytes(n) {
  if (n == null) return '0'
  if (n < 1024) return `${n}B`
  if (n < 1048576) return `${(n/1024).toFixed(1)}K`
  return `${(n/1048576).toFixed(1)}M`
}

// ── Chart ───────────────────────────────────────────────────────────────────
function drawChart() {
  const canvas = chartCanvas.value; if (!canvas) return
  const data = timelineBuckets.value; if (!data.length) return
  const dpr = window.devicePixelRatio || 1
  const rect = canvas.getBoundingClientRect()
  const W = rect.width, H = 180
  canvas.width = W * dpr; canvas.height = H * dpr; canvas.style.height = H + 'px'
  const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr); ctx.clearRect(0, 0, W, H)
  const pad = { top:10, right:12, bottom:28, left:42 }
  const cw = W - pad.left - pad.right, ch = H - pad.top - pad.bottom
  let maxY = 1
  for (const b of data) maxY = Math.max(maxY, b.completed||0, b.denied||0, b.reset||0, b.dropped||0)
  maxY = Math.ceil(maxY * 1.15) || 1
  const stepX = data.length > 1 ? cw / (data.length - 1) : cw
  ctx.strokeStyle = '#ebeef5'; ctx.lineWidth = 1
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + ch - (ch * i / 4)
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + cw, y); ctx.stroke()
    ctx.fillStyle = '#909399'; ctx.font = '10px sans-serif'; ctx.textAlign = 'right'
    ctx.fillText(String(Math.round(maxY * i / 4)), pad.left - 6, y + 3)
  }
  const series = [
    { key:'completed', color:'#22c55e' }, { key:'denied', color:'#ef4444' },
    { key:'reset', color:'#f97316' }, { key:'dropped', color:'#991b1b' },
  ]
  for (const s of series) {
    ctx.beginPath(); ctx.strokeStyle = s.color; ctx.lineWidth = 2; ctx.lineJoin = 'round'
    for (let i = 0; i < data.length; i++) {
      const x = pad.left + i * stepX, v = data[i][s.key] || 0
      const y = pad.top + ch - (v / maxY) * ch
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y)
    }
    ctx.stroke()
    ctx.lineTo(pad.left + (data.length - 1) * stepX, pad.top + ch)
    ctx.lineTo(pad.left, pad.top + ch); ctx.closePath()
    ctx.fillStyle = s.color + '18'; ctx.fill()
  }
  ctx.fillStyle = '#909399'; ctx.font = '10px sans-serif'; ctx.textAlign = 'center'
  const labelEvery = Math.max(1, Math.floor(data.length / 8))
  for (let i = 0; i < data.length; i += labelEvery) {
    const x = pad.left + i * stepX, b = data[i].bucket || ''
    const hm = b.includes('T') ? b.split('T')[1]?.substring(0,5) : b.substring(11,16)
    ctx.fillText(hm || '', x, H - 6)
  }
}
function onChartHover(e) {
  const canvas = chartCanvas.value; if (!canvas || !timelineBuckets.value.length) return
  const rect = canvas.getBoundingClientRect(), data = timelineBuckets.value
  const pad = { left:42, right:12 }, cw = rect.width - pad.left - pad.right
  const stepX = data.length > 1 ? cw / (data.length - 1) : cw
  const idx = Math.round((e.clientX - rect.left - pad.left) / stepX)
  if (idx < 0 || idx >= data.length) { canvas.title = ''; return }
  const b = data[idx], hm = (b.bucket||'').split('T')[1]?.substring(0,5) || ''
  canvas.title = `${hm}  completed:${b.completed} denied:${b.denied} reset:${b.reset} dropped:${b.dropped}`
}

// ── Timers ──────────────────────────────────────────────────────────────────
function startTimers() {
  stopTimers()
  if (!autoRefresh.value) return
  tableTimer = setInterval(() => { offset.value = 0; fetchFlows() }, 10000)
  statsTimer = setInterval(fetchStats, 15000)
  chartTimer = setInterval(fetchTimeline, 30000)
}
function stopTimers() {
  if (tableTimer) { clearInterval(tableTimer); tableTimer = null }
  if (statsTimer) { clearInterval(statsTimer); statsTimer = null }
  if (chartTimer) { clearInterval(chartTimer); chartTimer = null }
}
watch(autoRefresh, (on) => { if (on) startTimers(); else stopTimers() })

onMounted(() => { fetchFlows(); fetchStats(); fetchTimeline(); startTimers() })
onUnmounted(stopTimers)
</script>

<style scoped>
.live-flows { max-width:1500px; margin:0 auto; }

/* Stats */
.stats-bar { display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap; }
.stat-card { background:white; border-radius:8px; border:1px solid #e4e7ed; padding:10px 14px; min-width:90px; flex:1; }
.stat-value { font-size:18px; font-weight:700; color:#1a1a2e; }
.stat-label { font-size:10px; color:#909399; text-transform:uppercase; margin-top:1px; }
.sb-active .stat-value { color:#409eff; }
.sb-completed .stat-value { color:#67c23a; }
.sb-denied .stat-value { color:#f56c6c; }
.sb-reset .stat-value { color:#f97316; }
.sb-dropped .stat-value { color:#991b1b; }
.sb-scanning .stat-value { color:#a16207; }
.sb-suspicious .stat-value { color:#7c3aed; }
.mono { font-family:'SF Mono','Menlo',monospace; font-size:12px; }

/* Chart */
.timeline-chart-wrap { background:white; border-radius:8px; border:1px solid #e4e7ed; padding:12px 16px; margin-bottom:12px; }
.chart-header { display:flex; justify-content:space-between; margin-bottom:8px; }
.chart-title { font-size:13px; font-weight:600; color:#303133; }
.chart-legend { display:flex; gap:12px; font-size:11px; color:#606266; }
.legend-item { display:flex; align-items:center; gap:4px; }
.leg-dot { width:8px; height:8px; border-radius:50%; display:inline-block; }
.timeline-canvas { width:100%; height:180px; cursor:crosshair; }

/* Filters */
.filter-bar { display:flex; align-items:center; gap:6px; flex-wrap:wrap; margin-bottom:10px; padding:8px 12px; background:white; border-radius:8px; border:1px solid #e4e7ed; }
.filter-right { margin-left:auto; display:flex; align-items:center; gap:8px; }

/* Table */
.table-wrap { background:white; border-radius:8px; border:1px solid #e4e7ed; overflow:hidden; }
.ts { color:#606266; white-space:nowrap; font-size:11px; }
.port-hint { color:#c0c4cc; font-size:11px; }

.state-badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; text-transform:uppercase; }
.st-active { background:#d9ecff; color:#409eff; }
.st-completed { background:#e1f3d8; color:#67c23a; }
.st-denied { background:#fde2e2; color:#f56c6c; }
.st-reset { background:#faecd8; color:#f97316; }
.st-dropped { background:#f5d0d0; color:#991b1b; }
.st-expired { background:#ebeef5; color:#909399; }
.state-badge.large { font-size:14px; padding:4px 14px; }

/* Flow type badges */
.ft-badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; text-transform:uppercase; }
.ft-badge.large { font-size:13px; padding:3px 12px; }
.ft-normal { color:#909399; font-size:11px; }
.ft-blocked    { background:#fde2e2; color:#f56c6c; }
.ft-unstable   { background:#faecd8; color:#f97316; }
.ft-scanning   { background:#fef9c3; color:#a16207; }
.ft-suspicious { background:#e8def8; color:#7c3aed; }

.pagination-bar { display:flex; justify-content:space-between; align-items:center; margin-top:8px; padding:6px 4px; }
.page-info { font-size:12px; color:#909399; }

/* Detail panel */
.detail-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.15); z-index:200; display:flex; justify-content:flex-end; }
.detail-panel { width:420px; max-width:90vw; background:white; height:100vh; overflow-y:auto; padding:20px; box-shadow:-4px 0 20px rgba(0,0,0,0.08); }
.panel-enter-active,.panel-leave-active { transition:transform 0.25s ease; }
.panel-enter-from,.panel-leave-to { transform:translateX(100%); }

.dp-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
.dp-close { background:none; border:none; font-size:24px; cursor:pointer; color:#909399; }
.dp-close:hover { color:#303133; }
.dp-section { margin-bottom:14px; }
.dp-label { font-size:11px; font-weight:600; text-transform:uppercase; color:#909399; margin-bottom:4px; }
.dp-tuple { font-size:13px; color:#303133; }
.dp-grid { display:grid; grid-template-columns:auto 1fr; gap:2px 12px; font-size:12px; color:#606266; }
.dp-grid .mono { color:#303133; }

/* Action bars */
.action-bars { display:flex; flex-direction:column; gap:4px; }
.ab-row { display:flex; align-items:center; gap:6px; font-size:11px; }
.ab-label { width:40px; text-align:right; color:#909399; }
.ab-track { flex:1; height:8px; background:#ebeef5; border-radius:4px; overflow:hidden; }
.ab-fill { height:100%; border-radius:4px; transition:width 0.3s; }
.ab-fill.ab-allow { background:#67c23a; }
.ab-fill.ab-deny { background:#f56c6c; }
.ab-fill.ab-drop { background:#991b1b; }
.ab-fill.ab-reset { background:#f97316; }
.ab-fill.ab-alert { background:#409eff; }
.ab-count { width:30px; text-align:right; color:#606266; font-weight:600; }

.dp-pills { display:flex; flex-wrap:wrap; gap:6px; margin-top:4px; }
.reason-pill { display:inline-block; padding:3px 10px; border-radius:12px; font-size:11px; background:#fef9c3; color:#a16207; border:1px solid #fde68a; }
.metric-danger { color:#f56c6c !important; font-weight:700; }
.asym-badge { display:inline-block; padding:1px 8px; border-radius:8px; font-size:11px; font-weight:600; }
.asym-badge.yes { background:#fde2e2; color:#f56c6c; }
.asym-badge.no { background:#e1f3d8; color:#67c23a; }
.dp-suppressed { display:flex; align-items:center; gap:6px; padding:8px 12px; background:#fdf6ec; border:1px solid #e6a23c; border-radius:6px; font-size:12px; color:#e6a23c; margin-top:10px; }
</style>
