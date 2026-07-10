<template>
  <div class="web-transactions">
    <!-- Stats bar -->
    <div class="stats-bar" v-if="stats">
      <div class="stat-card">
        <div class="stat-value">{{ (stats.total || 0).toLocaleString() }}</div>
        <div class="stat-label">Total Transactions</div>
      </div>
      <div class="stat-card sb-duration">
        <div class="stat-value">{{ fmtDur(stats.avg_duration_ms) }}</div>
        <div class="stat-label">Avg Duration</div>
      </div>
      <div class="stat-card" v-if="stats.top_hosts?.[0]">
        <div class="stat-value mono">{{ stats.top_hosts[0].host }}</div>
        <div class="stat-label">Top Host ({{ stats.top_hosts[0].count }})</div>
      </div>
      <div class="stat-card" v-if="stats.top_source_ips?.[0]">
        <div class="stat-value mono">{{ stats.top_source_ips[0].source_ip }}</div>
        <div class="stat-label">Top Source ({{ stats.top_source_ips[0].count }})</div>
      </div>
      <div class="stat-card" v-for="sc in topStatusCodes" :key="sc.status_code" :class="statusCardClass(sc.status_code)">
        <div class="stat-value">{{ sc.count.toLocaleString() }}</div>
        <div class="stat-label">HTTP {{ sc.status_code }}</div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filter-bar">
      <el-input v-model="filters.host" placeholder="Host" clearable size="small" style="width:160px" @clear="resetAndFetch" @keyup.enter="resetAndFetch" />
      <el-input v-model="filters.source_ip" placeholder="Source IP" clearable size="small" style="width:140px" @clear="resetAndFetch" @keyup.enter="resetAndFetch" />
      <el-select v-model="filters.method" placeholder="Method" clearable size="small" style="width:110px" @change="resetAndFetch">
        <el-option label="All methods" value="" />
        <el-option v-for="m in ['GET','POST','PUT','DELETE','HEAD','OPTIONS','PATCH','CONNECT']" :key="m" :label="m" :value="m" />
      </el-select>
      <el-input v-model="filters.status_code" placeholder="Status code" clearable size="small" style="width:110px" @clear="resetAndFetch" @keyup.enter="resetAndFetch" />
      <el-select v-model="filters.action" placeholder="Action" clearable size="small" style="width:110px" @change="resetAndFetch">
        <el-option label="All actions" value="" />
        <el-option v-for="a in ['allow','deny','block','alert']" :key="a" :label="a" :value="a" />
      </el-select>
      <el-date-picker
        v-model="timeRange"
        type="datetimerange"
        size="small"
        start-placeholder="Start time"
        end-placeholder="End time"
        style="width:320px"
        @change="resetAndFetch"
      />
      <el-input v-model="filters.search" placeholder="Search URL" clearable size="small" style="width:180px" @clear="resetAndFetch" @keyup.enter="resetAndFetch" />
      <el-button size="small" @click="resetAndFetch" :loading="loading">Search</el-button>
      <div class="filter-right">
        <el-switch v-model="autoRefresh" active-text="Auto" size="small" />
      </div>
    </div>

    <!-- Table -->
    <div class="table-wrap">
      <el-table :data="transactions" stripe size="small" v-loading="loading && !transactions.length" empty-text="No web transactions found" style="width:100%" @row-click="openDetail" highlight-current-row>
        <el-table-column label="Time" width="150"><template #default="{row}"><span class="mono ts">{{ fmtTime(row.transaction_time) }}</span></template></el-table-column>
        <el-table-column label="Source" min-width="130"><template #default="{row}"><span class="mono">{{ row.source_ip }}<span class="port-hint" v-if="row.source_port">:{{ row.source_port }}</span></span></template></el-table-column>
        <el-table-column label="Host" min-width="160"><template #default="{row}"><span class="mono">{{ row.host || '—' }}</span></template></el-table-column>
        <el-table-column label="Method" width="80" align="center"><template #default="{row}"><span class="method-badge" :class="`m-${(row.method||'').toLowerCase()}`">{{ row.method || '—' }}</span></template></el-table-column>
        <el-table-column label="URL" min-width="220"><template #default="{row}"><span class="mono url-cell" :title="row.url">{{ truncateUrl(row.url) }}</span></template></el-table-column>
        <el-table-column label="Status" width="80" align="center"><template #default="{row}"><span v-if="row.status_code" class="status-badge" :class="statusClass(row.status_code)">{{ row.status_code }}</span><span v-else class="dim">—</span></template></el-table-column>
        <el-table-column label="Action" width="80" align="center"><template #default="{row}"><span v-if="row.action" class="action-badge" :class="`act-${row.action}`">{{ row.action }}</span><span v-else class="dim">—</span></template></el-table-column>
        <el-table-column label="Category" width="110"><template #default="{row}">{{ row.category || '—' }}</template></el-table-column>
        <el-table-column label="Bytes" width="100" align="right"><template #default="{row}">{{ fmtBytes((row.bytes_in || 0) + (row.bytes_out || 0)) }}</template></el-table-column>
        <el-table-column label="Duration" width="85" align="right"><template #default="{row}">{{ fmtDur(row.duration_ms) }}</template></el-table-column>
      </el-table>
    </div>

    <div class="pagination-bar">
      <span class="page-info">Showing {{ transactions.length }} of {{ total }}</span>
      <el-button v-if="transactions.length < total" size="small" :loading="loadingMore" @click="loadMore">Load more</el-button>
    </div>

    <!-- Detail panel -->
    <Transition name="panel">
      <div v-if="selected" class="detail-overlay" @click.self="selected = null">
        <div class="detail-panel">
          <div class="dp-header">
            <span v-if="selected.status_code" class="status-badge large" :class="statusClass(selected.status_code)">{{ selected.status_code }}</span>
            <span class="method-badge large" :class="`m-${(selected.method||'').toLowerCase()}`">{{ selected.method || '?' }}</span>
            <span v-if="selected.action" class="action-badge large" :class="`act-${selected.action}`">{{ selected.action }}</span>
            <button class="dp-close" @click="selected = null">&times;</button>
          </div>

          <div class="dp-section">
            <div class="dp-label">Request</div>
            <div class="dp-url mono">{{ selected.host || '' }}{{ selected.url || '—' }}</div>
          </div>

          <div class="dp-section">
            <div class="dp-label">Connection</div>
            <div class="dp-tuple mono">
              {{ selected.source_ip }}:{{ selected.source_port || '*' }}
              → {{ selected.destination_ip }}:{{ selected.destination_port || '*' }}
            </div>
          </div>

          <div class="dp-section">
            <div class="dp-label">Timing</div>
            <div class="dp-grid">
              <span>Transaction time</span><span class="mono">{{ fmtTime(selected.transaction_time) }}</span>
              <span>Duration</span><span class="mono">{{ fmtDur(selected.duration_ms) }}</span>
            </div>
          </div>

          <div class="dp-section">
            <div class="dp-label">HTTP</div>
            <div class="dp-grid">
              <span>Method</span><span class="mono">{{ selected.method || '—' }}</span>
              <span>Status</span><span class="mono">{{ selected.status_code || '—' }}</span>
              <span>Content type</span><span class="mono">{{ selected.content_type || '—' }}</span>
              <span>Referer</span><span class="mono dp-break">{{ selected.referer || '—' }}</span>
              <span>User agent</span><span class="mono dp-break">{{ selected.user_agent || '—' }}</span>
            </div>
          </div>

          <div class="dp-section">
            <div class="dp-label">Classification</div>
            <div class="dp-grid">
              <span>Category</span><span>{{ selected.category || '—' }}</span>
              <span>Action</span><span>{{ selected.action || '—' }}</span>
            </div>
          </div>

          <div class="dp-section">
            <div class="dp-label">Counters</div>
            <div class="dp-grid">
              <span>Bytes in</span><span class="mono">{{ fmtBytes(selected.bytes_in) }}</span>
              <span>Bytes out</span><span class="mono">{{ fmtBytes(selected.bytes_out) }}</span>
            </div>
          </div>

          <div class="dp-section">
            <div class="dp-label">Device</div>
            <div class="dp-grid">
              <span>Source ID</span><span class="mono">{{ selected.source_id }}</span>
              <span>Type</span><span>{{ selected.device_type || '—' }}</span>
            </div>
          </div>

          <div class="dp-suppressed" v-if="selected.suppressed">
            <el-icon><Warning /></el-icon> This transaction is suppressed by an active rule.
          </div>

          <el-button size="small" type="primary" @click="viewRelated" style="margin-top:12px">
            View related flows →
          </el-button>
        </div>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { Warning } from '@element-plus/icons-vue'
import { getWebTransactions, getWebTransaction, getWebTransactionStats } from '@/api'

const router = useRouter()
const PAGE_SIZE = 100

const transactions = ref([])
const total = ref(0)
const offset = ref(0)
const loading = ref(false)
const loadingMore = ref(false)
const stats = ref(null)
const autoRefresh = ref(true)
const selected = ref(null)
const timeRange = ref(null)

let tableTimer = null
let statsTimer = null

const filters = reactive({
  host: '', source_ip: '', method: '', status_code: '', action: '', search: '',
})

const topStatusCodes = computed(() => {
  // Backend returns status_code_counts as an object: { "200": 2, "403": 1 }
  const counts = stats.value?.status_code_counts || {}
  return Object.entries(counts)
    .map(([status_code, count]) => ({ status_code, count: Number(count) || 0 }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 4)
})

function buildParams(extra = {}) {
  const p = { limit: PAGE_SIZE, ...extra }
  if (filters.host) p.host = filters.host.trim()
  if (filters.source_ip) p.source_ip = filters.source_ip.trim()
  if (filters.method) p.method = filters.method
  if (filters.status_code) p.status_code = String(filters.status_code).trim()
  if (filters.action) p.action = filters.action
  if (filters.search) p.search = filters.search.trim()
  if (timeRange.value?.[0]) p.start_time = new Date(timeRange.value[0]).toISOString()
  if (timeRange.value?.[1]) p.end_time = new Date(timeRange.value[1]).toISOString()
  return p
}

function extractRows(data) {
  if (Array.isArray(data)) return data
  return data.transactions || data.flows || data.items || data.results || []
}

async function fetchTransactions(append = false) {
  if (append) loadingMore.value = true; else loading.value = true
  try {
    const res = await getWebTransactions(buildParams({ offset: offset.value }))
    const rows = extractRows(res.data)
    if (append) transactions.value = [...transactions.value, ...rows]
    else transactions.value = rows
    total.value = res.data.total ?? rows.length
  } catch {} finally { loading.value = false; loadingMore.value = false }
}
async function fetchStats() { try { stats.value = (await getWebTransactionStats()).data } catch {} }
function resetAndFetch() { offset.value = 0; fetchTransactions(); fetchStats() }
function loadMore() { offset.value = transactions.value.length; fetchTransactions(true) }

async function openDetail(row) {
  selected.value = row
  if (row.id == null) return
  try {
    const res = await getWebTransaction(row.id)
    if (res.data && selected.value && selected.value.id === row.id) {
      selected.value = { ...row, ...res.data }
    }
  } catch {}
}

function viewRelated() {
  if (!selected.value) return
  router.push(`/live-flows?source_ip=${selected.value.source_ip}&destination_ip=${selected.value.destination_ip}`)
}

function statusClass(code) {
  const c = Number(code)
  if (c >= 500) return 'sc-5xx'
  if (c >= 400) return 'sc-4xx'
  if (c >= 300) return 'sc-3xx'
  if (c >= 200) return 'sc-2xx'
  return 'sc-1xx'
}
function statusCardClass(code) {
  const c = Number(code)
  if (c >= 500) return 'sb-5xx'
  if (c >= 400) return 'sb-4xx'
  if (c >= 300) return 'sb-3xx'
  if (c >= 200) return 'sb-2xx'
  return ''
}

function truncateUrl(url) {
  if (!url) return '—'
  return url.length > 60 ? url.slice(0, 57) + '…' : url
}

function fmtTime(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString(undefined, { month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false })
}
function fmtDur(ms) {
  if (ms == null) return '—'
  if (ms < 1000) return `${Math.round(ms)}ms`
  return `${(ms/1000).toFixed(1)}s`
}
function fmtBytes(n) {
  if (n == null) return '0'
  if (n < 1024) return `${n}B`
  if (n < 1048576) return `${(n/1024).toFixed(1)}K`
  return `${(n/1048576).toFixed(1)}M`
}

// ── Timers ──────────────────────────────────────────────────────────────────
function startTimers() {
  stopTimers()
  if (!autoRefresh.value) return
  tableTimer = setInterval(() => { offset.value = 0; fetchTransactions() }, 10000)
  statsTimer = setInterval(fetchStats, 15000)
}
function stopTimers() {
  if (tableTimer) { clearInterval(tableTimer); tableTimer = null }
  if (statsTimer) { clearInterval(statsTimer); statsTimer = null }
}
watch(autoRefresh, (on) => { if (on) startTimers(); else stopTimers() })

onMounted(() => { fetchTransactions(); fetchStats(); startTimers() })
onUnmounted(stopTimers)
</script>

<style scoped>
.web-transactions { max-width:1500px; margin:0 auto; }

/* Stats */
.stats-bar { display:flex; gap:8px; margin-bottom:12px; flex-wrap:wrap; }
.stat-card { background:white; border-radius:8px; border:1px solid #e4e7ed; padding:10px 14px; min-width:90px; flex:1; }
.stat-value { font-size:18px; font-weight:700; color:#1a1a2e; }
.stat-label { font-size:10px; color:#909399; text-transform:uppercase; margin-top:1px; }
.sb-duration .stat-value { color:#409eff; }
.sb-2xx .stat-value { color:#67c23a; }
.sb-3xx .stat-value { color:#409eff; }
.sb-4xx .stat-value { color:#e6a23c; }
.sb-5xx .stat-value { color:#f56c6c; }
.mono { font-family:'SF Mono','Menlo',monospace; font-size:12px; }

/* Filters */
.filter-bar { display:flex; align-items:center; gap:6px; flex-wrap:wrap; margin-bottom:10px; padding:8px 12px; background:white; border-radius:8px; border:1px solid #e4e7ed; }
.filter-right { margin-left:auto; display:flex; align-items:center; gap:8px; }

/* Table */
.table-wrap { background:white; border-radius:8px; border:1px solid #e4e7ed; overflow:hidden; }
.ts { color:#606266; white-space:nowrap; font-size:11px; }
.port-hint { color:#c0c4cc; font-size:11px; }
.url-cell { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; display:block; }
.dim { color:#c0c4cc; }

/* Status badges */
.status-badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }
.sc-1xx { background:#ebeef5; color:#909399; }
.sc-2xx { background:#e1f3d8; color:#67c23a; }
.sc-3xx { background:#d9ecff; color:#409eff; }
.sc-4xx { background:#faecd8; color:#e6a23c; }
.sc-5xx { background:#fde2e2; color:#f56c6c; }
.status-badge.large { font-size:14px; padding:4px 14px; }

/* Method badges */
.method-badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; background:#ebeef5; color:#606266; }
.method-badge.large { font-size:13px; padding:3px 12px; }
.m-get { background:#d9ecff; color:#409eff; }
.m-post { background:#e1f3d8; color:#67c23a; }
.m-put { background:#faecd8; color:#e6a23c; }
.m-patch { background:#faecd8; color:#f97316; }
.m-delete { background:#fde2e2; color:#f56c6c; }
.m-connect { background:#e8def8; color:#7c3aed; }

/* Action badges */
.action-badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; text-transform:uppercase; }
.action-badge.large { font-size:13px; padding:3px 12px; }
.act-allow { background:#e1f3d8; color:#67c23a; }
.act-deny { background:#fde2e2; color:#f56c6c; }
.act-block { background:#f5d0d0; color:#991b1b; }
.act-alert { background:#faecd8; color:#e6a23c; }

.pagination-bar { display:flex; justify-content:space-between; align-items:center; margin-top:8px; padding:6px 4px; }
.page-info { font-size:12px; color:#909399; }

/* Detail panel */
.detail-overlay { position:fixed; inset:0; background:rgba(0,0,0,0.15); z-index:200; display:flex; justify-content:flex-end; }
.detail-panel { width:420px; max-width:90vw; background:white; height:100vh; overflow-y:auto; padding:20px; box-shadow:-4px 0 20px rgba(0,0,0,0.08); }
.panel-enter-active,.panel-leave-active { transition:transform 0.25s ease; }
.panel-enter-from,.panel-leave-to { transform:translateX(100%); }

.dp-header { display:flex; align-items:center; gap:8px; margin-bottom:16px; }
.dp-close { background:none; border:none; font-size:24px; cursor:pointer; color:#909399; margin-left:auto; }
.dp-close:hover { color:#303133; }
.dp-section { margin-bottom:14px; }
.dp-label { font-size:11px; font-weight:600; text-transform:uppercase; color:#909399; margin-bottom:4px; }
.dp-url { font-size:13px; color:#303133; word-break:break-all; }
.dp-tuple { font-size:13px; color:#303133; }
.dp-grid { display:grid; grid-template-columns:auto 1fr; gap:2px 12px; font-size:12px; color:#606266; }
.dp-grid .mono { color:#303133; }
.dp-break { word-break:break-all; }
.dp-suppressed { display:flex; align-items:center; gap:6px; padding:8px 12px; background:#fdf6ec; border:1px solid #e6a23c; border-radius:6px; font-size:12px; color:#e6a23c; margin-top:10px; }
</style>
