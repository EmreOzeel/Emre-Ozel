<template>
  <div class="packet-engine">
    <div class="page-header">
      <h2>Packet Engine</h2>
      <p>Live SPAN packet capture, streaming analysis, and watch rules</p>
    </div>

    <!-- ══ Section 1 — Engine Status ════════════════════════════════════ -->
    <el-card class="pe-card" shadow="never">
      <template #header>
        <div class="card-header-row">
          <span class="card-title">Engine Status</span>
          <span class="status-dot-wrap">
            <span class="status-dot" :class="engineOnline ? 'dot-on' : 'dot-off'"></span>
            {{ engineOnline ? 'Running' : 'Offline' }}
          </span>
        </div>
      </template>
      <div class="status-grid" v-if="engineOnline">
        <div class="sg-item">
          <div class="sg-value">{{ engineStats.packets_total?.toLocaleString() || 0 }}</div>
          <div class="sg-label">Packets Total</div>
        </div>
        <div class="sg-item">
          <div class="sg-value">{{ engineStats.active_flows?.toLocaleString() || 0 }}</div>
          <div class="sg-label">Active Flows</div>
        </div>
        <div class="sg-item">
          <div class="sg-value">{{ engineStats.alerts_total?.toLocaleString() || 0 }}</div>
          <div class="sg-label">Alerts Sent</div>
        </div>
        <div class="sg-item">
          <div class="sg-value">{{ engineStats.watch_count || 0 }}</div>
          <div class="sg-label">Watch Rules</div>
        </div>
      </div>
      <div v-else class="empty-hint">
        Packet engine is not reachable. Check that the Go service is running.
      </div>
    </el-card>

    <!-- ══ Section 2 — Watch Rules ══════════════════════════════════════ -->
    <el-card class="pe-card" shadow="never">
      <template #header>
        <div class="card-header-row">
          <span class="card-title">Watch Rules</span>
          <el-button type="primary" size="small" @click="showAddForm = !showAddForm">
            {{ showAddForm ? 'Cancel' : 'Add Watch' }}
          </el-button>
        </div>
      </template>

      <!-- Add form -->
      <div v-if="showAddForm" class="add-form">
        <div class="form-row">
          <el-input v-model="newWatch.target_ip" placeholder="Target IP" style="width: 160px" />
          <el-input-number v-model="newWatch.target_port" :min="0" :max="65535" placeholder="Port (0=any)" style="width: 140px" />
          <el-select v-model="newWatch.protocol" placeholder="Protocol" style="width: 120px">
            <el-option label="Any" value="" />
            <el-option label="TCP" value="TCP" />
            <el-option label="UDP" value="UDP" />
          </el-select>
          <el-input-number v-model="newWatch.max_pps" :min="0" placeholder="Max PPS" style="width: 130px" />
          <el-input-number v-model="newWatch.max_bps" :min="0" placeholder="Max BPS" style="width: 130px" />
          <el-input-number v-model="newWatch.max_conns" :min="0" placeholder="Max Conns" style="width: 130px" />
          <el-button type="success" size="small" @click="addWatch" :loading="addingWatch">Save</el-button>
        </div>
      </div>

      <!-- Watch table -->
      <el-table :data="watches" stripe style="width: 100%" empty-text="No watch rules configured">
        <el-table-column prop="target_ip" label="Target IP" width="160">
          <template #default="{ row }">
            <span class="mono">{{ row.target_ip }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="target_port" label="Port" width="80">
          <template #default="{ row }">
            {{ row.target_port || 'any' }}
          </template>
        </el-table-column>
        <el-table-column prop="protocol" label="Protocol" width="100">
          <template #default="{ row }">
            {{ row.protocol || 'any' }}
          </template>
        </el-table-column>
        <el-table-column prop="max_pps" label="Max PPS" width="100">
          <template #default="{ row }">
            {{ row.max_pps || '—' }}
          </template>
        </el-table-column>
        <el-table-column prop="max_bps" label="Max BPS" width="100">
          <template #default="{ row }">
            {{ row.max_bps || '—' }}
          </template>
        </el-table-column>
        <el-table-column prop="max_conns" label="Max Conns" width="100">
          <template #default="{ row }">
            {{ row.max_conns || '—' }}
          </template>
        </el-table-column>
        <el-table-column label="Actions" width="80">
          <template #default="{ row }">
            <el-button
              type="danger"
              link
              size="small"
              @click="removeWatch(row)"
            >Delete</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- ══ Section 3 — Recent Stream Alerts ═════════════════════════════ -->
    <el-card class="pe-card" shadow="never">
      <template #header>
        <span class="card-title">Recent Stream Alerts</span>
      </template>
      <el-table :data="streamAlerts" stripe style="width: 100%" empty-text="No stream alerts">
        <el-table-column label="Time" width="170">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column label="Type" width="160">
          <template #default="{ row }">
            <span class="alert-type-badge" :class="alertTypeClass(row._alertType)">
              {{ row._alertType }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="Source IP" width="140">
          <template #default="{ row }">
            <span class="mono">{{ row._srcIp || '—' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="Message" min-width="300">
          <template #default="{ row }">
            {{ row._cleanMsg }}
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- ══ Section 4 — Live Flow Mini-table ═════════════════════════════ -->
    <el-card class="pe-card" shadow="never">
      <template #header>
        <div class="card-header-row">
          <span class="card-title">Live Flows (Packet Engine)</span>
          <el-button link type="primary" size="small" @click="$router.push('/live-flows')">
            View all
          </el-button>
        </div>
      </template>
      <el-table :data="liveFlows" stripe style="width: 100%" empty-text="No packet engine flows">
        <el-table-column label="Src IP" width="140">
          <template #default="{ row }">
            <span class="mono">{{ row.source_ip }}</span>
          </template>
        </el-table-column>
        <el-table-column label="Dst IP:Port" width="180">
          <template #default="{ row }">
            <span class="mono">{{ row.destination_ip }}:{{ row.destination_port }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="protocol" label="Protocol" width="90" />
        <el-table-column label="Packets" width="90">
          <template #default="{ row }">
            {{ (row.packet_count || 0).toLocaleString() }}
          </template>
        </el-table-column>
        <el-table-column label="Bytes" width="100">
          <template #default="{ row }">
            {{ formatBytes(row.bytes_total || row.bytes_in || 0) }}
          </template>
        </el-table-column>
        <el-table-column label="Duration" width="100">
          <template #default="{ row }">
            {{ formatDuration(row.duration_ms) }}
          </template>
        </el-table-column>
        <el-table-column label="State" width="100">
          <template #default="{ row }">
            <span class="state-badge" :class="'state-' + (row.state || row.action || 'active')">
              {{ row.state || row.action || 'active' }}
            </span>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import api from '../api'
import { fetchPacketWatches, createPacketWatch, deletePacketWatch } from '../api'

// ── State ────────────────────────────────────────────────────────────────────
const engineOnline = ref(false)
const engineStats = ref({})
const watches = ref([])
const streamAlerts = ref([])
const liveFlows = ref([])
const showAddForm = ref(false)
const addingWatch = ref(false)

const newWatch = ref({
  target_ip: '',
  target_port: 0,
  protocol: '',
  max_pps: 0,
  max_bps: 0,
  max_conns: 0,
})

let fastTimer = null
let slowTimer = null

// ── Fetchers ─────────────────────────────────────────────────────────────────
async function fetchStatus() {
  try {
    const res = await fetchPacketWatches()
    engineOnline.value = true
    watches.value = res.data || []
    engineStats.value = { ...engineStats.value, watch_count: watches.value.length }
  } catch {
    engineOnline.value = false
    watches.value = []
  }

  // Try to get stats from live flows
  try {
    const res = await api.get('/live-flows/stats')
    engineStats.value = {
      ...engineStats.value,
      active_flows: res.data?.active_flows || 0,
      packets_total: res.data?.total_flows || 0,
    }
  } catch {}
}

async function fetchAlerts() {
  try {
    const res = await api.get('/notifications', {
      params: { unread_only: false, limit: 50 },
    })
    const all = res.data?.notifications || res.data || []
    const filtered = all
      .filter(n => n.message && n.message.startsWith('[STREAM ALERT]'))
      .slice(0, 20)
      .map(n => {
        const msg = n.message.replace('[STREAM ALERT] ', '')
        const colonIdx = msg.indexOf(':')
        const alertType = colonIdx > 0 ? msg.substring(0, colonIdx).trim() : 'unknown'
        const cleanMsg = colonIdx > 0 ? msg.substring(colonIdx + 1).trim() : msg

        // Try to extract source IP from message
        const ipMatch = cleanMsg.match(/(?:src=|from |for )(\d+\.\d+\.\d+\.\d+)/)
        return {
          ...n,
          _alertType: alertType,
          _cleanMsg: cleanMsg,
          _srcIp: ipMatch ? ipMatch[1] : '',
        }
      })
    streamAlerts.value = filtered
  } catch {}
}

async function fetchFlows() {
  try {
    const res = await api.get('/live-flows', {
      params: { limit: 10, parser_id: 'gopacket' },
    })
    let flows = res.data?.flows || res.data || []
    // Fallback: also try filtering by device_type
    if (!flows.length) {
      const res2 = await api.get('/live-flows', {
        params: { limit: 10, device_type: 'packet_engine' },
      })
      flows = res2.data?.flows || res2.data || []
    }
    liveFlows.value = flows.slice(0, 10)
  } catch {}
}

// ── Watch management ─────────────────────────────────────────────────────────
async function addWatch() {
  if (!newWatch.value.target_ip) {
    ElMessage.warning('Target IP is required')
    return
  }
  addingWatch.value = true
  try {
    await createPacketWatch(newWatch.value)
    ElMessage.success('Watch rule added')
    showAddForm.value = false
    newWatch.value = { target_ip: '', target_port: 0, protocol: '', max_pps: 0, max_bps: 0, max_conns: 0 }
    await fetchStatus()
  } catch (err) {
    ElMessage.error(err.response?.data?.detail || 'Failed to add watch rule')
  } finally {
    addingWatch.value = false
  }
}

async function removeWatch(rule) {
  try {
    await deletePacketWatch(rule.target_ip, rule.target_port || 0)
    ElMessage.success('Watch rule removed')
    await fetchStatus()
  } catch (err) {
    ElMessage.error(err.response?.data?.detail || 'Failed to remove watch rule')
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────
function alertTypeClass(type) {
  if (type === 'threshold_exceeded') return 'at-threshold'
  if (type === 'dns_anomaly') return 'at-dns'
  if (type === 'tls_anomaly') return 'at-tls'
  if (type === 'new_connection') return 'at-new'
  return ''
}

function formatDate(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleString()
}

function formatBytes(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function formatDuration(ms) {
  if (!ms) return '—'
  if (ms < 1000) return `${ms}ms`
  const s = (ms / 1000).toFixed(1)
  if (s < 60) return `${s}s`
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`
}

// ── Lifecycle ────────────────────────────────────────────────────────────────
onMounted(() => {
  fetchStatus()
  fetchAlerts()
  fetchFlows()
  // Fast refresh: status + flows every 5s
  fastTimer = setInterval(() => {
    fetchStatus()
    fetchFlows()
  }, 5000)
  // Slow refresh: alerts every 10s
  slowTimer = setInterval(fetchAlerts, 10000)
})

onUnmounted(() => {
  if (fastTimer) clearInterval(fastTimer)
  if (slowTimer) clearInterval(slowTimer)
})
</script>

<style scoped>
.packet-engine {
  max-width: 1200px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 24px;
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
}

.pe-card {
  border-radius: 12px;
  border: 1px solid #e4e7ed;
  margin-bottom: 18px;
}
.card-title {
  font-size: 15px;
  font-weight: 600;
  color: #303133;
}
.card-header-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.mono {
  font-family: 'SF Mono', 'Menlo', monospace;
  font-size: 12px;
}
.empty-hint {
  font-size: 13px;
  color: #909399;
  padding: 12px 0;
  text-align: center;
}

/* ── Status dot ───────────────────────────────────────────────────────── */
.status-dot-wrap {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 13px;
  color: #606266;
}
.status-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.dot-on  { background: #67c23a; }
.dot-off { background: #c0c4cc; }

/* ── Status grid ──────────────────────────────────────────────────────── */
.status-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
}
.sg-item {
  text-align: center;
  padding: 16px 8px;
  background: #f5f7fa;
  border-radius: 10px;
}
.sg-value {
  font-size: 24px;
  font-weight: 700;
  color: #303133;
}
.sg-label {
  font-size: 12px;
  color: #909399;
  margin-top: 4px;
}

/* ── Add form ─────────────────────────────────────────────────────────── */
.add-form {
  margin-bottom: 16px;
  padding: 14px;
  background: #f5f7fa;
  border-radius: 10px;
}
.form-row {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
}

/* ── Alert type badges ────────────────────────────────────────────────── */
.alert-type-badge {
  font-size: 11px;
  font-weight: 600;
  padding: 3px 8px;
  border-radius: 8px;
  text-transform: capitalize;
}
.at-threshold { background: #fde2e2; color: #f56c6c; }
.at-dns       { background: #faecd8; color: #e6a23c; }
.at-tls       { background: #ede9fe; color: #7c3aed; }
.at-new       { background: #dbeafe; color: #2563eb; }

/* ── State badge ──────────────────────────────────────────────────────── */
.state-badge {
  font-size: 11px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 8px;
  text-transform: capitalize;
}
.state-active,
.state-allow    { background: #e1f3d8; color: #67c23a; }
.state-reset    { background: #fde2e2; color: #f56c6c; }
.state-fin_closed,
.state-closed   { background: #ebeef5; color: #909399; }
.state-deny,
.state-drop     { background: #fde2e2; color: #f56c6c; }

@media (max-width: 768px) {
  .status-grid { grid-template-columns: repeat(2, 1fr); }
  .form-row { flex-direction: column; align-items: stretch; }
}
</style>
