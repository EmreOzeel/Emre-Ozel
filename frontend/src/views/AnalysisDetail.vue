<template>
  <div class="analysis-detail" v-loading="loading">
    <!-- Header -->
    <div class="page-header">
      <div class="header-left">
        <el-button link @click="$router.back()">
          <el-icon><ArrowLeft /></el-icon>
          Back
        </el-button>
        <div class="title-block">
          <h2>{{ analysisData?.filename || 'Analysis' }}</h2>
          <span class="meta">{{ formatDate(analysisData?.created_at) }} · {{ formatSize(analysisData?.file_size) }}</span>
        </div>
      </div>
      <el-tag :type="overallStatus.type" size="large" effect="dark" round>
        {{ overallStatus.label }}
      </el-tag>
    </div>

    <template v-if="result">
      <!-- Summary Stats -->
      <div class="stats-grid">
        <el-card class="stat-card" shadow="never">
          <div class="stat-value">{{ result.summary.total_packets.toLocaleString() }}</div>
          <div class="stat-label">Total Packets</div>
        </el-card>
        <el-card class="stat-card" shadow="never">
          <div class="stat-value">{{ formatSize(result.summary.total_bytes) }}</div>
          <div class="stat-label">Total Data</div>
        </el-card>
        <el-card class="stat-card" shadow="never">
          <div class="stat-value">{{ result.summary.unique_ips }}</div>
          <div class="stat-label">Unique IPs</div>
        </el-card>
        <el-card class="stat-card" shadow="never">
          <div class="stat-value">{{ formatDuration(result.summary.duration_sec) }}</div>
          <div class="stat-label">Capture Duration</div>
        </el-card>
        <el-card class="stat-card critical" shadow="never">
          <div class="stat-value" style="color: #F56C6C">{{ result.summary.critical_count }}</div>
          <div class="stat-label">Critical Issues</div>
        </el-card>
        <el-card class="stat-card warning" shadow="never">
          <div class="stat-value" style="color: #E6A23C">{{ result.summary.warning_count }}</div>
          <div class="stat-label">Warnings</div>
        </el-card>
      </div>

      <!-- Protocol Distribution + Top Talkers -->
      <div class="info-row">
        <!-- Protocols -->
        <el-card class="info-card" shadow="never">
          <template #header>
            <span class="card-title">Protocol Distribution</span>
          </template>
          <div class="protocol-list">
            <div v-for="(count, proto) in result.summary.protocols" :key="proto" class="protocol-item">
              <span class="proto-name">{{ proto }}</span>
              <div class="proto-bar-wrap">
                <div
                  class="proto-bar"
                  :style="{ width: getProtoPercent(count) + '%', background: protoColor(proto) }"
                />
              </div>
              <span class="proto-count">{{ count.toLocaleString() }}</span>
            </div>
          </div>
        </el-card>

        <!-- Top Talkers -->
        <el-card class="info-card" shadow="never" v-if="result.summary.top_talkers?.length">
          <template #header>
            <span class="card-title">Top Talkers (by bytes)</span>
          </template>
          <div class="talker-list">
            <div v-for="(t, i) in result.summary.top_talkers" :key="i" class="talker-item">
              <div class="talker-rank">{{ i + 1 }}</div>
              <div class="talker-ip">{{ t.ip }}</div>
              <div class="talker-bytes">{{ formatSize(t.bytes) }}</div>
            </div>
          </div>
        </el-card>
      </div>

      <!-- Tabs: Findings / TCP Connections -->
      <el-card class="findings-card" shadow="never">
        <el-tabs v-model="activeTab">

          <!-- ── FINDINGS TAB ── -->
          <el-tab-pane name="findings">
            <template #label>
              <span>Findings <el-badge :value="filteredFindings.length" style="margin-left:4px" /></span>
            </template>
            <div class="tab-toolbar">
              <el-select v-model="filterSeverity" placeholder="Severity" clearable size="small" style="width: 130px">
                <el-option label="Critical" value="critical"><el-tag type="danger" size="small">Critical</el-tag></el-option>
                <el-option label="Warning" value="warning"><el-tag type="warning" size="small">Warning</el-tag></el-option>
                <el-option label="Info" value="info"><el-tag type="info" size="small">Info</el-tag></el-option>
              </el-select>
              <el-select v-model="filterCategory" placeholder="Category" clearable size="small" style="width: 130px">
                <el-option label="TCP/IP" value="tcp" />
                <el-option label="Security" value="security" />
                <el-option label="DNS" value="dns" />
                <el-option label="HTTP" value="http" />
              </el-select>
            </div>

            <!-- No findings -->
            <el-empty v-if="filteredFindings.length === 0" description="No findings match the current filter" :image-size="80" />

            <!-- Timeline view -->
            <el-timeline v-else>
          <el-timeline-item
            v-for="finding in filteredFindings"
            :key="finding.id"
            :type="timelineType(finding.severity)"
            :timestamp="categoryLabel(finding.category)"
            placement="top"
            size="large"
          >
            <el-card
              class="finding-card"
              :class="'finding-' + finding.severity"
              shadow="never"
            >
              <div class="finding-header">
                <div class="finding-title-row">
                  <el-tag
                    :type="severityTagType(finding.severity)"
                    size="small"
                    effect="dark"
                    class="severity-tag"
                  >
                    {{ finding.severity.toUpperCase() }}
                  </el-tag>
                  <el-tag
                    :type="categoryTagType(finding.category)"
                    size="small"
                    effect="light"
                  >
                    {{ categoryLabel(finding.category) }}
                  </el-tag>
                  <span class="finding-title">{{ finding.title }}</span>
                </div>
              </div>

              <p class="finding-description">{{ finding.description }}</p>

              <!-- IPs / Ports -->
              <div class="finding-network" v-if="finding.src_ip || finding.dst_ip">
                <span v-if="finding.src_ip">
                  <el-icon><TopRight /></el-icon>
                  <strong>Src:</strong> {{ finding.src_ip }}{{ finding.src_port ? ':' + finding.src_port : '' }}
                </span>
                <span v-if="finding.dst_ip" style="margin-left: 16px">
                  <el-icon><BottomRight /></el-icon>
                  <strong>Dst:</strong> {{ finding.dst_ip }}{{ finding.dst_port ? ':' + finding.dst_port : '' }}
                </span>
                <span v-if="finding.packet_count" style="margin-left: 16px">
                  <el-icon><Files /></el-icon>
                  {{ finding.packet_count.toLocaleString() }} packets
                </span>
              </div>

              <!-- Details (collapsible) -->
              <el-collapse v-if="finding.details && Object.keys(finding.details).length > 0" style="margin-top: 12px">
                <el-collapse-item title="View Technical Details" name="details">
                  <div class="details-grid">
                    <div v-for="(val, key) in finding.details" :key="key" class="detail-item">
                      <span class="detail-key">{{ formatKey(key) }}</span>
                      <span class="detail-val">{{ formatVal(val) }}</span>
                    </div>
                  </div>
                </el-collapse-item>
              </el-collapse>
            </el-card>
          </el-timeline-item>
            </el-timeline>
          </el-tab-pane>

          <!-- ── TCP CONNECTIONS TAB ── -->
          <el-tab-pane name="connections">
            <template #label>
              <span>TCP Connections <el-badge :value="result.connections?.length || 0" style="margin-left:4px" /></span>
            </template>

            <el-empty v-if="!result.connections?.length" description="No TCP connections captured" :image-size="80" />

            <template v-else>
              <!-- Search box -->
              <div class="tab-toolbar">
                <el-input v-model="connSearch" placeholder="Filter by IP or port…" :prefix-icon="Search" clearable size="small" style="max-width:300px" />
                <el-select v-model="connStateFilter" placeholder="State" clearable size="small" style="width:160px">
                  <el-option label="Established" value="established" />
                  <el-option label="FIN Closed" value="fin-closed" />
                  <el-option label="Reset" value="reset" />
                  <el-option label="Half-Open" value="half-open" />
                  <el-option label="Mid-Stream" value="mid-stream" />
                </el-select>
              </div>

              <!-- Connections table with expand -->
              <el-table
                :data="filteredConnections"
                row-key="id"
                style="width:100%"
                @expand-change="onExpandChange"
              >
                <el-table-column type="expand">
                  <template #default="{ row }">
                    <div class="conn-flow-wrap">
                      <div class="conn-flow-header">
                        <span class="conn-flow-title">
                          <el-icon><Connection /></el-icon>
                          {{ row.client_ip }}:{{ row.client_port }}
                          <span class="arrow">⟶</span>
                          {{ row.server_ip }}:{{ row.server_port }}
                        </span>
                        <span class="conn-flow-meta">
                          {{ row.packet_count }} packets ·
                          ↑ {{ formatSize(row.bytes_client) }} ·
                          ↓ {{ formatSize(row.bytes_server) }}
                        </span>
                      </div>

                      <!-- Step-by-step packet table -->
                      <table class="packet-table">
                        <thead>
                          <tr>
                            <th>#</th>
                            <th>Time (s)</th>
                            <th>Dir</th>
                            <th>Flags</th>
                            <th>Seq</th>
                            <th>Ack</th>
                            <th>Len</th>
                            <th>Description</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr
                            v-for="(step, idx) in row.steps"
                            :key="idx"
                            :class="stepRowClass(step)"
                          >
                            <td class="pkt-num">{{ idx + 1 }}</td>
                            <td class="pkt-time">+{{ step.rel_time_sec.toFixed(4) }}s</td>
                            <td class="pkt-dir" :class="step.direction === '→' ? 'dir-fwd' : 'dir-rev'">
                              {{ step.direction }}
                            </td>
                            <td class="pkt-flags">
                              <span
                                v-for="flag in step.flags.split('+')"
                                :key="flag"
                                :class="'flag flag-' + flag.toLowerCase()"
                              >{{ flag }}</span>
                            </td>
                            <td class="pkt-seq">{{ step.seq_num }}</td>
                            <td class="pkt-ack">{{ step.ack_num }}</td>
                            <td class="pkt-len">{{ step.payload_len > 0 ? step.payload_len + 'B' : '—' }}</td>
                            <td class="pkt-desc">{{ step.description }}</td>
                          </tr>
                        </tbody>
                      </table>
                      <p v-if="row.packet_count > row.steps?.length" class="truncated-note">
                        ⚠ Showing first {{ row.steps?.length }} of {{ row.packet_count }} packets
                      </p>
                    </div>
                  </template>
                </el-table-column>

                <el-table-column label="#" prop="id" width="55" />

                <el-table-column label="Client" min-width="170">
                  <template #default="{ row }">
                    <span class="mono">{{ row.client_ip }}:{{ row.client_port }}</span>
                  </template>
                </el-table-column>

                <el-table-column label="Server" min-width="170">
                  <template #default="{ row }">
                    <span class="mono">{{ row.server_ip }}:{{ row.server_port }}</span>
                  </template>
                </el-table-column>

                <el-table-column label="State" width="130">
                  <template #default="{ row }">
                    <el-tag :type="stateTagType(row.state)" size="small" effect="light">
                      {{ stateLabel(row.state) }}
                    </el-tag>
                  </template>
                </el-table-column>

                <el-table-column label="Duration" width="100">
                  <template #default="{ row }">
                    {{ formatDuration(row.duration_sec) }}
                  </template>
                </el-table-column>

                <el-table-column label="Packets" prop="packet_count" width="90" />

                <el-table-column label="↑ Client" width="100">
                  <template #default="{ row }">{{ formatSize(row.bytes_client) }}</template>
                </el-table-column>

                <el-table-column label="↓ Server" width="100">
                  <template #default="{ row }">{{ formatSize(row.bytes_server) }}</template>
                </el-table-column>
              </el-table>
            </template>
          </el-tab-pane>

        </el-tabs>
      </el-card>
    </template>

    <el-empty v-else-if="!loading" description="No analysis data available" />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { Search } from '@element-plus/icons-vue'
import api from '../api'

const route = useRoute()

const loading = ref(true)
const analysisData = ref(null)
const result = ref(null)
const filterSeverity = ref('')
const filterCategory = ref('')
const activeTab = ref('findings')
const connSearch = ref('')
const connStateFilter = ref('')

onMounted(async () => {
  try {
    const res = await api.get(`/analyses/${route.params.id}`)
    analysisData.value = res.data
    result.value = res.data.result
  } catch {
    // handled by interceptor
  } finally {
    loading.value = false
  }
})

const filteredFindings = computed(() => {
  if (!result.value?.findings) return []
  return result.value.findings.filter(f => {
    if (filterSeverity.value && f.severity !== filterSeverity.value) return false
    if (filterCategory.value && f.category !== filterCategory.value) return false
    return true
  })
})

const filteredConnections = computed(() => {
  if (!result.value?.connections) return []
  return result.value.connections.filter(c => {
    if (connStateFilter.value && c.state !== connStateFilter.value) return false
    if (connSearch.value) {
      const q = connSearch.value.toLowerCase()
      const haystack = `${c.client_ip} ${c.server_ip} ${c.client_port} ${c.server_port}`.toLowerCase()
      if (!haystack.includes(q)) return false
    }
    return true
  })
})

const overallStatus = computed(() => {
  if (!result.value) return { type: 'info', label: 'Pending' }
  const s = result.value.summary
  if (s.critical_count > 0) return { type: 'danger', label: 'Critical Issues Found' }
  if (s.warning_count > 0) return { type: 'warning', label: 'Warnings Found' }
  return { type: 'success', label: 'All Clear' }
})

const maxProtoCount = computed(() => {
  if (!result.value?.summary?.protocols) return 1
  return Math.max(...Object.values(result.value.summary.protocols))
})

function getProtoPercent(count) {
  return Math.round((count / maxProtoCount.value) * 100)
}

function protoColor(proto) {
  const colors = {
    TCP: '#409EFF', UDP: '#67C23A', IPv4: '#E6A23C',
    IPv6: '#9b59b6', HTTP: '#F56C6C', TLS: '#00cec9',
    DNS: '#fd79a8', ARP: '#fdcb6e', ICMP: '#e17055'
  }
  return colors[proto] || '#909399'
}

function severityTagType(severity) {
  return { critical: 'danger', warning: 'warning', info: 'info' }[severity] || 'info'
}

function categoryTagType(category) {
  return { tcp: 'primary', security: 'danger', dns: 'success', http: 'warning' }[category] || ''
}

function categoryLabel(category) {
  return { tcp: 'TCP/IP', security: 'Security', dns: 'DNS', http: 'HTTP' }[category] || category
}

function timelineType(severity) {
  return { critical: 'danger', warning: 'warning', info: 'primary' }[severity] || 'primary'
}

// TCP Connection helpers
function stateTagType(state) {
  return { established: 'success', 'fin-closed': 'info', reset: 'danger', 'half-open': 'warning', 'syn-ack-sent': 'warning', 'mid-stream': '' }[state] || ''
}

function stateLabel(state) {
  return { established: 'Established', 'fin-closed': 'FIN Closed', reset: 'Reset (RST)', 'half-open': 'Half-Open', 'syn-ack-sent': 'SYN-ACK Sent', 'mid-stream': 'Mid-Stream', unknown: 'Unknown' }[state] || state
}

function stepRowClass(step) {
  if (step.flags.includes('RST')) return 'row-rst'
  if (step.flags.includes('FIN')) return 'row-fin'
  if (step.flags === 'SYN') return 'row-syn'
  if (step.flags === 'SYN+ACK') return 'row-synack'
  if (step.payload_len > 0) return 'row-data'
  return ''
}

function onExpandChange() {}


function formatKey(key) {
  return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function formatVal(val) {
  if (Array.isArray(val)) return val.join(', ')
  if (typeof val === 'object' && val !== null) return JSON.stringify(val, null, 2)
  return String(val)
}

function formatDate(dateStr) {
  if (!dateStr) return ''
  return new Date(dateStr).toLocaleString()
}

function formatSize(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function formatDuration(sec) {
  if (!sec || sec < 1) return '<1s'
  if (sec < 60) return `${sec.toFixed(1)}s`
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${Math.floor(sec % 60)}s`
  return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`
}
</script>

<style scoped>
.analysis-detail {
  max-width: 1000px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 24px;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 16px;
}

.title-block h2 {
  font-size: 20px;
  font-weight: 700;
  color: #1a1a2e;
  margin-bottom: 2px;
}

.title-block .meta {
  font-size: 13px;
  color: #909399;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 12px;
  margin-bottom: 20px;
}

.stat-card {
  border-radius: 12px;
  border: 1px solid #e4e7ed;
  text-align: center;
}

.stat-card :deep(.el-card__body) {
  padding: 16px 12px;
}

.stat-value {
  font-size: 22px;
  font-weight: 700;
  color: #303133;
  margin-bottom: 4px;
}

.stat-label {
  font-size: 12px;
  color: #909399;
}

.info-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-bottom: 20px;
}

.info-card {
  border-radius: 12px;
  border: 1px solid #e4e7ed;
}

.card-title {
  font-size: 15px;
  font-weight: 600;
  color: #303133;
}

.protocol-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.protocol-item {
  display: flex;
  align-items: center;
  gap: 10px;
}

.proto-name {
  font-size: 13px;
  font-weight: 500;
  color: #303133;
  width: 50px;
  flex-shrink: 0;
}

.proto-bar-wrap {
  flex: 1;
  height: 8px;
  background: #f0f2f5;
  border-radius: 4px;
  overflow: hidden;
}

.proto-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 0.5s ease;
}

.proto-count {
  font-size: 12px;
  color: #909399;
  width: 60px;
  text-align: right;
}

.talker-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.talker-item {
  display: flex;
  align-items: center;
  gap: 12px;
}

.talker-rank {
  width: 24px;
  height: 24px;
  border-radius: 50%;
  background: #f0f2f5;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 600;
  color: #606266;
  flex-shrink: 0;
}

.talker-ip {
  flex: 1;
  font-size: 13px;
  font-family: monospace;
  color: #303133;
}

.talker-bytes {
  font-size: 13px;
  color: #606266;
}

.findings-card {
  border-radius: 12px;
  border: 1px solid #e4e7ed;
}

.findings-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
}

.filter-row {
  display: flex;
  gap: 8px;
}

.badge {
  margin-left: 8px;
}

.finding-card {
  border-radius: 10px;
  border: 1px solid #e4e7ed;
  margin-bottom: 4px;
}

.finding-card.finding-critical {
  border-left: 4px solid #F56C6C;
  background: #fffafa;
}

.finding-card.finding-warning {
  border-left: 4px solid #E6A23C;
  background: #fffbf0;
}

.finding-card.finding-info {
  border-left: 4px solid #409EFF;
  background: #f8fbff;
}

.finding-header {
  margin-bottom: 10px;
}

.finding-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.finding-title {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
}

.finding-description {
  font-size: 13px;
  color: #606266;
  line-height: 1.6;
}

.finding-network {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 10px;
  padding: 8px 12px;
  background: #f5f7fa;
  border-radius: 6px;
  font-size: 12px;
  color: #606266;
  font-family: monospace;
}

.finding-network .el-icon {
  vertical-align: middle;
  margin-right: 4px;
}

.details-grid {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.detail-item {
  display: flex;
  gap: 12px;
  font-size: 12px;
  padding: 4px 0;
  border-bottom: 1px solid #f0f2f5;
}

.detail-key {
  font-weight: 600;
  color: #606266;
  min-width: 150px;
  flex-shrink: 0;
}

.detail-val {
  color: #303133;
  font-family: monospace;
  word-break: break-all;
  white-space: pre-wrap;
}

/* ── Tabs toolbar ── */
.tab-toolbar {
  display: flex;
  gap: 10px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}

/* ── Connection flow expand area ── */
.conn-flow-wrap {
  padding: 0 16px 16px;
}

.conn-flow-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 0 10px;
  border-bottom: 1px solid #e4e7ed;
  margin-bottom: 12px;
}

.conn-flow-title {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
  font-family: monospace;
  display: flex;
  align-items: center;
  gap: 8px;
}

.conn-flow-title .arrow {
  color: #409EFF;
  font-size: 18px;
}

.conn-flow-meta {
  font-size: 12px;
  color: #909399;
}

/* ── Packet table ── */
.packet-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  font-family: monospace;
}

.packet-table th {
  background: #f5f7fa;
  color: #606266;
  font-weight: 600;
  padding: 6px 10px;
  text-align: left;
  border-bottom: 2px solid #e4e7ed;
  white-space: nowrap;
}

.packet-table td {
  padding: 5px 10px;
  border-bottom: 1px solid #f0f2f5;
  vertical-align: middle;
}

.packet-table tr:hover td {
  background: #fafafa;
}

/* Row color coding */
.row-syn td { background: #f0f9eb; }
.row-synack td { background: #ecf5ff; }
.row-fin td { background: #fdf6ec; }
.row-rst td { background: #fef0f0; }
.row-data td { background: #fafafa; }

.pkt-num { color: #909399; width: 30px; }
.pkt-time { color: #67C23A; width: 90px; white-space: nowrap; }
.pkt-seq, .pkt-ack { color: #909399; width: 90px; }
.pkt-len { color: #E6A23C; width: 55px; text-align: right; }
.pkt-desc { color: #303133; }

.pkt-dir { font-size: 16px; font-weight: 700; width: 30px; text-align: center; }
.dir-fwd { color: #409EFF; }
.dir-rev { color: #67C23A; }

/* Flag badges */
.flag {
  display: inline-block;
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 700;
  margin-right: 2px;
}
.flag-syn  { background: #e1f3d8; color: #529b2e; }
.flag-ack  { background: #ecf5ff; color: #409eff; }
.flag-fin  { background: #fdf6ec; color: #b88230; }
.flag-rst  { background: #fef0f0; color: #f56c6c; }
.flag-psh  { background: #f4f4f5; color: #909399; }
.flag-urg  { background: #fff0f0; color: #f56c6c; }

.mono { font-family: monospace; font-size: 13px; }

.truncated-note {
  font-size: 12px;
  color: #E6A23C;
  margin-top: 8px;
  padding: 6px 10px;
  background: #fdf6ec;
  border-radius: 4px;
}
</style>
