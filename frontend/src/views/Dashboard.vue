<template>
  <div class="dashboard">
    <div class="page-header">
      <div>
        <h2>Dashboard</h2>
        <p>Upload a PCAP file to analyze your network traffic</p>
      </div>
      <div class="last-updated" v-if="lastUpdatedAt">
        <span :class="{ stale: secondsAgo > 20 }">
          Updated {{ secondsAgo < 2 ? 'just now' : `${secondsAgo}s ago` }}
        </span>
      </div>
    </div>

    <!-- Stale warning bar -->
    <div class="stale-bar" v-if="fetchError && !staleDismissed">
      <el-icon><Warning /></el-icon>
      Dashboard data may be stale
      <span v-if="lastUpdatedAt" class="stale-time">
        · last successful fetch {{ formatDate(lastUpdatedAt.toISOString()) }}
      </span>
      <el-button size="small" link @click="staleDismissed = true">Dismiss</el-button>
    </div>

    <!-- ══ Section 1 — Live Network Status bar ══════════════════════════ -->
    <template v-if="loaded">
      <div class="live-status-bar">
        <div class="ls-item">
          <span
            class="collector-dot"
            :class="summary.collector?.running ? 'dot-on' : 'dot-off'"
          ></span>
          <span>{{ summary.collector?.running ? 'Collecting' : 'Offline' }}</span>
        </div>
        <div class="ls-item">
          <strong>{{ (summary.live_events?.total_last_5min || 0).toLocaleString() }}</strong>
          <span>events (5 min)</span>
        </div>
        <div class="ls-item ls-threats">
          <strong>{{ ((summary.live_events?.deny_last_5min || 0) + (summary.live_events?.drop_last_5min || 0)).toLocaleString() }}</strong>
          <span>deny/drop</span>
        </div>
        <div class="ls-item" v-if="summary.live_events?.top_risk_ip">
          <span class="risk-ip-badge" :class="`risk-${topRiskLevel}`">
            {{ summary.live_events.top_risk_ip }}
          </span>
          <span>top risk</span>
        </div>
        <div class="ls-item ls-ti" v-if="tiMatchCount > 0" @click="$router.push('/threat-intel')">
          <strong>{{ tiMatchCount }}</strong>
          <span>TI matches</span>
        </div>
        <div class="ls-item" v-if="topSourceCountry">
          <span>{{ topSourceCountry.flag }} {{ topSourceCountry.code }}</span>
          <span>top source</span>
        </div>
        <div class="ls-item ls-capture" v-if="activeCaptures > 0">
          <strong>{{ activeCaptures }}</strong>
          <span>active captures</span>
        </div>
        <div class="ls-spacer"></div>
        <el-button size="small" type="primary" link @click="$router.push('/live-events')">
          View all <el-icon class="el-icon--right"><ArrowRight /></el-icon>
        </el-button>
      </div>
    </template>
    <div v-else class="skeleton-bar pulse"></div>

    <!-- ══ Two-column layout ═══════════════════════════════════════════ -->
    <div class="dash-columns">
      <!-- Left column: existing content -->
      <div class="dash-left">
        <!-- Upload Area -->
        <el-card class="upload-card" shadow="never">
          <div
            class="upload-zone"
            :class="{ 'dragging': isDragging, 'uploading': uploading }"
            @dragover.prevent="isDragging = true"
            @dragleave.prevent="isDragging = false"
            @drop.prevent="handleDrop"
            @click="triggerFileInput"
          >
            <input
              ref="fileInput"
              type="file"
              accept=".pcap,.pcapng,.cap"
              style="display: none"
              @change="handleFileSelect"
            />
            <template v-if="!uploading">
              <div class="upload-icon">
                <el-icon size="56" color="#409EFF"><Upload /></el-icon>
              </div>
              <h3>Drop PCAP file here or click to upload</h3>
              <p class="upload-hint">Supports <strong>.pcap</strong>, <strong>.pcapng</strong>, <strong>.cap</strong> files</p>
            </template>
            <template v-else>
              <div class="upload-progress">
                <el-icon size="48" color="#409EFF" class="spinning"><Loading /></el-icon>
                <h3>Analyzing {{ uploadingFilename }}...</h3>
                <p>Running TCP, Security, DNS & HTTP analysis</p>
                <el-progress
                  :percentage="uploadProgress"
                  :stroke-width="6"
                  style="width: 300px; margin-top: 16px"
                />
              </div>
            </template>
          </div>
        </el-card>

        <!-- Analysis Steps Info -->
        <el-card class="steps-card" shadow="never">
          <template #header>
            <span class="card-title">What gets analyzed?</span>
          </template>
          <div class="analysis-steps">
            <div class="step-item">
              <div class="step-icon" style="background: #ecf5ff; color: #409EFF">
                <el-icon size="24"><Connection /></el-icon>
              </div>
              <div class="step-info">
                <h4>TCP/IP Analysis</h4>
                <p>Retransmissions, SYN floods, RST packets, incomplete handshakes</p>
              </div>
            </div>
            <div class="step-item">
              <div class="step-icon" style="background: #fef0f0; color: #F56C6C">
                <el-icon size="24"><Shield /></el-icon>
              </div>
              <div class="step-info">
                <h4>Security Threats</h4>
                <p>Port scans, ARP spoofing, ICMP floods, TCP null/xmas scans, data exfiltration</p>
              </div>
            </div>
            <div class="step-item">
              <div class="step-icon" style="background: #f0f9eb; color: #67C23A">
                <el-icon size="24"><Promotion /></el-icon>
              </div>
              <div class="step-info">
                <h4>DNS Analysis</h4>
                <p>NXDOMAIN responses, DNS tunneling, high query rates, slow responses</p>
              </div>
            </div>
            <div class="step-item">
              <div class="step-icon" style="background: #fdf6ec; color: #E6A23C">
                <el-icon size="24"><Monitor /></el-icon>
              </div>
              <div class="step-info">
                <h4>HTTP/HTTPS Analysis</h4>
                <p>Error codes, cleartext credentials, unencrypted traffic, suspicious user agents</p>
              </div>
            </div>
          </div>
        </el-card>

        <!-- Recent Analyses -->
        <el-card class="recent-card" shadow="never" v-if="recentAnalyses.length > 0">
          <template #header>
            <div class="card-header-row">
              <span class="card-title">Recent Analyses</span>
              <el-button link type="primary" @click="$router.push('/history')">
                View All <el-icon class="el-icon--right"><ArrowRight /></el-icon>
              </el-button>
            </div>
          </template>
          <div class="recent-list">
            <div
              v-for="item in recentAnalyses"
              :key="item.id"
              class="recent-item"
              @click="$router.push(`/analysis/${item.id}`)"
            >
              <div class="recent-icon">
                <el-icon size="20" color="#409EFF"><Document /></el-icon>
              </div>
              <div class="recent-info">
                <div class="recent-name">{{ item.filename }}</div>
                <div class="recent-meta">{{ formatDate(item.created_at) }} · {{ formatSize(item.file_size) }}</div>
              </div>
              <div class="recent-badges">
                <el-tag v-if="item.critical_count > 0" type="danger" size="small" effect="light">
                  {{ item.critical_count }} Critical
                </el-tag>
                <el-tag v-if="item.warning_count > 0" type="warning" size="small" effect="light">
                  {{ item.warning_count }} Warning
                </el-tag>
                <el-tag v-if="item.critical_count === 0 && item.warning_count === 0" type="success" size="small" effect="light">
                  Clean
                </el-tag>
              </div>
              <el-icon color="#c0c4cc"><ArrowRight /></el-icon>
            </div>
          </div>
        </el-card>
      </div>

      <!-- Right column: live intelligence -->
      <div class="dash-right">
        <!-- ══ Section 2 — Top Risk IPs ════════════════════════════════ -->
        <template v-if="loaded">
          <el-card class="intel-card" shadow="never">
            <template #header>
              <div class="card-header-row">
                <span class="card-title">Top Risk IPs</span>
                <el-button
                  link type="primary" size="small"
                  @click="$router.push('/live-events')"
                >View all</el-button>
              </div>
            </template>
            <div v-if="summary.risk_scores?.length" class="risk-list">
              <div
                v-for="r in summary.risk_scores"
                :key="r.source_ip"
                class="risk-row clickable"
                @click="$router.push(`/live-events?source_ip=${r.source_ip}`)"
              >
                <span class="mono risk-ip">{{ r.source_ip }}</span>
                <span
                  class="risk-badge"
                  :class="[`risk-${r.risk_level}`, { flash: changedScores.has(r.source_ip) }]"
                >{{ r.risk_score }}</span>
                <span class="risk-driver">{{ (r.drivers?.[0] || '').replace(/_/g, ' ') }}</span>
                <span class="risk-count">{{ r.event_count }}</span>
              </div>
            </div>
            <div v-else class="empty-hint">No elevated risk detected</div>
          </el-card>
        </template>
        <div v-else class="skeleton-card pulse"></div>

        <!-- ══ Section 3 — Recent Auto-Detections ══════════════════════ -->
        <template v-if="loaded">
          <el-card class="intel-card" shadow="never">
            <template #header>
              <span class="card-title">Recent Auto-Detections</span>
            </template>
            <TransitionGroup name="slide" tag="div" class="auto-list" v-if="summary.auto_detections?.length">
              <div
                v-for="d in summary.auto_detections"
                :key="d.id"
                class="auto-row clickable"
                @click="d.analysis_id && $router.push(`/analysis/${d.analysis_id}`)"
              >
                <span class="auto-time">{{ timeAgo(d.created_at) }}</span>
                <span class="auto-msg">{{ (d.message || '').replace('[AUTO] ', '') }}</span>
              </div>
            </TransitionGroup>
            <div v-else class="empty-hint">No auto-detections yet</div>
          </el-card>
        </template>
        <div v-else class="skeleton-card skeleton-sm pulse"></div>

        <!-- ══ Section 3b — Active Incidents ═══════════════════════════ -->
        <el-card class="intel-card" shadow="never">
          <template #header>
            <div class="card-header-row">
              <span class="card-title">Active Incidents</span>
              <el-button link type="primary" size="small" @click="$router.push('/live-incidents')">
                View all
              </el-button>
            </div>
          </template>
          <template v-if="incidents.length">
            <div class="incident-counts">
              <span class="ic-total">{{ incidents.length }}</span>
              <span class="ic-badge ic-critical" v-if="incidentCounts.critical">{{ incidentCounts.critical }} critical</span>
              <span class="ic-badge ic-high" v-if="incidentCounts.high">{{ incidentCounts.high }} high</span>
              <span class="ic-badge ic-medium" v-if="incidentCounts.medium">{{ incidentCounts.medium }} medium</span>
            </div>
            <div class="incident-list">
              <div
                v-for="inc in incidents.slice(0, 3)"
                :key="inc.id"
                class="incident-row"
              >
                <span class="sev-badge" :class="`sev-${inc.severity}`">{{ inc.severity }}</span>
                <span class="inc-type">{{ inc.behavior_type.replace(/_/g, ' ') }}</span>
                <span class="mono inc-ip">{{ inc.source_ip }}</span>
                <span class="inc-count">{{ inc.event_count }}×</span>
                <span class="inc-time">{{ timeAgo(inc.last_seen) }}</span>
              </div>
            </div>
          </template>
          <div v-else class="empty-hint">No active incidents</div>
        </el-card>

        <!-- ══ Section 4 — Collector Health (collapsed) ════════════════ -->
        <el-card class="intel-card collector-card" shadow="never">
          <template #header>
            <div
              class="card-header-row clickable"
              @click="collectorExpanded = !collectorExpanded"
            >
              <span class="card-title">Collector Health</span>
              <el-icon :class="{ rotated: collectorExpanded }"><ArrowDown /></el-icon>
            </div>
          </template>
          <div v-show="collectorExpanded" class="collector-body">
            <template v-if="summary.collector">
              <div class="coll-row">
                <span class="coll-label">Status</span>
                <span>
                  <span
                    class="collector-dot"
                    :class="summary.collector.running ? 'dot-on' : 'dot-off'"
                  ></span>
                  {{ summary.collector.running ? 'Running' : 'Stopped' }}
                </span>
              </div>
              <div class="coll-row">
                <span class="coll-label">Syslog port</span>
                <span class="mono">{{ summary.collector.syslog_port }}</span>
              </div>
              <div class="coll-row">
                <span class="coll-label">Source ID</span>
                <span class="mono">{{ summary.collector.source_id || '—' }}</span>
              </div>
              <template v-if="summary.collector.pipeline_stats">
                <div class="coll-row" v-for="(v, k) in summary.collector.pipeline_stats" :key="k">
                  <span class="coll-label">{{ k }}</span>
                  <span class="mono">{{ v?.toLocaleString?.() ?? v }}</span>
                </div>
              </template>
              <div class="coll-row">
                <span class="coll-label">Buffer size</span>
                <span class="mono">{{ summary.collector.buffer_size }}</span>
              </div>
              <div class="coll-row" v-if="summary.collector.netflow_packets_received != null">
                <span class="coll-label">NetFlow packets</span>
                <span class="mono">{{ summary.collector.netflow_packets_received }}</span>
              </div>
              <div class="coll-row" v-if="baselineCount != null">
                <span class="coll-label">Baselines</span>
                <span class="mono">{{ baselineCount }} IP(s) profiled</span>
              </div>
            </template>
            <div v-else class="empty-hint">Loading…</div>
          </div>
        </el-card>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { ArrowDown, Warning } from '@element-plus/icons-vue'
import api from '../api'
import { lookupThreatIP, fetchGeoBatchLookup, fetchPcapTriggerStatus } from '../api'
import { classifyAnalysisError } from '../utils/analysisErrors'

const router = useRouter()

// ── Existing state ──────────────────────────────────────────────────────────
const fileInput = ref()
const isDragging = ref(false)
const uploading = ref(false)
const uploadProgress = ref(0)
const uploadingFilename = ref('')
const recentAnalyses = ref([])

// ── Unified dashboard state ─────────────────────────────────────────────────
const summary = ref({})
const loaded = ref(false)           // first successful fetch
const fetchError = ref(false)
const staleDismissed = ref(false)
const lastUpdatedAt = ref(null)     // Date object
const secondsAgo = ref(0)
const incidents = ref([])
const collectorExpanded = ref(false)
const baselineCount = ref(null)
const tiMatchCount = ref(0)
const topSourceCountry = ref(null)
const activeCaptures = ref(0)

function _countryFlag(code) {
  if (!code) return ''
  return code.toUpperCase().replace(/./g, c => String.fromCodePoint(0x1F1E0 - 65 + c.charCodeAt(0)))
}

const incidentCounts = computed(() => {
  const c = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const inc of incidents.value) {
    c[inc.severity] = (c[inc.severity] || 0) + 1
  }
  return c
})

// Change tracking for flash animations
const prevScoreMap = ref(new Map())  // source_ip → risk_score
const changedScores = ref(new Set())
const prevDetectionIds = ref(new Set())

// Timers
let refreshTimer = null
let tickTimer = null
let retryTimer = null

const REFRESH_MS = 10_000
const TICK_MS = 1_000
const RETRY_MS = 30_000

const topRiskLevel = computed(() => {
  const s = summary.value.live_events?.top_risk_score
  if (s == null) return 'low'
  if (s >= 80) return 'critical'
  if (s >= 60) return 'high'
  if (s >= 30) return 'medium'
  return 'low'
})

async function _countTiMatches(riskScores) {
  let count = 0
  const checks = riskScores.slice(0, 20).map(async (r) => {
    try {
      const res = await lookupThreatIP(r.source_ip)
      if (res.data.is_threat) count++
    } catch {}
  })
  await Promise.all(checks)
  tiMatchCount.value = count

  // Fetch PCAP trigger active captures
  try {
    const trigRes = await fetchPcapTriggerStatus()
    activeCaptures.value = trigRes.data.active_captures || 0
  } catch { activeCaptures.value = 0 }

  // Compute top source country from risk scores
  const ips = riskScores.slice(0, 20).map(r => r.source_ip)
  if (ips.length) {
    try {
      const res = await fetchGeoBatchLookup(ips)
      const countryCounts = {}
      for (const geo of Object.values(res.data)) {
        const cc = geo?.country_code
        if (cc && !geo.is_private) countryCounts[cc] = (countryCounts[cc] || 0) + 1
      }
      const top = Object.entries(countryCounts).sort((a, b) => b[1] - a[1])[0]
      topSourceCountry.value = top ? { code: top[0], flag: _countryFlag(top[0]), count: top[1] } : null
    } catch {
      topSourceCountry.value = null
    }
  }
}

// ── Unified fetch ───────────────────────────────────────────────────────────
async function fetchDashboardSummary() {
  try {
    const res = await api.get('/dashboard/summary')
    const data = res.data

    // Detect changed risk scores for flash animation
    const newScoreMap = new Map()
    const changed = new Set()
    for (const r of data.risk_scores || []) {
      newScoreMap.set(r.source_ip, r.risk_score)
      const prev = prevScoreMap.value.get(r.source_ip)
      if (prev !== undefined && prev !== r.risk_score) {
        changed.add(r.source_ip)
      }
    }
    prevScoreMap.value = newScoreMap
    changedScores.value = changed
    if (changed.size) {
      setTimeout(() => { changedScores.value = new Set() }, 600)
    }

    // Detect new auto-detections for slide animation
    const newIds = new Set((data.auto_detections || []).map(d => d.id))
    prevDetectionIds.value = newIds

    summary.value = data
    loaded.value = true
    fetchError.value = false
    staleDismissed.value = false
    lastUpdatedAt.value = new Date()
    secondsAgo.value = 0

    // Count TI matches from risk score IPs
    _countTiMatches(data.risk_scores || [])

    // Clear retry timer on success
    if (retryTimer) { clearInterval(retryTimer); retryTimer = null }
  } catch {
    fetchError.value = true
    // Start retry timer if not already running
    if (!retryTimer) {
      retryTimer = setInterval(fetchDashboardSummary, RETRY_MS)
    }
  }
}

async function fetchRecent() {
  try {
    const res = await api.get('/analyses')
    recentAnalyses.value = res.data.slice(0, 5)
  } catch {}
}

async function fetchIncidents() {
  try {
    const [open, inv] = await Promise.all([
      api.get('/live-incidents', { params: { status: 'open', limit: 50 } }),
      api.get('/live-incidents', { params: { status: 'investigating', limit: 50 } }),
    ])
    const all = [...(open.data?.incidents || []), ...(inv.data?.incidents || [])]
    all.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen))
    incidents.value = all
  } catch {}
}

async function fetchBaselineCount() {
  try {
    const res = await api.get('/baselines')
    baselineCount.value = (res.data || []).length
  } catch {}
}

// ── Timer management ────────────────────────────────────────────────────────
function startTimers() {
  refreshTimer = setInterval(() => {
    fetchDashboardSummary()
    fetchRecent()
    fetchIncidents()
    fetchBaselineCount()
  }, REFRESH_MS)
  tickTimer = setInterval(() => {
    if (lastUpdatedAt.value) {
      secondsAgo.value = Math.floor((Date.now() - lastUpdatedAt.value.getTime()) / 1000)
    }
  }, TICK_MS)
}

function stopTimers() {
  if (refreshTimer)  { clearInterval(refreshTimer); refreshTimer = null }
  if (tickTimer)     { clearInterval(tickTimer); tickTimer = null }
  if (retryTimer)    { clearInterval(retryTimer); retryTimer = null }
}

// ── Optimistic refresh on analysis-created event ────────────────────────────
function onAnalysisCreated() {
  fetchDashboardSummary()
  fetchRecent()
}

// ── Lifecycle ───────────────────────────────────────────────────────────────
onMounted(() => {
  fetchDashboardSummary()
  fetchRecent()
  fetchIncidents()
  fetchBaselineCount()
  startTimers()
  window.addEventListener('analysis-created', onAnalysisCreated)
})

onUnmounted(() => {
  stopTimers()
  window.removeEventListener('analysis-created', onAnalysisCreated)
})

// ── Existing upload functions (unchanged) ───────────────────────────────────

function triggerFileInput() {
  if (!uploading.value) fileInput.value?.click()
}

function handleFileSelect(e) {
  const file = e.target.files?.[0]
  if (file) uploadFile(file)
  e.target.value = ''
}

function handleDrop(e) {
  isDragging.value = false
  const file = e.dataTransfer.files?.[0]
  if (file) uploadFile(file)
}

async function uploadFile(file) {
  const ext = file.name.split('.').pop().toLowerCase()
  if (!['pcap', 'pcapng', 'cap'].includes(ext)) {
    ElMessage.error('Only .pcap, .pcapng, .cap files are supported')
    return
  }
  uploading.value = true
  uploadingFilename.value = file.name
  uploadProgress.value = 5
  try {
    const formData = new FormData()
    formData.append('file', file)
    const res = await api.post('/analyses', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    const analysisId = res.data.id
    uploadProgress.value = 15
    let pollAttempts = 0
    const maxAttempts = 180
    await new Promise((resolve, reject) => {
      const poller = setInterval(async () => {
        pollAttempts++
        if (pollAttempts > maxAttempts) {
          clearInterval(poller)
          reject(new Error('Analysis timed out'))
          return
        }
        try {
          const statusRes = await api.get(`/analyses/${analysisId}/status`)
          const status = statusRes.data.status
          if (status === 'pending') {
            uploadProgress.value = Math.min(30, uploadProgress.value + 1)
          } else if (status === 'running') {
            uploadProgress.value = Math.min(92, uploadProgress.value + 0.8)
          } else if (status === 'completed') {
            clearInterval(poller)
            uploadProgress.value = 100
            resolve()
          } else if (status === 'failed') {
            clearInterval(poller)
            const info = classifyAnalysisError(statusRes.data.error)
            reject(new Error(`${info.title}: ${info.message} ${info.hint}`))
          }
        } catch {}
      }, 1000)
    })
    ElMessage.success('Analysis complete!')
    // Trigger optimistic refresh
    window.dispatchEvent(new Event('analysis-created'))
    setTimeout(() => router.push(`/analysis/${analysisId}`), 400)
  } catch (err) {
    const msg = err.message || err.response?.data?.detail || 'Upload or analysis failed'
    ElMessage.error(msg)
  } finally {
    uploading.value = false
    uploadProgress.value = 0
  }
}

function formatDate(dateStr) {
  return new Date(dateStr).toLocaleString()
}

function formatSize(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function timeAgo(iso) {
  if (!iso) return ''
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}
</script>

<style scoped>
.dashboard {
  max-width: 1200px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
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

/* ── Last updated indicator ──────────────────────────────────────────── */
.last-updated {
  font-size: 12px;
  color: #909399;
  padding-top: 6px;
}
.last-updated .stale { color: #e6a23c; }

/* ── Stale warning bar ───────────────────────────────────────────────── */
.stale-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  background: #fdf6ec;
  border: 1px solid #e6a23c;
  border-radius: 8px;
  margin-bottom: 14px;
  font-size: 13px;
  color: #e6a23c;
}
.stale-bar :deep(.el-icon) { color: #e6a23c; }
.stale-time { color: #909399; }

/* ── Skeleton placeholders ───────────────────────────────────────────── */
.skeleton-bar {
  height: 44px;
  border-radius: 10px;
  background: #ebeef5;
  margin-bottom: 18px;
}
.skeleton-card {
  height: 200px;
  border-radius: 12px;
  background: #ebeef5;
}
.skeleton-card.skeleton-sm { height: 140px; }

.pulse {
  animation: pulse 1.5s ease-in-out infinite;
}
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50%      { opacity: 0.5; }
}

/* ── Live Status Bar ─────────────────────────────────────────────────── */
.live-status-bar {
  display: flex;
  align-items: center;
  gap: 20px;
  padding: 10px 18px;
  background: white;
  border-radius: 10px;
  border: 1px solid #e4e7ed;
  margin-bottom: 18px;
  font-size: 13px;
  color: #606266;
  flex-wrap: wrap;
}
.ls-item {
  display: flex;
  align-items: center;
  gap: 6px;
}
.ls-item strong { color: #303133; font-size: 16px; }
.ls-threats strong { color: #f56c6c; }
.ls-ti { cursor: pointer; border-radius: 6px; padding: 6px 12px; background: #fef0f0; }
.ls-ti:hover { background: #fde2e2; }
.ls-ti strong { color: #f56c6c; }
.ls-capture { background: #fdf6ec; border-radius: 6px; padding: 6px 12px; }
.ls-capture strong { color: #e6a23c; }
.ls-spacer { flex: 1; }

.collector-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.dot-on  { background: #67c23a; }
.dot-off { background: #f56c6c; }

.risk-ip-badge {
  font-family: 'SF Mono', monospace;
  font-size: 12px;
  padding: 2px 8px;
  border-radius: 6px;
  font-weight: 600;
}
.risk-ip-badge.risk-critical { background: #fde2e2; color: #f56c6c; }
.risk-ip-badge.risk-high     { background: #faecd8; color: #e6a23c; }
.risk-ip-badge.risk-medium   { background: #fdf6ec; color: #c68a19; }
.risk-ip-badge.risk-low      { background: #e1f3d8; color: #67c23a; }

/* ── Two-column layout ───────────────────────────────────────────────── */
.dash-columns {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 18px;
}
@media (max-width: 900px) {
  .dash-columns { grid-template-columns: 1fr; }
}
.dash-left, .dash-right {
  display: flex;
  flex-direction: column;
  gap: 18px;
}

/* ── Shared card styles ──────────────────────────────────────────────── */
.upload-card, .steps-card, .recent-card, .intel-card {
  border-radius: 12px;
  border: 1px solid #e4e7ed;
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
.card-header-row.clickable { cursor: pointer; }
.card-header-row .el-icon {
  transition: transform 0.2s;
  color: #909399;
}
.card-header-row .el-icon.rotated { transform: rotate(180deg); }
.empty-hint {
  font-size: 13px;
  color: #909399;
  padding: 12px 0;
  text-align: center;
}
.mono { font-family: 'SF Mono', 'Menlo', monospace; font-size: 12px; }

/* ── Upload zone ─────────────────────────────────────────────────────── */
.upload-zone {
  border: 2px dashed #d0d7de;
  border-radius: 12px;
  padding: 48px 24px;
  text-align: center;
  cursor: pointer;
  transition: all 0.3s;
}
.upload-zone:hover, .upload-zone.dragging {
  border-color: #409EFF;
  background: #f0f7ff;
}
.upload-zone.uploading {
  cursor: default;
  border-color: #409EFF;
  background: #f0f7ff;
}
.upload-icon { margin-bottom: 16px; }
.upload-zone h3 {
  font-size: 16px;
  color: #303133;
  margin-bottom: 8px;
  font-weight: 600;
}
.upload-hint { font-size: 13px; color: #909399; }
.upload-progress {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}
.upload-progress h3 { font-size: 16px; color: #303133; font-weight: 600; }
.upload-progress p  { font-size: 13px; color: #909399; }
.spinning { animation: spin 1s linear infinite; }
@keyframes spin {
  from { transform: rotate(0deg); }
  to   { transform: rotate(360deg); }
}

/* ── Analysis steps ──────────────────────────────────────────────────── */
.analysis-steps {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.step-item {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 16px;
  background: #fafafa;
  border-radius: 10px;
  border: 1px solid #f0f0f0;
}
.step-icon {
  width: 48px;
  height: 48px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.step-info h4 { font-size: 14px; font-weight: 600; color: #303133; margin-bottom: 4px; }
.step-info p  { font-size: 12px; color: #909399; line-height: 1.5; }

/* ── Recent analyses ─────────────────────────────────────────────────── */
.recent-list { display: flex; flex-direction: column; gap: 4px; }
.recent-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-radius: 8px;
  cursor: pointer;
  transition: background 0.2s;
}
.recent-item:hover { background: #f5f7fa; }
.recent-icon {
  width: 40px;
  height: 40px;
  border-radius: 8px;
  background: #ecf5ff;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.recent-info { flex: 1; min-width: 0; }
.recent-name { font-size: 14px; font-weight: 500; color: #303133; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.recent-meta { font-size: 12px; color: #909399; margin-top: 2px; }
.recent-badges { display: flex; gap: 6px; }

/* ── Top Risk IPs ────────────────────────────────────────────────────── */
.risk-list { display: flex; flex-direction: column; gap: 2px; }
.risk-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 4px;
  border-radius: 6px;
  font-size: 12px;
}
.risk-row.clickable { cursor: pointer; }
.risk-row.clickable:hover { background: #f5f7fa; }
.risk-ip { flex: 1; color: #303133; font-weight: 500; }
.risk-badge {
  display: inline-block;
  min-width: 28px;
  text-align: center;
  padding: 2px 6px;
  border-radius: 10px;
  font-weight: 700;
  font-size: 11px;
  transition: background 0.3s;
}
.risk-badge.risk-critical { background: #fde2e2; color: #f56c6c; }
.risk-badge.risk-high     { background: #faecd8; color: #e6a23c; }
.risk-badge.risk-medium   { background: #fdf6ec; color: #c68a19; }
.risk-badge.risk-low      { background: #e1f3d8; color: #67c23a; }

/* Flash highlight when score changes */
.risk-badge.flash {
  animation: score-flash 0.5s ease-out;
}
@keyframes score-flash {
  0%   { background: #fef08a; }
  100% { background: inherit; }
}

.risk-driver {
  flex: 1;
  color: #909399;
  text-transform: capitalize;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.risk-count { color: #606266; font-family: monospace; }

/* ── Auto-detections ─────────────────────────────────────────────────── */
.auto-list { display: flex; flex-direction: column; gap: 2px; }
.auto-row {
  display: flex;
  gap: 8px;
  padding: 8px 4px;
  border-radius: 6px;
  font-size: 12px;
  color: #303133;
}
.auto-row.clickable { cursor: pointer; }
.auto-row.clickable:hover { background: #f5f7fa; }
.auto-time {
  color: #909399;
  white-space: nowrap;
  min-width: 50px;
}
.auto-msg {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Slide-in animation for new auto-detections */
.slide-enter-active {
  transition: all 0.4s ease-out;
}
.slide-enter-from {
  opacity: 0;
  transform: translateY(-20px);
}

/* ── Active incidents ─────────────────────────────────────────────────── */
.incident-counts {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.ic-total {
  font-size: 24px;
  font-weight: 700;
  color: #1a1a2e;
}
.ic-badge {
  font-size: 11px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 10px;
}
.ic-critical { background: #fde2e2; color: #f56c6c; }
.ic-high     { background: #faecd8; color: #f97316; }
.ic-medium   { background: #fef9c3; color: #a16207; }

.incident-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.incident-row {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 4px;
  border-radius: 6px;
  font-size: 12px;
}
.incident-row:hover { background: #f5f7fa; }
.sev-badge {
  display: inline-block;
  min-width: 50px;
  text-align: center;
  padding: 2px 6px;
  border-radius: 8px;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
}
.sev-critical { background: #fde2e2; color: #f56c6c; }
.sev-high     { background: #faecd8; color: #f97316; }
.sev-medium   { background: #fef9c3; color: #a16207; }
.sev-low      { background: #ebeef5; color: #909399; }
.inc-type {
  color: #303133;
  font-weight: 500;
  text-transform: capitalize;
  min-width: 80px;
}
.inc-ip {
  flex: 1;
  color: #303133;
}
.inc-count {
  color: #606266;
  font-size: 11px;
}
.inc-time {
  color: #909399;
  font-size: 11px;
  white-space: nowrap;
}

/* ── Collector health ────────────────────────────────────────────────── */
.collector-body { padding-top: 4px; }
.coll-row {
  display: flex;
  justify-content: space-between;
  padding: 4px 0;
  font-size: 12px;
  color: #303133;
  border-bottom: 1px solid #f4f6fa;
}
.coll-row:last-child { border-bottom: none; }
.coll-label {
  color: #909399;
  text-transform: capitalize;
}
</style>
