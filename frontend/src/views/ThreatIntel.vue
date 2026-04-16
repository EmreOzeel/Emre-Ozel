<template>
  <div class="threat-intel-page">
    <h2 class="page-title">Threat Intelligence</h2>

    <!-- Feed status cards -->
    <div class="feed-grid">
      <div v-for="feed in feeds" :key="feed.id" class="feed-card">
        <div class="fc-header">
          <span
            class="fc-dot"
            :class="feedDotClass(feed)"
          ></span>
          <span class="fc-name">{{ feedLabel(feed.name) }}</span>
        </div>
        <div class="fc-body">
          <div class="fc-row">
            <span class="fc-key">Last fetched</span>
            <span class="fc-val">{{ feedAgo(feed.last_fetched_at) }}</span>
          </div>
          <div class="fc-row">
            <span class="fc-key">Indicators</span>
            <span class="fc-val mono">{{ feed.last_indicator_count.toLocaleString() }}</span>
          </div>
          <div class="fc-row">
            <span class="fc-key">Threat type</span>
            <span class="threat-badge" :class="`tt-${feed.default_threat_type}`">{{ feed.default_threat_type }}</span>
          </div>
          <div class="fc-row">
            <span class="fc-key">Confidence</span>
            <span class="fc-val">{{ (feed.default_confidence * 100).toFixed(0) }}%</span>
          </div>
        </div>
        <div class="fc-footer" v-if="isAdmin">
          <el-button
            size="small"
            type="primary"
            :loading="fetchingFeed === feed.id"
            @click="fetchNow(feed)"
          >
            <el-icon v-if="fetchingFeed !== feed.id"><Refresh /></el-icon>
            Fetch now
          </el-button>
        </div>
      </div>
    </div>

    <!-- Indicators table -->
    <div class="indicators-section">
      <div class="ind-header">
        <span class="ind-title">Indicators</span>
        <span class="ind-count" v-if="indTotal > 0">{{ indTotal.toLocaleString() }} total</span>
      </div>

      <div class="filter-bar">
        <el-select v-model="indFilters.threat_type" placeholder="Threat type" clearable size="small" style="width:140px" @change="resetIndicators">
          <el-option label="All types" value="" />
          <el-option v-for="t in ['malware','c2','scanner','tor_exit','botnet','phishing']" :key="t" :label="t" :value="t" />
        </el-select>
        <el-select v-model="indFilters.source_feed" placeholder="Source feed" clearable size="small" style="width:200px" @change="resetIndicators">
          <el-option label="All feeds" value="" />
          <el-option v-for="f in feeds" :key="f.name" :label="feedLabel(f.name)" :value="f.name" />
        </el-select>
        <el-input v-model="indFilters.search" placeholder="Search IP..." clearable size="small" style="width:160px" @keyup.enter="resetIndicators" @clear="resetIndicators" />
        <el-button size="small" @click="resetIndicators">Search</el-button>
      </div>

      <div class="table-wrap">
        <el-table :data="indicators" stripe size="small" v-loading="indLoading" empty-text="No indicators found" style="width:100%">
          <el-table-column label="Type" width="80">
            <template #default="{ row }">
              <span class="type-badge">{{ row.indicator_type }}</span>
            </template>
          </el-table-column>
          <el-table-column label="Value" min-width="180">
            <template #default="{ row }">
              <span class="mono">{{ row.indicator_value }}</span>
            </template>
          </el-table-column>
          <el-table-column label="Country" width="65" align="center">
            <template #default="{ row }">
              <span v-if="row.indicator_type === 'ip' && geoCache[row.indicator_value]" class="geo-flag" :title="geoCache[row.indicator_value]?.country_name">
                {{ countryFlag(geoCache[row.indicator_value]?.country_code) || '?' }}
              </span>
              <span v-else>—</span>
            </template>
          </el-table-column>
          <el-table-column label="Threat Type" width="120">
            <template #default="{ row }">
              <span class="threat-badge" :class="`tt-${row.threat_type}`">{{ row.threat_type }}</span>
            </template>
          </el-table-column>
          <el-table-column label="Source" width="200">
            <template #default="{ row }">
              {{ feedLabel(row.source_feed) }}
            </template>
          </el-table-column>
          <el-table-column label="Confidence" width="100" align="center">
            <template #default="{ row }">
              {{ (row.confidence * 100).toFixed(0) }}%
            </template>
          </el-table-column>
          <el-table-column label="First Seen" width="145">
            <template #default="{ row }">
              <span class="ts">{{ fmtTime(row.first_seen) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="Last Seen" width="145">
            <template #default="{ row }">
              <span class="ts">{{ fmtTime(row.last_seen) }}</span>
            </template>
          </el-table-column>
        </el-table>
      </div>

      <div class="pagination-bar">
        <span class="page-info">Showing {{ indicators.length }} of {{ indTotal }}</span>
        <el-button v-if="indicators.length < indTotal" size="small" :loading="indLoadingMore" @click="loadMoreIndicators">Load more</el-button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import {
  fetchThreatFeeds,
  fetchThreatIndicators,
  fetchThreatFeed,
  fetchGeoBatchLookup,
} from '@/api'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const isAdmin = computed(() => auth.user?.is_admin ?? false)

const feeds = ref([])
const feedsLoading = ref(false)
const fetchingFeed = ref(null)

const indicators = ref([])
const indTotal = ref(0)
const indOffset = ref(0)
const indLoading = ref(false)
const indLoadingMore = ref(false)
const PAGE_SIZE = 100
const geoCache = reactive({})

function countryFlag(code) {
  if (!code) return ''
  return code.toUpperCase().replace(/./g, c => String.fromCodePoint(0x1F1E0 - 65 + c.charCodeAt(0)))
}

async function lookupIndicatorGeos(items) {
  const ips = items
    .filter(i => i.indicator_type === 'ip' && !geoCache[i.indicator_value])
    .map(i => i.indicator_value)
    .slice(0, 50)
  if (!ips.length) return
  try {
    const res = await fetchGeoBatchLookup(ips)
    for (const [ip, geo] of Object.entries(res.data)) {
      geoCache[ip] = geo
    }
  } catch {}
}

const indFilters = reactive({
  threat_type: '',
  source_feed: '',
  search: '',
})

const FEED_LABELS = {
  emerging_threats_compromised: 'Emerging Threats',
  feodo_tracker_c2: 'Feodo Tracker C2',
  cins_army_scanners: 'CINS Army Scanners',
  tor_exit_nodes: 'TOR Exit Nodes',
}

function feedLabel(name) {
  return FEED_LABELS[name] || name.replace(/_/g, ' ')
}

function feedDotClass(feed) {
  if (!feed.last_fetched_at) return 'dot-gray'
  const hoursAgo = (Date.now() - new Date(feed.last_fetched_at).getTime()) / 3600000
  if (hoursAgo <= feed.fetch_interval_hours * 1.5) return 'dot-green'
  return 'dot-red'
}

function feedAgo(iso) {
  if (!iso) return 'Never'
  const ms = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(ms / 60000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

function fmtTime(iso) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString(undefined, {
    month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false,
  })
}

async function loadFeeds() {
  feedsLoading.value = true
  try {
    feeds.value = (await fetchThreatFeeds()).data
  } catch (e) {
    console.error('Failed to load feeds', e)
  } finally {
    feedsLoading.value = false
  }
}

async function fetchNow(feed) {
  fetchingFeed.value = feed.id
  try {
    await fetchThreatFeed(feed.id)
    await loadFeeds()
    resetIndicators()
  } catch (e) {
    console.error('Fetch failed', e)
  } finally {
    fetchingFeed.value = null
  }
}

async function loadIndicators(append = false) {
  if (append) indLoadingMore.value = true
  else indLoading.value = true
  try {
    const params = { limit: PAGE_SIZE, offset: indOffset.value }
    if (indFilters.threat_type) params.threat_type = indFilters.threat_type
    if (indFilters.source_feed) params.source_feed = indFilters.source_feed
    const res = await fetchThreatIndicators(params)
    if (append) indicators.value = [...indicators.value, ...res.data.items]
    else indicators.value = res.data.items
    indTotal.value = res.data.total
    lookupIndicatorGeos(res.data.items)
  } catch (e) {
    console.error('Failed to load indicators', e)
  } finally {
    indLoading.value = false
    indLoadingMore.value = false
  }
}

function resetIndicators() {
  indOffset.value = 0
  loadIndicators()
}

function loadMoreIndicators() {
  indOffset.value = indicators.value.length
  loadIndicators(true)
}

onMounted(() => {
  loadFeeds()
  loadIndicators()
})
</script>

<style scoped>
.threat-intel-page { max-width: 1300px; margin: 0 auto; }
.page-title { margin: 0 0 16px; font-size: 20px; }

/* Feed cards grid */
.feed-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-bottom: 24px;
}
.feed-card {
  background: white;
  border-radius: 8px;
  border: 1px solid #e4e7ed;
  padding: 16px;
}
.fc-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}
.fc-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex-shrink: 0;
}
.dot-green { background: #67c23a; }
.dot-gray  { background: #c0c4cc; }
.dot-red   { background: #f56c6c; }
.fc-name {
  font-weight: 600;
  font-size: 14px;
  color: #303133;
}
.fc-body {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.fc-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 12px;
}
.fc-key { color: #909399; }
.fc-val { color: #303133; font-weight: 500; }
.fc-footer {
  margin-top: 12px;
  padding-top: 10px;
  border-top: 1px solid #ebeef5;
}
.mono { font-family: 'SF Mono', 'Menlo', monospace; font-size: 12px; }

/* Threat type badges */
.threat-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
}
.tt-malware  { background: #fde2e2; color: #f56c6c; }
.tt-c2       { background: #f3e8ff; color: #7c3aed; }
.tt-scanner  { background: #faecd8; color: #e6a23c; }
.tt-tor_exit { background: #e8f4fd; color: #409eff; }
.tt-botnet   { background: #fce4ec; color: #e91e63; }
.tt-phishing { background: #fff3e0; color: #ff9800; }
.tt-unknown  { background: #ebeef5; color: #909399; }

/* Indicators section */
.indicators-section {
  margin-top: 8px;
}
.ind-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
}
.ind-title {
  font-size: 16px;
  font-weight: 600;
  color: #303133;
}
.ind-count {
  font-size: 12px;
  color: #909399;
  background: #f4f4f5;
  padding: 2px 8px;
  border-radius: 10px;
}

.filter-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 10px;
  padding: 10px 14px;
  background: white;
  border-radius: 8px;
  border: 1px solid #e4e7ed;
}

.table-wrap {
  background: white;
  border-radius: 8px;
  border: 1px solid #e4e7ed;
  overflow: hidden;
}
.type-badge {
  display: inline-block;
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  background: #ebeef5;
  color: #606266;
}
.ts { color: #606266; font-size: 11px; white-space: nowrap; }
.geo-flag { font-size: 14px; }

.pagination-bar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 10px;
  padding: 8px 4px;
}
.page-info { font-size: 12px; color: #909399; }
</style>
