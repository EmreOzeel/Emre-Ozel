<template>
  <div class="geo-map-page">
    <div class="map-header">
      <h2>Geographic Map</h2>
      <div class="map-controls">
        <el-select v-model="timeRange" size="small" style="width:120px" @change="refreshData">
          <el-option value="15" label="Last 15 min" />
          <el-option value="60" label="Last 1 hour" />
          <el-option value="360" label="Last 6 hours" />
        </el-select>
        <el-checkbox-group v-model="layers" size="small">
          <el-checkbox-button label="incidents">Incidents</el-checkbox-button>
          <el-checkbox-button label="arcs">Flow Arcs</el-checkbox-button>
        </el-checkbox-group>
        <el-button size="small" @click="refreshData" :loading="loading">
          <el-icon><Refresh /></el-icon> Refresh
        </el-button>
      </div>
    </div>

    <div class="map-container" ref="mapContainer"></div>

    <!-- Legend -->
    <div class="map-legend">
      <div class="legend-section">
        <div class="legend-title">Incidents</div>
        <div class="legend-item"><span class="legend-dot dot-critical"></span> Critical / High</div>
        <div class="legend-item"><span class="legend-dot dot-medium"></span> Medium</div>
        <div class="legend-item"><span class="legend-dot dot-low"></span> Low</div>
      </div>
      <div class="legend-section">
        <div class="legend-title">Flows</div>
        <div class="legend-item"><span class="legend-line line-denied"></span> Denied</div>
        <div class="legend-item"><span class="legend-line line-reset"></span> Reset</div>
        <div class="legend-item"><span class="legend-line line-completed"></span> Completed</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import { Refresh } from '@element-plus/icons-vue'
import api from '@/api'
import { fetchGeoBatchLookup } from '@/api'

const mapContainer = ref(null)
const timeRange = ref('60')
const layers = ref(['incidents', 'arcs'])
const loading = ref(false)

let map = null
let incidentMarkers = []
let arcLines = []

// Country centroids for flow arcs
const CENTROIDS = {
  US: [37.09, -95.71], CN: [35.86, 104.19], TR: [38.96, 35.24],
  RU: [61.52, 105.31], DE: [51.16, 10.45], GB: [55.37, -3.43],
  FR: [46.22, 2.21], NL: [52.13, 5.29], BR: [-14.23, -51.92],
  IN: [20.59, 78.96], JP: [36.20, 138.25], KR: [35.91, 127.77],
  AU: [-25.27, 133.77], CA: [56.13, -106.35], IT: [41.87, 12.57],
  ES: [40.46, -3.75], SE: [60.13, 18.64], CH: [46.82, 8.23],
  PL: [51.92, 19.15], UA: [48.38, 31.17], SA: [23.89, 45.08],
  SG: [1.35, 103.82], HK: [22.40, 114.11], TW: [23.70, 120.96],
  MX: [23.63, -102.55], AR: [-38.42, -63.62], ZA: [-30.56, 22.94],
  EG: [26.82, 30.80], NG: [9.08, 8.68], KE: [-0.02, 37.91],
}

function countryFlag(code) {
  if (!code) return ''
  return code.toUpperCase().replace(/./g, c => String.fromCodePoint(0x1F1E0 - 65 + c.charCodeAt(0)))
}

// ── Leaflet setup ───────────────────────────────────────────────────────────

let L = null

async function loadLeaflet() {
  if (window.L) { L = window.L; return }

  // Load CSS
  const link = document.createElement('link')
  link.rel = 'stylesheet'
  link.href = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css'
  document.head.appendChild(link)

  // Load JS
  await new Promise((resolve, reject) => {
    const script = document.createElement('script')
    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js'
    script.onload = resolve
    script.onerror = reject
    document.head.appendChild(script)
  })
  L = window.L
}

function initMap() {
  if (!L || !mapContainer.value) return
  map = L.map(mapContainer.value).setView([25, 10], 2)
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors',
    maxZoom: 18,
  }).addTo(map)
}

// ── Data loading ────────────────────────────────────────────────────────────

async function refreshData() {
  loading.value = true
  try {
    await Promise.all([
      layers.value.includes('incidents') ? loadIncidents() : clearIncidents(),
      layers.value.includes('arcs') ? loadFlowArcs() : clearArcs(),
    ])
  } finally {
    loading.value = false
  }
}

async function loadIncidents() {
  clearIncidents()
  if (!map || !L) return

  try {
    const res = await api.get('/live-incidents', { params: { status: 'open', limit: 200 } })
    const incidents = res.data.incidents || []

    // Batch lookup geo for all source IPs
    const ips = [...new Set(incidents.map(i => i.source_ip))]
    let geoMap = {}
    if (ips.length) {
      try {
        const geoRes = await fetchGeoBatchLookup(ips.slice(0, 50))
        geoMap = geoRes.data
      } catch {}
    }

    for (const inc of incidents) {
      const geo = inc.source_geo || geoMap[inc.source_ip]
      if (!geo?.latitude || !geo?.longitude || geo.is_private) continue

      const color = (inc.severity === 'critical' || inc.severity === 'high')
        ? '#f56c6c'
        : inc.severity === 'medium' ? '#e6a23c' : '#909399'

      const marker = L.circleMarker([geo.latitude, geo.longitude], {
        radius: 7,
        fillColor: color,
        color: color,
        weight: 1,
        opacity: 0.9,
        fillOpacity: 0.6,
      }).addTo(map)

      marker.bindPopup(
        `<strong>${inc.source_ip}</strong><br>` +
        `${countryFlag(geo.country_code)} ${geo.country_name || ''}${geo.city ? ' / ' + geo.city : ''}<br>` +
        `Behavior: ${inc.behavior_type.replace(/_/g, ' ')}<br>` +
        `Severity: <strong>${inc.severity}</strong><br>` +
        `Detections: ${inc.event_count}`
      )
      incidentMarkers.push(marker)
    }
  } catch (e) {
    console.error('Failed to load incidents for map', e)
  }
}

async function loadFlowArcs() {
  clearArcs()
  if (!map || !L) return

  try {
    const res = await api.get('/live-flows', { params: { limit: 100 } })
    const flows = res.data.flows || []

    // Get top 20 by event count
    const sorted = flows
      .filter(f => f.source_geo || f.destination_geo)
      .sort((a, b) => (b.event_count || 0) - (a.event_count || 0))
      .slice(0, 20)

    // Batch lookup geo for any missing
    const ips = new Set()
    for (const f of sorted) {
      if (!f.source_geo?.country_code) ips.add(f.source_ip)
      if (!f.destination_geo?.country_code) ips.add(f.destination_ip)
    }
    let geoMap = {}
    if (ips.size) {
      try {
        const geoRes = await fetchGeoBatchLookup([...ips].slice(0, 50))
        geoMap = geoRes.data
      } catch {}
    }

    for (const f of sorted) {
      const srcGeo = f.source_geo || geoMap[f.source_ip]
      const dstGeo = f.destination_geo || geoMap[f.destination_ip]

      const srcCC = srcGeo?.country_code
      const dstCC = dstGeo?.country_code
      if (!srcCC || !dstCC || srcCC === dstCC) continue

      const srcLatLng = srcGeo?.latitude && srcGeo?.longitude
        ? [srcGeo.latitude, srcGeo.longitude]
        : CENTROIDS[srcCC]
      const dstLatLng = dstGeo?.latitude && dstGeo?.longitude
        ? [dstGeo.latitude, dstGeo.longitude]
        : CENTROIDS[dstCC]

      if (!srcLatLng || !dstLatLng) continue

      // Curved line via midpoint offset
      const midLat = (srcLatLng[0] + dstLatLng[0]) / 2
      const midLng = (srcLatLng[1] + dstLatLng[1]) / 2
      const dist = Math.sqrt(
        Math.pow(srcLatLng[0] - dstLatLng[0], 2) +
        Math.pow(srcLatLng[1] - dstLatLng[1], 2)
      )
      const offsetLat = midLat + dist * 0.15
      const offsetLng = midLng

      const color = f.state === 'denied' || f.state === 'dropped'
        ? '#f56c6c'
        : f.state === 'reset' ? '#e6a23c' : '#67c23a'
      const weight = Math.max(1, Math.min(5, (f.event_count || 1) / 5))

      const arc = L.polyline(
        [srcLatLng, [offsetLat, offsetLng], dstLatLng],
        { color, weight, opacity: 0.6, smoothFactor: 3 }
      ).addTo(map)

      arc.bindPopup(
        `<strong>${f.source_ip}</strong> ${countryFlag(srcCC)}` +
        ` → ${countryFlag(dstCC)} <strong>${f.destination_ip}</strong><br>` +
        `State: ${f.state} | Events: ${f.event_count}<br>` +
        `${f.application || ''}`
      )
      arcLines.push(arc)
    }
  } catch (e) {
    console.error('Failed to load flow arcs', e)
  }
}

function clearIncidents() {
  for (const m of incidentMarkers) m.remove()
  incidentMarkers = []
}

function clearArcs() {
  for (const a of arcLines) a.remove()
  arcLines = []
}

watch(layers, () => refreshData())

onMounted(async () => {
  await loadLeaflet()
  await nextTick()
  initMap()
  refreshData()
})

onUnmounted(() => {
  if (map) { map.remove(); map = null }
})
</script>

<style scoped>
.geo-map-page {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 48px);
}
.map-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 0 12px;
  flex-shrink: 0;
}
.map-header h2 {
  margin: 0;
  font-size: 20px;
}
.map-controls {
  display: flex;
  align-items: center;
  gap: 10px;
}
.map-container {
  flex: 1;
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid #e4e7ed;
  min-height: 400px;
}

/* Legend */
.map-legend {
  display: flex;
  gap: 24px;
  padding: 10px 0 0;
  flex-shrink: 0;
}
.legend-section {
  display: flex;
  align-items: center;
  gap: 12px;
}
.legend-title {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  color: #909399;
  margin-right: 4px;
}
.legend-item {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  color: #606266;
}
.legend-dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
}
.dot-critical { background: #f56c6c; }
.dot-medium   { background: #e6a23c; }
.dot-low      { background: #909399; }
.legend-line {
  display: inline-block;
  width: 20px;
  height: 3px;
  border-radius: 2px;
}
.line-denied    { background: #f56c6c; }
.line-reset     { background: #e6a23c; }
.line-completed { background: #67c23a; }
</style>
