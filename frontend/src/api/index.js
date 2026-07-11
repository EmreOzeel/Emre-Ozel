import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 300000, // 5 minutes for large PCAP analysis
})

// Attach token to every request
api.interceptors.request.use(config => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle 401 globally — but NOT for the login endpoint itself
api.interceptors.response.use(
  response => response,
  error => {
    const isLoginEndpoint = error.config?.url?.includes('/auth/login')
    if (error.response?.status === 401 && !isLoginEndpoint) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// ── Live events helpers ──────────────────────────────────────────────────────

export function fetchLiveEvents(params = {}) {
  return api.get('/live-events', { params })
}

export function fetchLiveEventsStats() {
  return api.get('/live-events/stats')
}

export function fetchLiveEventsTimeline(params = {}) {
  return api.get('/live-events/timeline', { params })
}

export function fetchLiveFlows(params = {}) {
  return api.get('/live-flows', { params })
}

export function fetchLiveFlowsStats() {
  return api.get('/live-flows/stats')
}

export function fetchLiveFlowsTimeline(params = {}) {
  return api.get('/live-flows/timeline', { params })
}

export function fetchLiveRiskScores(params = {}) {
  return api.get('/live-events/risk-scores', { params })
}

export function fetchLiveIncidents(params = {}) {
  return api.get('/live-incidents', { params })
}

export function fetchLiveIncidentDetail(id) {
  return api.get(`/live-incidents/${id}`)
}

export function fetchUpdateIncidentStatus(id, status) {
  return api.put(`/live-incidents/${id}/status`, { status })
}

export function fetchCollectorStatus() {
  return api.get('/collector/status')
}

export function fetchBehaviors(params = {}) {
  return api.get('/live-flows/behaviors', { params })
}

export function fetchBaselines(params = {}) {
  return api.get('/baselines', { params })
}

export function fetchBaseline(sourceIp) {
  return api.get(`/baselines/${sourceIp}`)
}

// ── Correlation Rules ────────────────────────────────────────────────────────

export function fetchCorrelationRules() {
  return api.get('/correlation-rules')
}

export function createCorrelationRule(data) {
  return api.post('/correlation-rules', data)
}

export function updateCorrelationRule(id, data) {
  return api.put(`/correlation-rules/${id}`, data)
}

export function deleteCorrelationRule(id) {
  return api.delete(`/correlation-rules/${id}`)
}

export function toggleCorrelationRule(id) {
  return api.patch(`/correlation-rules/${id}/toggle`)
}

// ── Threat Intelligence ──────────────────────────────────────────────────────

export function fetchThreatFeeds() {
  return api.get('/threat-feeds')
}

export function fetchThreatIndicators(params = {}) {
  return api.get('/threat-indicators', { params })
}

export function lookupThreatIP(ip) {
  return api.get('/threat-indicators/lookup', { params: { ip } })
}

export function fetchThreatFeed(id) {
  return api.post(`/threat-feeds/${id}/fetch`)
}

export function refreshAllThreatFeeds() {
  return api.post('/threat-feeds/refresh-all')
}

// ── Web Transactions ─────────────────────────────────────────────────────────

export function getWebTransactions(params = {}) {
  return api.get('/web-transactions', { params })
}

export function getWebTransaction(id) {
  return api.get(`/web-transactions/${id}`)
}

export function getWebTransactionStats() {
  return api.get('/web-transactions/stats')
}

export function getWebTransactionTimeseries(params = {}) {
  return api.get('/web-transactions/timeseries', { params })
}

export function getWebTransactionsTop(params = {}) {
  return api.get('/web-transactions/top', { params })
}

// ── PCAP Trigger ─────────────────────────────────────────────────────────────

export function fetchPcapTriggerStatus() {
  return api.get('/pcap-trigger/status')
}

export function triggerManualPcap(data) {
  return api.post('/pcap-trigger/manual', data)
}

export function fetchIncidentPcaps(incidentId) {
  return api.get(`/live-incidents/${incidentId}/pcaps`)
}

// ── GeoIP ────────────────────────────────────────────────────────────────────

export function fetchGeoLookup(ip) {
  return api.get('/geo/lookup', { params: { ip } })
}

export function fetchGeoBatchLookup(ips) {
  return api.post('/geo/batch-lookup', { ips })
}

export function fetchGeoCacheStats() {
  return api.get('/geo/cache-stats')
}

// ── Packet Engine ───────────────────────────────────────────────────────────

export function fetchPacketWatches() {
  return api.get('/packet-engine/watches')
}

export function createPacketWatch(data) {
  return api.post('/packet-engine/watches', data)
}

export function deletePacketWatch(ip, port) {
  return api.delete(`/packet-engine/watches/${ip}/${port}`)
}

export default api
