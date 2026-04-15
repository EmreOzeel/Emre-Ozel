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

export default api
