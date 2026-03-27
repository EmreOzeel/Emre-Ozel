import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 120000, // 2 minutes for large PCAP uploads
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

export default api
