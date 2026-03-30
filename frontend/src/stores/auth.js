import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '../api'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem('token') || '')
  const user = ref(null)

  function init() {
    if (token.value) {
      api.get('/auth/me').then(res => {
        user.value = res.data
      }).catch(() => {
        logout()
      })
    }
  }

  async function login(username, password) {
    const res = await api.post('/auth/login', { username, password })
    token.value = res.data.access_token
    localStorage.setItem('token', token.value)
    const me = await api.get('/auth/me')
    user.value = me.data
  }

  function logout() {
    token.value = ''
    user.value = null
    localStorage.removeItem('token')
  }

  return { token, user, init, login, logout }
})
