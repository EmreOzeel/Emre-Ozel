import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '../stores/auth'

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('../views/Login.vue'),
    meta: { public: true }
  },
  {
    path: '/',
    component: () => import('../views/Layout.vue'),
    children: [
      {
        path: '',
        name: 'Dashboard',
        component: () => import('../views/Dashboard.vue'),
      },
      {
        path: 'work-queue',
        name: 'WorkQueue',
        component: () => import('../views/WorkQueue.vue'),
      },
      {
        path: 'analysis/:id',
        name: 'AnalysisDetail',
        component: () => import('../views/analysis/AnalysisDetail.vue'),
      },
      {
        path: 'history',
        name: 'History',
        component: () => import('../views/History.vue'),
      },
      {
        path: 'compare',
        name: 'Compare',
        component: () => import('../views/CompareView.vue'),
      },
      {
        path: 'suppressions',
        name: 'Suppressions',
        component: () => import('../views/SuppressionsView.vue'),
      },
      {
        path: 'calibration',
        name: 'Calibration',
        component: () => import('../views/CalibrationView.vue'),
      },
      {
        path: 'monitoring',
        name: 'Monitoring',
        component: () => import('../views/Monitoring.vue'),
      },
      {
        path: 'live-events',
        name: 'LiveEvents',
        component: () => import('../views/LiveEvents.vue'),
      },
      {
        path: 'live-flows',
        name: 'LiveFlows',
        component: () => import('../views/LiveFlows.vue'),
      },
      {
        path: 'web-transactions',
        name: 'WebTransactions',
        component: () => import('../views/WebTransactions.vue'),
      },
      {
        path: 'live-incidents',
        name: 'LiveIncidents',
        component: () => import('../views/LiveIncidents.vue'),
      },
      {
        path: 'correlation-rules',
        name: 'CorrelationRules',
        component: () => import('../views/CorrelationRules.vue'),
      },
      {
        path: 'threat-intel',
        name: 'ThreatIntel',
        component: () => import('../views/ThreatIntel.vue'),
      },
      {
        path: 'geo-map',
        name: 'GeoMap',
        component: () => import('../views/GeoMap.vue'),
      },
      {
        path: 'packet-engine',
        name: 'PacketEngine',
        component: () => import('../views/PacketEngine.vue'),
      },
    ]
  },
  {
    path: '/:pathMatch(.*)*',
    redirect: '/'
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

router.beforeEach((to) => {
  const auth = useAuthStore()
  if (!to.meta.public && !auth.token) {
    return { name: 'Login' }
  }
  if (to.name === 'Login' && auth.token) {
    return { name: 'Dashboard' }
  }
})

export default router
