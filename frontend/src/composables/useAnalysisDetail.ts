import { ref, computed } from 'vue'
import type { Ref, ComputedRef } from 'vue'
import api from '@/api'
import type { AnalysisDetail, Finding, HostProfile, TCPSession } from '@/types/analysis'

export type TabName =
  | 'overview' | 'findings' | 'hosts' | 'conversations'
  | 'protocols' | 'dns' | 'web' | 'tls' | 'tcp'
  | 'security' | 'timeline' | 'expert'

export interface FindingFilters {
  severity: string
  category: string
  search: string
}

export interface ConversationFilters {
  handshake: string
  protocol: string
  search: string
}

export interface UseAnalysisDetailReturn {
  // State
  analysis: Ref<AnalysisDetail | null>
  loading: Ref<boolean>
  error: Ref<string | null>
  activeTab: Ref<TabName>
  findingFilters: Ref<FindingFilters>
  conversationFilters: Ref<ConversationFilters>
  // Actions
  fetch: (id: string) => Promise<void>
  navigateTo: (tab: string, filters?: Record<string, string>) => void
  // Computed
  criticalFindings: ComputedRef<Finding[]>
  warningFindings: ComputedRef<Finding[]>
  allActiveFindings: ComputedRef<Finding[]>
  filteredFindings: ComputedRef<Finding[]>
  topHosts: ComputedRef<HostProfile[]>
  filteredSessions: ComputedRef<TCPSession[]>
  midstreamCount: ComputedRef<number>
  failedHandshakeCount: ComputedRef<number>
}

export function useAnalysisDetail(): UseAnalysisDetailReturn {
  const analysis = ref<AnalysisDetail | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const activeTab = ref<TabName>('overview')

  const findingFilters = ref<FindingFilters>({
    severity: '',
    category: '',
    search: '',
  })

  const conversationFilters = ref<ConversationFilters>({
    handshake: '',
    protocol: '',
    search: '',
  })

  async function fetch(id: string): Promise<void> {
    loading.value = true
    error.value = null
    try {
      const res = await api.get(`/analyses/${id}`)
      analysis.value = res.data as AnalysisDetail
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : 'Failed to load analysis'
    } finally {
      loading.value = false
    }
  }

  // ── Findings ──────────────────────────────────────────────────────────────

  const allActiveFindings = computed<Finding[]>(() =>
    analysis.value?.data?.all_issues ?? []
  )

  const criticalFindings = computed<Finding[]>(() =>
    allActiveFindings.value.filter(f => f.severity === 'critical')
  )

  const warningFindings = computed<Finding[]>(() =>
    allActiveFindings.value.filter(f => f.severity === 'high' || f.severity === 'medium')
  )

  const filteredFindings = computed<Finding[]>(() => {
    let findings = allActiveFindings.value
    const { severity, category, search } = findingFilters.value

    if (severity) findings = findings.filter(f => f.severity === severity)
    if (category) findings = findings.filter(f => f.category === category)
    if (search) {
      const q = search.toLowerCase()
      findings = findings.filter(
        f =>
          f.title.toLowerCase().includes(q) ||
          f.description.toLowerCase().includes(q) ||
          f.explanation?.toLowerCase().includes(q)
      )
    }
    return findings
  })

  // ── Hosts ─────────────────────────────────────────────────────────────────

  const topHosts = computed<HostProfile[]>(() => {
    const hosts = analysis.value?.data?.hosts ?? []
    return [...hosts].sort((a, b) => b.anomaly_score - a.anomaly_score).slice(0, 20)
  })

  // ── TCP Sessions ──────────────────────────────────────────────────────────

  const filteredSessions = computed<TCPSession[]>(() => {
    let sessions = analysis.value?.data?.tcp?.sessions ?? []
    const { handshake, protocol, search } = conversationFilters.value

    if (handshake) sessions = sessions.filter(s => s.handshake_status === handshake)
    if (protocol) {
      const q = protocol.toLowerCase()
      sessions = sessions.filter(s => s.protocol_guess?.toLowerCase().includes(q))
    }
    if (search) {
      const q = search.toLowerCase()
      sessions = sessions.filter(
        s =>
          s.src_ip.includes(q) ||
          s.dst_ip.includes(q) ||
          String(s.dst_port).includes(q)
      )
    }
    return sessions
  })

  const midstreamCount = computed<number>(() =>
    analysis.value?.data?.tcp?.midstream ?? 0
  )

  const failedHandshakeCount = computed<number>(() =>
    analysis.value?.data?.tcp?.failed_handshakes ?? 0
  )

  function navigateTo(tab: string, filters?: Record<string, string>): void {
    activeTab.value = tab as TabName

    if (filters) {
      // Apply to the right filter object based on tab
      if (tab === 'findings' || tab === 'security') {
        if (filters.severity !== undefined) findingFilters.value.severity = filters.severity
        if (filters.category !== undefined) findingFilters.value.category = filters.category
        if (filters.search !== undefined) findingFilters.value.search = filters.search
      } else if (tab === 'conversations') {
        if (filters.handshake !== undefined) conversationFilters.value.handshake = filters.handshake
        if (filters.protocol !== undefined) conversationFilters.value.protocol = filters.protocol
        if (filters.search !== undefined) conversationFilters.value.search = filters.search
      }
    }
  }

  return {
    analysis,
    loading,
    error,
    activeTab,
    findingFilters,
    conversationFilters,
    fetch,
    navigateTo,
    criticalFindings,
    warningFindings,
    allActiveFindings,
    filteredFindings,
    topHosts,
    filteredSessions,
    midstreamCount,
    failedHandshakeCount,
  }
}
