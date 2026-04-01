<template>
  <div class="analysis-detail" v-loading="loading">
    <!-- Error state -->
    <el-alert v-if="error" type="error" :title="error" show-icon :closable="false" />

    <!-- Loading placeholder -->
    <template v-else-if="loading">
      <el-skeleton :rows="8" animated />
    </template>

    <template v-else-if="analysis">
      <!-- Header always visible for any non-loading, non-network-error state -->
      <AnalysisHeader :analysis="analysis" :data="analysis.data" />

      <!-- Analysis job failed — show friendly classified error -->
      <el-alert
        v-if="analysisFailure"
        type="error"
        :title="analysisFailure.title"
        show-icon
        :closable="false"
        style="margin-bottom: 16px"
      >
        <template #default>
          <p style="margin: 4px 0 0">{{ analysisFailure.message }}</p>
          <p style="margin: 6px 0 0; color: #909399; font-size: 13px">{{ analysisFailure.hint }}</p>
        </template>
      </el-alert>

      <!-- Still running / pending with no data yet -->
      <el-empty
        v-else-if="!analysis.data"
        description="Analysis is not yet complete or produced no data."
      />

      <template v-else>
        <!-- Investigation entry point — shown first when there are critical items -->
        <StartHerePanel
          :findings="allActiveFindings"
          :hosts="topHosts"
          :tcp-stats="analysis.data.tcp ?? null"
          @navigate="handleNavigate"
        />

        <!-- Executive summary + stats always visible above tabs -->
        <ExecutiveSummaryCard
          :bullets="analysis.data.bullet_summary ?? []"
          :executive-summary="analysis.data.executive_summary ?? ''"
          :assessment="analysis.data.capture_assessment ?? null"
          :file-info="analysis.data.file_info"
          :issue-counts="analysis.data.issue_counts ?? null"
          :tcp-stats="analysis.data.tcp ?? null"
          :analysis-time-sec="analysis.data.analysis_time_sec ?? 0"
        />

        <!-- Main tab navigation -->
        <el-tabs v-model="activeTab" type="border-card" class="main-tabs">

          <!-- Findings (all) -->
          <el-tab-pane label="Findings" name="findings">
            <FindingsPanel
              :findings="allActiveFindings"
              :filters="findingFilters"
            />
          </el-tab-pane>

          <!-- Hosts -->
          <el-tab-pane label="Hosts" name="hosts">
            <div class="host-grid">
              <HostProfileCard
                v-for="h in topHosts"
                :key="h.ip"
                :host="h"
              />
              <el-empty
                v-if="!topHosts.length"
                description="No host profiles available"
              />
            </div>
          </el-tab-pane>

          <!-- Conversations -->
          <el-tab-pane label="Conversations" name="conversations">
            <ConversationsTab
              :sessions="filteredSessions"
              :stats="analysis.data.tcp"
              :filters="conversationFilters"
            />
          </el-tab-pane>

          <!-- Protocols -->
          <el-tab-pane label="Protocols" name="protocols">
            <ProtocolsTab
              :protocol-stats="analysis.data.protocol_stats ?? {}"
              :total-packets="analysis.data.file_info?.total_packets ?? 0"
            />
          </el-tab-pane>

          <!-- DNS -->
          <el-tab-pane label="DNS" name="dns">
            <DnsTab :dns="analysis.data.dns ?? null" />
          </el-tab-pane>

          <!-- Web -->
          <el-tab-pane label="Web" name="web">
            <WebTab :http="analysis.data.http ?? null" />
          </el-tab-pane>

          <!-- TLS -->
          <el-tab-pane label="TLS" name="tls">
            <TlsTab :tls="analysis.data.tls ?? null" />
          </el-tab-pane>

          <!-- TCP Issues -->
          <el-tab-pane label="TCP Issues" name="tcp">
            <TcpIssuesTab :tcp="analysis.data.tcp ?? null" />
          </el-tab-pane>

          <!-- Security Findings -->
          <el-tab-pane label="Security" name="security">
            <SecurityFindingsTab :findings="allActiveFindings" />
          </el-tab-pane>

          <!-- Timeline -->
          <el-tab-pane label="Timeline" name="timeline">
            <TimelineTab :events="analysis.data.timeline ?? []" />
          </el-tab-pane>

          <!-- Expert Info -->
          <el-tab-pane label="Expert Info" name="expert">
            <ExpertInfoTab
              :assessment="analysis.data.capture_assessment ?? null"
              :expert-info="analysis.data.expert_info ?? []"
            />
          </el-tab-pane>

        </el-tabs>
      </template>
    </template>

    <el-empty v-else description="Analysis not found" />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useAnalysisDetail } from '@/composables/useAnalysisDetail'
import { classifyAnalysisError } from '@/utils/analysisErrors'

// Components
import AnalysisHeader      from '@/components/analysis/AnalysisHeader.vue'
import StartHerePanel      from '@/components/analysis/StartHerePanel.vue'
import ExecutiveSummaryCard from '@/components/analysis/ExecutiveSummaryCard.vue'
import FindingsPanel       from '@/components/analysis/FindingsPanel.vue'
import HostProfileCard     from '@/components/analysis/HostProfileCard.vue'
import ConversationsTab    from '@/components/analysis/ConversationsTab.vue'
import ProtocolsTab        from '@/components/analysis/ProtocolsTab.vue'
import DnsTab              from '@/components/analysis/DnsTab.vue'
import WebTab              from '@/components/analysis/WebTab.vue'
import TlsTab              from '@/components/analysis/TlsTab.vue'
import TcpIssuesTab        from '@/components/analysis/TcpIssuesTab.vue'
import SecurityFindingsTab from '@/components/analysis/SecurityFindingsTab.vue'
import TimelineTab         from '@/components/analysis/TimelineTab.vue'
import ExpertInfoTab       from '@/components/analysis/ExpertInfoTab.vue'

const route = useRoute()

const {
  analysis, loading, error, activeTab,
  findingFilters, conversationFilters,
  fetch, navigateTo,
  allActiveFindings, topHosts,
  filteredSessions,
} = useAnalysisDetail()

onMounted(() => fetch(route.params.id as string))

function handleNavigate(tab: string, filters?: Record<string, string>) {
  navigateTo(tab, filters)
  // Scroll tabs into view
  setTimeout(() => {
    document.querySelector('.main-tabs')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, 50)
}

// When the analysis job itself failed, map the raw error to a friendly message.
// This is separate from `error` (which is set only on network/fetch failures).
const analysisFailure = computed(() => {
  if (!analysis.value || analysis.value.status !== 'failed') return null
  return classifyAnalysisError(analysis.value.error)
})
</script>

<style scoped>
.analysis-detail { padding: 20px; }
.main-tabs :deep(.el-tabs__content) { padding: 16px; }
.host-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 12px;
}
</style>
