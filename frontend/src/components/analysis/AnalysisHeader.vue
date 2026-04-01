<template>
  <div class="analysis-header">
    <div class="header-left">
      <el-button :icon="ArrowLeft" text @click="$router.back()">Back</el-button>
      <div class="title-block">
        <h2>{{ analysis.filename }}</h2>
        <div class="meta">
          <el-tag :type="statusType" size="small">{{ analysis.status }}</el-tag>
          <span class="meta-item" v-if="data?.file_info?.total_packets">
            {{ formatNum(data.file_info.total_packets) }} packets
          </span>
          <span class="meta-item" v-if="data?.file_info?.duration_sec">
            {{ formatDuration(data.file_info.duration_sec) }}
          </span>
          <span class="meta-item">
            {{ analysis.created_at?.substring(0, 16).replace('T', ' ') }}
          </span>
        </div>
      </div>
    </div>

    <div class="header-right">
      <!-- Capture quality badge -->
      <el-tag
        v-if="data?.capture_assessment"
        :type="qualityTagType"
        size="small"
        effect="plain"
      >
        Capture: {{ data.capture_assessment.quality_label }}
      </el-tag>

      <!-- Finding counts -->
      <template v-if="data?.issue_counts">
        <el-tag type="danger" effect="dark" v-if="data.issue_counts.critical > 0">
          {{ data.issue_counts.critical }} Critical
        </el-tag>
        <el-tag type="warning" effect="dark" v-if="data.issue_counts.warning > 0">
          {{ data.issue_counts.warning }} Warning
        </el-tag>
        <el-tag type="success" v-if="data.issue_counts.total === 0">
          Clean
        </el-tag>
      </template>

      <!-- Export actions -->
      <template v-if="analysis.status === 'completed'">
        <el-button size="small" plain :icon="Download" @click="downloadReport">Report</el-button>
        <el-button size="small" plain :icon="Download" @click="downloadJson">JSON</el-button>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { ArrowLeft, Download } from '@element-plus/icons-vue'
import api from '@/api'
import type { AnalysisDetail, AnalysisData } from '@/types/analysis'

const props = defineProps<{
  analysis: AnalysisDetail
  data: AnalysisData | null
}>()

const statusType = computed(() => {
  const s = props.analysis.status
  if (s === 'completed') return 'success'
  if (s === 'failed') return 'danger'
  if (s === 'running') return 'warning'
  return 'info'
})

const qualityTagType = computed(() => {
  const q = props.data?.capture_assessment?.quality
  if (q === 'good') return 'success'
  if (q === 'partial') return 'warning'
  if (q === 'poor') return 'danger'
  return 'info'
})

function formatNum(n: number): string {
  return Number(n).toLocaleString()
}

function formatDuration(s: number): string {
  if (s < 60) return s.toFixed(1) + 's'
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}

async function downloadReport() {
  const res = await api.get(`/analyses/${props.analysis.id}/report`, { responseType: 'blob' })
  const url = URL.createObjectURL(res.data)
  const a = document.createElement('a')
  a.href = url
  a.download = `${props.analysis.filename}_report.html`
  a.click()
  URL.revokeObjectURL(url)
}

async function downloadJson() {
  const res = await api.get(`/analyses/${props.analysis.id}/export`, { responseType: 'blob' })
  const url = URL.createObjectURL(res.data)
  const a = document.createElement('a')
  a.href = url
  a.download = `${props.analysis.filename}_analysis.json`
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<style scoped>
.analysis-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 16px;
  flex-wrap: wrap;
  gap: 12px;
}
.header-left { display: flex; align-items: flex-start; gap: 12px; }
.title-block h2 { margin: 0 0 6px; font-size: 18px; }
.meta { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.meta-item { font-size: 13px; color: #606266; }
.header-right { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
</style>
