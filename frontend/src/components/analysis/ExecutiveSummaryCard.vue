<template>
  <!-- Capture quality warning banner -->
  <el-alert
    v-if="assessment && assessment.quality !== 'good'"
    :type="assessment.quality === 'poor' ? 'error' : 'warning'"
    :closable="false"
    show-icon
    class="quality-banner"
  >
    <template #title>
      <strong>Capture Quality: {{ assessment.quality_label }}</strong>
    </template>
    <ul class="issue-list">
      <li v-for="(issue, i) in assessment.issues" :key="i">{{ issue }}</li>
    </ul>
  </el-alert>

  <!-- Bullet summary -->
  <el-card shadow="never" class="summary-card">
    <template #header>
      <span class="card-title">What happened in this capture</span>
    </template>
    <ul class="bullet-list" v-if="bullets.length">
      <li v-for="(b, i) in bullets" :key="i" class="bullet-item">
        <el-icon class="bullet-icon"><InfoFilled /></el-icon>
        <span>{{ b }}</span>
      </li>
    </ul>
    <p v-else-if="executiveSummary" class="summary-text">{{ executiveSummary }}</p>
    <el-empty v-else description="No summary available" :image-size="40" />
  </el-card>

  <!-- Key stats row -->
  <div class="stats-row">
    <div class="stat-chip">
      <div class="stat-value">{{ formatNum(fileInfo.total_packets) }}</div>
      <div class="stat-label">Total Packets</div>
    </div>
    <div class="stat-chip">
      <div class="stat-value">{{ formatBytes(fileInfo.file_size_bytes) }}</div>
      <div class="stat-label">File Size</div>
    </div>
    <div class="stat-chip">
      <div class="stat-value">{{ formatDuration(fileInfo.duration_sec) }}</div>
      <div class="stat-label">Duration</div>
    </div>
    <div class="stat-chip" v-if="issueCounts">
      <div class="stat-value" :style="{ color: issueCounts.critical > 0 ? '#f56c6c' : '#67c23a' }">
        {{ issueCounts.critical }}
      </div>
      <div class="stat-label">Critical Issues</div>
    </div>
    <div class="stat-chip" v-if="tcpStats">
      <div class="stat-value" :style="{ color: tcpStats.midstream > 0 ? '#e6a23c' : '#67c23a' }">
        {{ tcpStats.midstream }} / {{ tcpStats.total_sessions }}
      </div>
      <div class="stat-label">Mid-stream Sessions</div>
    </div>
    <div class="stat-chip">
      <div class="stat-value">{{ analysisTimeSec }}s</div>
      <div class="stat-label">Analysis Time</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { InfoFilled } from '@element-plus/icons-vue'
import type { CaptureAssessment, FileInfo, TCPStats } from '@/types/analysis'

defineProps<{
  bullets: string[]
  executiveSummary: string
  assessment: CaptureAssessment | null
  fileInfo: FileInfo
  issueCounts: { critical: number; total: number } | null
  tcpStats: Pick<TCPStats, 'total_sessions' | 'midstream'> | null
  analysisTimeSec: number
}>()

function formatNum(n: number): string {
  return Number(n ?? 0).toLocaleString()
}

function formatBytes(b: number): string {
  if (!b) return '0 B'
  if (b < 1024) return b + ' B'
  if (b < 1024 ** 2) return (b / 1024).toFixed(1) + ' KB'
  if (b < 1024 ** 3) return (b / 1024 ** 2).toFixed(1) + ' MB'
  return (b / 1024 ** 3).toFixed(2) + ' GB'
}

function formatDuration(s: number): string {
  if (!s) return '0s'
  if (s < 60) return s.toFixed(1) + 's'
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}
</script>

<style scoped>
.quality-banner { margin-bottom: 12px; }
.issue-list { margin: 6px 0 0; padding-left: 18px; font-size: 13px; line-height: 1.8; }

.summary-card { margin-bottom: 16px; }
.card-title { font-weight: 600; font-size: 14px; }

.bullet-list { list-style: none; margin: 0; padding: 0; }
.bullet-item {
  display: flex; align-items: flex-start; gap: 8px;
  padding: 6px 0; border-bottom: 1px solid #f0f0f0; font-size: 14px; line-height: 1.7;
}
.bullet-item:last-child { border-bottom: none; }
.bullet-icon { color: #409eff; margin-top: 3px; flex-shrink: 0; }
.summary-text { font-size: 14px; line-height: 1.8; color: #303133; margin: 0; }

.stats-row {
  display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px;
}
.stat-chip {
  background: #fff; border: 1px solid #ebeef5; border-radius: 6px;
  padding: 12px 18px; text-align: center; min-width: 110px;
}
.stat-value { font-size: 20px; font-weight: 700; color: #303133; }
.stat-label { font-size: 11px; color: #909399; margin-top: 4px; }
</style>
