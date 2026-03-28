<template>
  <div class="dashboard">
    <div class="page-header">
      <h2>Dashboard</h2>
      <p>Upload a PCAP file to analyze your network traffic</p>
    </div>

    <!-- Upload Area -->
    <el-card class="upload-card" shadow="never">
      <div
        class="upload-zone"
        :class="{ 'dragging': isDragging, 'uploading': uploading }"
        @dragover.prevent="isDragging = true"
        @dragleave.prevent="isDragging = false"
        @drop.prevent="handleDrop"
        @click="triggerFileInput"
      >
        <input
          ref="fileInput"
          type="file"
          accept=".pcap,.pcapng,.cap"
          style="display: none"
          @change="handleFileSelect"
        />

        <template v-if="!uploading">
          <div class="upload-icon">
            <el-icon size="56" color="#409EFF"><Upload /></el-icon>
          </div>
          <h3>Drop PCAP file here or click to upload</h3>
          <p class="upload-hint">Supports <strong>.pcap</strong>, <strong>.pcapng</strong>, <strong>.cap</strong> files</p>
        </template>

        <template v-else>
          <div class="upload-progress">
            <el-icon size="48" color="#409EFF" class="spinning"><Loading /></el-icon>
            <h3>Analyzing {{ uploadingFilename }}...</h3>
            <p>Running TCP, Security, DNS & HTTP analysis</p>
            <el-progress
              :percentage="uploadProgress"
              :stroke-width="6"
              style="width: 300px; margin-top: 16px"
            />
          </div>
        </template>
      </div>
    </el-card>

    <!-- Analysis Steps Info -->
    <el-card class="steps-card" shadow="never">
      <template #header>
        <span class="card-title">What gets analyzed?</span>
      </template>
      <div class="analysis-steps">
        <div class="step-item">
          <div class="step-icon" style="background: #ecf5ff; color: #409EFF">
            <el-icon size="24"><Connection /></el-icon>
          </div>
          <div class="step-info">
            <h4>TCP/IP Analysis</h4>
            <p>Retransmissions, SYN floods, RST packets, incomplete handshakes</p>
          </div>
        </div>
        <div class="step-item">
          <div class="step-icon" style="background: #fef0f0; color: #F56C6C">
            <el-icon size="24"><Shield /></el-icon>
          </div>
          <div class="step-info">
            <h4>Security Threats</h4>
            <p>Port scans, ARP spoofing, ICMP floods, TCP null/xmas scans, data exfiltration</p>
          </div>
        </div>
        <div class="step-item">
          <div class="step-icon" style="background: #f0f9eb; color: #67C23A">
            <el-icon size="24"><Promotion /></el-icon>
          </div>
          <div class="step-info">
            <h4>DNS Analysis</h4>
            <p>NXDOMAIN responses, DNS tunneling, high query rates, slow responses</p>
          </div>
        </div>
        <div class="step-item">
          <div class="step-icon" style="background: #fdf6ec; color: #E6A23C">
            <el-icon size="24"><Monitor /></el-icon>
          </div>
          <div class="step-info">
            <h4>HTTP/HTTPS Analysis</h4>
            <p>Error codes, cleartext credentials, unencrypted traffic, suspicious user agents</p>
          </div>
        </div>
      </div>
    </el-card>

    <!-- Recent Analyses -->
    <el-card class="recent-card" shadow="never" v-if="recentAnalyses.length > 0">
      <template #header>
        <div class="card-header-row">
          <span class="card-title">Recent Analyses</span>
          <el-button link type="primary" @click="$router.push('/history')">
            View All <el-icon class="el-icon--right"><ArrowRight /></el-icon>
          </el-button>
        </div>
      </template>
      <div class="recent-list">
        <div
          v-for="item in recentAnalyses"
          :key="item.id"
          class="recent-item"
          @click="$router.push(`/analysis/${item.id}`)"
        >
          <div class="recent-icon">
            <el-icon size="20" color="#409EFF"><Document /></el-icon>
          </div>
          <div class="recent-info">
            <div class="recent-name">{{ item.filename }}</div>
            <div class="recent-meta">{{ formatDate(item.created_at) }} · {{ formatSize(item.file_size) }}</div>
          </div>
          <div class="recent-badges">
            <el-tag v-if="item.critical_count > 0" type="danger" size="small" effect="light">
              {{ item.critical_count }} Critical
            </el-tag>
            <el-tag v-if="item.warning_count > 0" type="warning" size="small" effect="light">
              {{ item.warning_count }} Warning
            </el-tag>
            <el-tag v-if="item.critical_count === 0 && item.warning_count === 0" type="success" size="small" effect="light">
              Clean
            </el-tag>
          </div>
          <el-icon color="#c0c4cc"><ArrowRight /></el-icon>
        </div>
      </div>
    </el-card>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import api from '../api'

const router = useRouter()

const fileInput = ref()
const isDragging = ref(false)
const uploading = ref(false)
const uploadProgress = ref(0)
const uploadingFilename = ref('')
const recentAnalyses = ref([])

onMounted(fetchRecent)

async function fetchRecent() {
  try {
    const res = await api.get('/analyses')
    recentAnalyses.value = res.data.slice(0, 5)
  } catch {}
}

function triggerFileInput() {
  if (!uploading.value) fileInput.value?.click()
}

function handleFileSelect(e) {
  const file = e.target.files?.[0]
  if (file) uploadFile(file)
  e.target.value = ''
}

function handleDrop(e) {
  isDragging.value = false
  const file = e.dataTransfer.files?.[0]
  if (file) uploadFile(file)
}

async function uploadFile(file) {
  const ext = file.name.split('.').pop().toLowerCase()
  if (!['pcap', 'pcapng', 'cap'].includes(ext)) {
    ElMessage.error('Only .pcap, .pcapng, .cap files are supported')
    return
  }

  uploading.value = true
  uploadingFilename.value = file.name
  uploadProgress.value = 5

  try {
    // Step 1: upload (fast, returns 202 immediately)
    const formData = new FormData()
    formData.append('file', file)
    const res = await api.post('/analyses', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
    const analysisId = res.data.id
    uploadProgress.value = 15

    // Step 2: poll status until completed or failed
    let pollAttempts = 0
    const maxAttempts = 180   // 3 min @ 1s intervals
    await new Promise((resolve, reject) => {
      const poller = setInterval(async () => {
        pollAttempts++
        if (pollAttempts > maxAttempts) {
          clearInterval(poller)
          reject(new Error('Analysis timed out'))
          return
        }
        try {
          const statusRes = await api.get(`/analyses/${analysisId}/status`)
          const status = statusRes.data.status
          // Smooth progress: pending=15-30, running=30-90, completed=100
          if (status === 'pending') {
            uploadProgress.value = Math.min(30, uploadProgress.value + 1)
          } else if (status === 'running') {
            uploadProgress.value = Math.min(92, uploadProgress.value + 0.8)
          } else if (status === 'completed') {
            clearInterval(poller)
            uploadProgress.value = 100
            resolve()
          } else if (status === 'failed') {
            clearInterval(poller)
            reject(new Error(statusRes.data.error || 'Analysis failed'))
          }
        } catch (e) {
          // ignore transient poll errors
        }
      }, 1000)
    })

    ElMessage.success('Analysis complete!')
    await fetchRecent()
    setTimeout(() => router.push(`/analysis/${analysisId}`), 400)

  } catch (err) {
    const msg = err.message || err.response?.data?.detail || 'Upload or analysis failed'
    ElMessage.error(msg)
  } finally {
    uploading.value = false
    uploadProgress.value = 0
  }
}

function formatDate(dateStr) {
  return new Date(dateStr).toLocaleString()
}

function formatSize(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}
</script>

<style scoped>
.dashboard {
  max-width: 900px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 24px;
}

.page-header h2 {
  font-size: 24px;
  font-weight: 700;
  color: #1a1a2e;
  margin-bottom: 6px;
}

.page-header p {
  color: #909399;
  font-size: 14px;
}

.upload-card, .steps-card, .recent-card {
  margin-bottom: 20px;
  border-radius: 12px;
  border: 1px solid #e4e7ed;
}

.upload-zone {
  border: 2px dashed #d0d7de;
  border-radius: 12px;
  padding: 48px 24px;
  text-align: center;
  cursor: pointer;
  transition: all 0.3s;
}

.upload-zone:hover, .upload-zone.dragging {
  border-color: #409EFF;
  background: #f0f7ff;
}

.upload-zone.uploading {
  cursor: default;
  border-color: #409EFF;
  background: #f0f7ff;
}

.upload-icon {
  margin-bottom: 16px;
}

.upload-zone h3 {
  font-size: 16px;
  color: #303133;
  margin-bottom: 8px;
  font-weight: 600;
}

.upload-hint {
  font-size: 13px;
  color: #909399;
}

.upload-progress {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}

.upload-progress h3 {
  font-size: 16px;
  color: #303133;
  font-weight: 600;
}

.upload-progress p {
  font-size: 13px;
  color: #909399;
}

.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.card-title {
  font-size: 15px;
  font-weight: 600;
  color: #303133;
}

.card-header-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.analysis-steps {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.step-item {
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 16px;
  background: #fafafa;
  border-radius: 10px;
  border: 1px solid #f0f0f0;
}

.step-icon {
  width: 48px;
  height: 48px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.step-info h4 {
  font-size: 14px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 4px;
}

.step-info p {
  font-size: 12px;
  color: #909399;
  line-height: 1.5;
}

.recent-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.recent-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  border-radius: 8px;
  cursor: pointer;
  transition: background 0.2s;
}

.recent-item:hover {
  background: #f5f7fa;
}

.recent-icon {
  width: 40px;
  height: 40px;
  border-radius: 8px;
  background: #ecf5ff;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.recent-info {
  flex: 1;
  min-width: 0;
}

.recent-name {
  font-size: 14px;
  font-weight: 500;
  color: #303133;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.recent-meta {
  font-size: 12px;
  color: #909399;
  margin-top: 2px;
}

.recent-badges {
  display: flex;
  gap: 6px;
}
</style>
