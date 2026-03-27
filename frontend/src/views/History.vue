<template>
  <div class="history-page">
    <div class="page-header">
      <div>
        <h2>Analysis History</h2>
        <p>All PCAP files you've analyzed</p>
      </div>
      <el-button type="primary" @click="$router.push('/')">
        <el-icon><Upload /></el-icon>
        New Analysis
      </el-button>
    </div>

    <!-- Search -->
    <el-card class="filter-card" shadow="never">
      <el-input
        v-model="searchQuery"
        placeholder="Search by filename..."
        :prefix-icon="Search"
        clearable
        style="max-width: 400px"
      />
    </el-card>

    <!-- Table -->
    <el-card shadow="never" style="border-radius: 12px; border: 1px solid #e4e7ed">
      <el-table
        v-loading="loading"
        :data="filteredList"
        style="width: 100%"
        row-class-name="table-row"
        @row-click="openAnalysis"
      >
        <el-table-column label="File" min-width="220">
          <template #default="{ row }">
            <div class="file-cell">
              <el-icon color="#409EFF"><Document /></el-icon>
              <div>
                <div class="filename">{{ row.filename }}</div>
                <div class="filesize">{{ formatSize(row.file_size) }}</div>
              </div>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="Status" width="130">
          <template #default="{ row }">
            <el-tag :type="statusType(row)" size="small" effect="light">
              {{ row.status }}
            </el-tag>
          </template>
        </el-table-column>

        <el-table-column label="Findings" width="230">
          <template #default="{ row }">
            <div v-if="row.status === 'completed'" class="findings-cell">
              <el-tag v-if="row.critical_count > 0" type="danger" size="small" effect="light">
                {{ row.critical_count }} Critical
              </el-tag>
              <el-tag v-if="row.warning_count > 0" type="warning" size="small" effect="light">
                {{ row.warning_count }} Warning
              </el-tag>
              <el-tag v-if="row.info_count > 0" type="info" size="small" effect="light">
                {{ row.info_count }} Info
              </el-tag>
              <el-tag v-if="row.critical_count === 0 && row.warning_count === 0 && row.info_count === 0" type="success" size="small" effect="light">
                Clean
              </el-tag>
            </div>
            <span v-else class="no-data">—</span>
          </template>
        </el-table-column>

        <el-table-column label="Packets" width="110">
          <template #default="{ row }">
            <span v-if="row.total_packets">{{ row.total_packets.toLocaleString() }}</span>
            <span v-else class="no-data">—</span>
          </template>
        </el-table-column>

        <el-table-column label="Date" width="180">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>

        <el-table-column label="" width="80" align="center">
          <template #default="{ row }">
            <el-dropdown trigger="click" @command="(cmd) => handleCommand(cmd, row)">
              <el-button link>
                <el-icon size="18"><MoreFilled /></el-icon>
              </el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item command="view" :disabled="row.status !== 'completed'">
                    <el-icon><View /></el-icon> View
                  </el-dropdown-item>
                  <el-dropdown-item command="delete" divided>
                    <el-icon color="#F56C6C"><Delete /></el-icon>
                    <span style="color: #F56C6C">Delete</span>
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </template>
        </el-table-column>
      </el-table>

      <el-empty v-if="!loading && filteredList.length === 0" description="No analyses found" :image-size="80" />
    </el-card>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import api from '../api'

const router = useRouter()

const loading = ref(true)
const list = ref([])
const searchQuery = ref('')

onMounted(fetchList)

async function fetchList() {
  loading.value = true
  try {
    const res = await api.get('/analyses')
    list.value = res.data
  } catch {
    ElMessage.error('Failed to load history')
  } finally {
    loading.value = false
  }
}

const filteredList = computed(() => {
  if (!searchQuery.value) return list.value
  const q = searchQuery.value.toLowerCase()
  return list.value.filter(a => a.filename.toLowerCase().includes(q))
})

function openAnalysis(row) {
  if (row.status === 'completed') {
    router.push(`/analysis/${row.id}`)
  }
}

function handleCommand(cmd, row) {
  if (cmd === 'view') {
    router.push(`/analysis/${row.id}`)
  } else if (cmd === 'delete') {
    deleteAnalysis(row)
  }
}

async function deleteAnalysis(row) {
  try {
    await ElMessageBox.confirm(
      `Delete analysis for "${row.filename}"? This cannot be undone.`,
      'Confirm Delete',
      { type: 'warning', confirmButtonText: 'Delete', confirmButtonClass: 'el-button--danger' }
    )
    await api.delete(`/analyses/${row.id}`)
    list.value = list.value.filter(a => a.id !== row.id)
    ElMessage.success('Deleted successfully')
  } catch {}
}

function statusType(row) {
  return { completed: 'success', failed: 'danger', running: 'warning', pending: 'info' }[row.status] || 'info'
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
.history-page {
  max-width: 1000px;
  margin: 0 auto;
}

.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
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

.filter-card {
  margin-bottom: 16px;
  border-radius: 12px;
  border: 1px solid #e4e7ed;
}

.file-cell {
  display: flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
}

.filename {
  font-size: 14px;
  font-weight: 500;
  color: #303133;
}

.filesize {
  font-size: 12px;
  color: #909399;
}

.findings-cell {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}

.no-data {
  color: #c0c4cc;
}

:deep(.table-row) {
  cursor: pointer;
}

:deep(.table-row:hover td) {
  background: #f5f7fa !important;
}
</style>
