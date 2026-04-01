<template>
  <div class="suppressions-view">
    <div class="page-header">
      <h2>Suppression Rules</h2>
      <p class="page-desc">
        Rules applied globally at analysis time. Matching findings are marked as suppressed but remain visible.
      </p>
    </div>

    <!-- Create form -->
    <el-card class="create-card">
      <template #header>
        <span class="card-label">Add Rule</span>
      </template>
      <el-form :model="form" inline @submit.prevent="createRule">
        <el-form-item label="Rule ID">
          <el-input v-model="form.rule_id" placeholder="e.g. SCAN-001" clearable style="width:140px" />
        </el-form-item>
        <el-form-item label="Src IP">
          <el-input v-model="form.src_ip" placeholder="192.168.1.10" clearable style="width:150px" />
        </el-form-item>
        <el-form-item label="Dst IP">
          <el-input v-model="form.dst_ip" placeholder="10.0.0.1" clearable style="width:150px" />
        </el-form-item>
        <el-form-item label="Reason">
          <el-input v-model="form.reason" placeholder="Known scanner, test host…" style="width:240px" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" native-type="submit" :loading="creating">Add</el-button>
        </el-form-item>
      </el-form>
      <el-alert v-if="createError" type="error" :title="createError" :closable="false" style="margin-top:8px" />
    </el-card>

    <!-- Rules table -->
    <el-card class="rules-card">
      <template #header>
        <span class="card-label">Active Rules ({{ rules.length }})</span>
      </template>
      <div v-if="loading" class="loading-row">
        <el-icon class="is-loading"><Loading /></el-icon> Loading…
      </div>
      <div v-else-if="!rules.length" class="empty-msg">No suppression rules defined.</div>
      <el-table v-else :data="rules" size="small">
        <el-table-column label="Rule ID" width="120">
          <template #default="{ row }">
            <el-tag v-if="row.rule_id" size="small" type="warning">{{ row.rule_id }}</el-tag>
            <span v-else class="any-label">any</span>
          </template>
        </el-table-column>
        <el-table-column label="Src IP" width="150">
          <template #default="{ row }">
            <code v-if="row.src_ip">{{ row.src_ip }}</code>
            <span v-else class="any-label">any</span>
          </template>
        </el-table-column>
        <el-table-column label="Dst IP" width="150">
          <template #default="{ row }">
            <code v-if="row.dst_ip">{{ row.dst_ip }}</code>
            <span v-else class="any-label">any</span>
          </template>
        </el-table-column>
        <el-table-column label="Reason" prop="reason" min-width="200" />
        <el-table-column label="Created" width="170">
          <template #default="{ row }">{{ fmtDate(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="" width="80" align="right">
          <template #default="{ row }">
            <el-button
              size="small" type="danger" plain
              :loading="deleting === row.id"
              @click="deleteRule(row.id)"
            >Remove</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card class="info-card">
      <div class="info-text">
        <strong>How rules work:</strong>
        A finding is suppressed if <em>all</em> non-null fields match.
        Rule ID matches the finding's rule identifier (e.g. <code>SCAN-001</code>).
        Src/Dst IP match the finding's affected hosts.
        Suppressed findings remain in analysis results but are excluded from counts.
        Rules take effect on the <em>next</em> analysis run — existing results are not retroactively altered.
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { Loading } from '@element-plus/icons-vue'
import api from '@/api'
import type { SuppressionRule } from '@/types/analysis'

const rules = ref<SuppressionRule[]>([])
const loading = ref(false)
const creating = ref(false)
const deleting = ref<number | null>(null)
const createError = ref('')

const form = ref({
  rule_id: '',
  src_ip: '',
  dst_ip: '',
  reason: '',
})

async function fetchRules() {
  loading.value = true
  try {
    const res = await api.get('/suppressions')
    rules.value = res.data
  } catch (e) {
    console.error('Failed to load suppression rules', e)
  } finally {
    loading.value = false
  }
}

async function createRule() {
  createError.value = ''
  const payload = {
    rule_id: form.value.rule_id || null,
    src_ip: form.value.src_ip || null,
    dst_ip: form.value.dst_ip || null,
    reason: form.value.reason,
  }
  if (!payload.rule_id && !payload.src_ip && !payload.dst_ip) {
    createError.value = 'At least one of Rule ID, Src IP, or Dst IP must be filled in.'
    return
  }
  creating.value = true
  try {
    const res = await api.post('/suppressions', payload)
    rules.value.unshift(res.data)
    form.value = { rule_id: '', src_ip: '', dst_ip: '', reason: '' }
  } catch (e: any) {
    createError.value = e.response?.data?.detail || 'Failed to create rule.'
  } finally {
    creating.value = false
  }
}

async function deleteRule(id: number) {
  deleting.value = id
  try {
    await api.delete(`/suppressions/${id}`)
    rules.value = rules.value.filter(r => r.id !== id)
  } catch (e) {
    console.error('Failed to delete rule', e)
  } finally {
    deleting.value = null
  }
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

onMounted(fetchRules)
</script>

<style scoped>
.suppressions-view { max-width: 1000px; margin: 0 auto; padding: 24px 16px; display: flex; flex-direction: column; gap: 16px; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.page-desc { margin: 0; color: #606266; font-size: 13px; }
.card-label { font-weight: 600; font-size: 14px; }
.any-label { color: #909399; font-style: italic; font-size: 12px; }
.loading-row { display: flex; align-items: center; gap: 8px; color: #909399; padding: 16px 0; }
.empty-msg { color: #909399; padding: 16px 0; font-size: 13px; }
code { background: #f5f7fa; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
.info-card { background: #f4f4f5; }
.info-text { font-size: 13px; color: #606266; line-height: 1.8; }
.info-text code { background: #e4e7ed; }
</style>
