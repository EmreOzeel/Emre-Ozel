<template>
  <div class="suppressions-view">
    <div class="page-header">
      <h2>Suppression Rules</h2>
      <p class="page-desc">
        Rules suppress matching findings at analysis time. Suppressed findings remain visible
        but are excluded from counts. Global rules require admin privileges.
      </p>
    </div>

    <!-- Create form -->
    <el-card class="create-card">
      <template #header><span class="card-label">Add Rule</span></template>
      <el-form :model="form" label-width="90px" @submit.prevent="createRule">
        <el-row :gutter="12">
          <el-col :span="6">
            <el-form-item label="Scope">
              <el-select v-model="form.scope" style="width:100%">
                <el-option value="user" label="User (mine only)" />
                <el-option value="global" label="Global (all users)" :disabled="!isAdmin" />
                <el-option value="analysis" label="Analysis (one run)" />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="6">
            <el-form-item label="Rule ID">
              <el-input v-model="form.rule_id" placeholder="SCAN-001" clearable />
            </el-form-item>
          </el-col>
          <el-col :span="6">
            <el-form-item label="Src IP">
              <el-input v-model="form.src_ip" placeholder="192.168.1.5" clearable />
            </el-form-item>
          </el-col>
          <el-col :span="6">
            <el-form-item label="Dst IP">
              <el-input v-model="form.dst_ip" placeholder="10.0.0.1" clearable />
            </el-form-item>
          </el-col>
        </el-row>
        <el-row :gutter="12">
          <el-col :span="12">
            <el-form-item label="Reason">
              <el-input v-model="form.reason" placeholder="Known scanner, test host, authorized scan…" />
            </el-form-item>
          </el-col>
          <el-col :span="8">
            <el-form-item label="Expires">
              <el-date-picker
                v-model="form.expires_at"
                type="datetime"
                placeholder="Never (leave blank)"
                style="width:100%"
              />
            </el-form-item>
          </el-col>
          <el-col :span="4" style="display:flex;align-items:flex-end;padding-bottom:18px">
            <el-button type="primary" native-type="submit" :loading="creating" style="width:100%">Add</el-button>
          </el-col>
        </el-row>
      </el-form>
      <el-alert v-if="createError" type="error" :title="createError" :closable="false" style="margin-top:4px" />
    </el-card>

    <!-- Rules table -->
    <el-card class="rules-card">
      <template #header>
        <div style="display:flex;align-items:center;gap:12px">
          <span class="card-label">Active Rules ({{ rules.length }})</span>
          <el-select v-model="scopeFilter" size="small" clearable placeholder="All scopes" style="width:140px">
            <el-option value="global" label="Global" />
            <el-option value="user" label="User" />
            <el-option value="analysis" label="Analysis" />
          </el-select>
        </div>
      </template>

      <div v-if="loading" class="loading-row">
        <el-icon class="is-loading"><Loading /></el-icon> Loading…
      </div>
      <div v-else-if="!filteredRules.length" class="empty-msg">No suppression rules defined.</div>

      <el-table v-else :data="filteredRules" size="small">
        <el-table-column label="Scope" width="100">
          <template #default="{ row }">
            <el-tag
              :type="row.scope === 'global' ? 'danger' : row.scope === 'user' ? 'info' : ''"
              size="small" effect="plain"
            >{{ row.scope }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Rule ID" width="110">
          <template #default="{ row }">
            <el-tag v-if="row.rule_id" size="small" type="warning">{{ row.rule_id }}</el-tag>
            <span v-else class="any-label">any</span>
          </template>
        </el-table-column>
        <el-table-column label="Src IP" width="140">
          <template #default="{ row }">
            <code v-if="row.src_ip">{{ row.src_ip }}</code>
            <span v-else class="any-label">any</span>
          </template>
        </el-table-column>
        <el-table-column label="Dst IP" width="140">
          <template #default="{ row }">
            <code v-if="row.dst_ip">{{ row.dst_ip }}</code>
            <span v-else class="any-label">any</span>
          </template>
        </el-table-column>
        <el-table-column label="Reason" prop="reason" min-width="160" />
        <el-table-column label="Expires" width="140">
          <template #default="{ row }">
            <span v-if="row.expires_at" :class="isExpired(row.expires_at) ? 'expired' : ''">
              {{ fmtDate(row.expires_at) }}
              <el-tag v-if="isExpired(row.expires_at)" size="small" type="danger" effect="plain" style="margin-left:4px">expired</el-tag>
            </span>
            <span v-else class="any-label">never</span>
          </template>
        </el-table-column>
        <el-table-column label="Active" width="72" align="center">
          <template #default="{ row }">
            <el-switch
              :model-value="row.is_active"
              size="small"
              @change="toggleRule(row)"
            />
          </template>
        </el-table-column>
        <el-table-column label="" width="80" align="right">
          <template #default="{ row }">
            <el-button
              size="small" type="danger" plain
              :loading="deleting === row.id"
              @click="deleteRule(row.id)"
            >Del</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card class="info-card">
      <div class="info-text">
        <strong>Matching logic:</strong> All non-null fields must match (AND).
        <strong>Scope:</strong> <code>user</code> applies only to your analyses;
        <code>global</code> applies to all users (admin only);
        <code>analysis</code> scopes to a single run.
        <strong>Effect:</strong> Rules apply to the <em>next analysis run</em> — existing results are not altered.
        Expired or inactive rules are skipped automatically.
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { Loading } from '@element-plus/icons-vue'
import api from '@/api'
import { useAuthStore } from '@/stores/auth'
import type { SuppressionRule } from '@/types/analysis'

const auth = useAuthStore()
const isAdmin = computed(() => (auth.user as any)?.is_admin ?? false)

const rules = ref<SuppressionRule[]>([])
const loading = ref(false)
const creating = ref(false)
const deleting = ref<number | null>(null)
const createError = ref('')
const scopeFilter = ref('')

const form = ref({
  scope: 'user' as 'user' | 'global' | 'analysis',
  rule_id: '',
  src_ip: '',
  dst_ip: '',
  reason: '',
  expires_at: null as Date | null,
})

const filteredRules = computed(() => {
  if (!scopeFilter.value) return rules.value
  return rules.value.filter(r => r.scope === scopeFilter.value)
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
    scope: form.value.scope,
    rule_id: form.value.rule_id || null,
    src_ip: form.value.src_ip || null,
    dst_ip: form.value.dst_ip || null,
    reason: form.value.reason,
    expires_at: form.value.expires_at ? (form.value.expires_at as Date).toISOString() : null,
  }
  if (!payload.rule_id && !payload.src_ip && !payload.dst_ip) {
    createError.value = 'At least one of Rule ID, Src IP, or Dst IP is required.'
    return
  }
  creating.value = true
  try {
    const res = await api.post('/suppressions', payload)
    rules.value.unshift(res.data)
    form.value = { scope: 'user', rule_id: '', src_ip: '', dst_ip: '', reason: '', expires_at: null }
  } catch (e: any) {
    createError.value = e.response?.data?.detail || 'Failed to create rule.'
  } finally {
    creating.value = false
  }
}

async function toggleRule(rule: SuppressionRule) {
  try {
    const res = await api.patch(`/suppressions/${rule.id}`)
    const idx = rules.value.findIndex(r => r.id === rule.id)
    if (idx !== -1) rules.value[idx] = res.data
  } catch (e) {
    console.error('Failed to toggle rule', e)
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

function isExpired(iso: string | null): boolean {
  if (!iso) return false
  return new Date(iso) < new Date()
}

onMounted(fetchRules)
</script>

<style scoped>
.suppressions-view { max-width: 1100px; margin: 0 auto; padding: 24px 16px; display: flex; flex-direction: column; gap: 16px; }
.page-header h2 { margin: 0 0 4px; font-size: 20px; }
.page-desc { margin: 0; color: #606266; font-size: 13px; }
.card-label { font-weight: 600; font-size: 14px; }
.any-label { color: #c0c4cc; font-style: italic; font-size: 12px; }
.loading-row { display: flex; align-items: center; gap: 8px; color: #909399; padding: 16px 0; }
.empty-msg { color: #909399; padding: 16px 0; font-size: 13px; }
code { background: #f5f7fa; padding: 1px 5px; border-radius: 3px; font-size: 12px; }
.expired { color: #f56c6c; }
.info-card { background: #f4f4f5; }
.info-text { font-size: 13px; color: #606266; line-height: 1.8; }
.info-text code { background: #e4e7ed; }
</style>
