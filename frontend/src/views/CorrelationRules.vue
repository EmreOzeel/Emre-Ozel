<template>
  <div class="correlation-rules-page">
    <!-- Header bar -->
    <div class="page-header">
      <div class="header-left">
        <h2>Correlation Rules</h2>
        <div class="header-badges">
          <span class="badge badge-active">{{ activeCount }} active</span>
          <span class="badge badge-total">{{ rules.length }} total</span>
        </div>
      </div>
      <el-button type="primary" @click="openCreate">
        <el-icon><Plus /></el-icon> New Rule
      </el-button>
    </div>

    <!-- Rules table -->
    <div class="table-wrap">
      <el-table
        :data="rules"
        stripe size="small"
        v-loading="loading"
        empty-text="No correlation rules defined"
        style="width:100%"
      >
        <el-table-column label="Status" width="72" align="center">
          <template #default="{ row }">
            <span
              class="status-dot"
              :class="row.enabled ? 'dot-on' : 'dot-off'"
              @click.stop="toggle(row)"
              title="Click to toggle"
            />
          </template>
        </el-table-column>

        <el-table-column label="Name" min-width="180">
          <template #default="{ row }">
            <span class="rule-name">{{ row.name }}</span>
          </template>
        </el-table-column>

        <el-table-column label="Condition" min-width="280">
          <template #default="{ row }">
            <span class="mono condition-summary">{{ conditionSummary(row) }}</span>
          </template>
        </el-table-column>

        <el-table-column label="Threshold" width="100" align="center">
          <template #default="{ row }">
            <span class="mono">&ge; {{ row.threshold }}</span>
          </template>
        </el-table-column>

        <el-table-column label="Window" width="80" align="center">
          <template #default="{ row }">
            {{ row.time_window_minutes }}m
          </template>
        </el-table-column>

        <el-table-column label="Severity" width="90" align="center">
          <template #default="{ row }">
            <span class="sev-badge" :class="`sev-${row.severity}`">{{ row.severity }}</span>
          </template>
        </el-table-column>

        <el-table-column label="Scope" width="90" align="center">
          <template #default="{ row }">
            <span class="scope-badge" :class="row.scope === 'global' ? 'scope-global' : 'scope-user'">
              {{ row.scope === 'global' ? 'Global' : 'Personal' }}
            </span>
          </template>
        </el-table-column>

        <el-table-column label="Actions" width="120" align="right">
          <template #default="{ row }">
            <el-button size="small" link @click.stop="openEdit(row)">
              <el-icon><Edit /></el-icon>
            </el-button>
            <el-button size="small" link type="danger" @click.stop="confirmDelete(row)">
              <el-icon><Delete /></el-icon>
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- Delete confirmation dialog -->
    <el-dialog v-model="showDeleteDialog" title="Delete Rule" width="420px" :close-on-click-modal="false">
      <p>Delete rule <strong>{{ deleteTarget?.name }}</strong>? This cannot be undone.</p>
      <template #footer>
        <el-button @click="showDeleteDialog = false">Cancel</el-button>
        <el-button type="danger" :loading="deleting" @click="doDelete">Delete</el-button>
      </template>
    </el-dialog>

    <!-- Editor panel (slide-in) -->
    <Transition name="panel">
      <div v-if="editorOpen" class="panel-overlay" @click.self="closeEditor">
        <div class="editor-panel">
          <div class="panel-header">
            <h3>{{ isEditMode ? 'Edit Rule' : 'New Rule' }}</h3>
            <el-button link @click="closeEditor"><el-icon size="20"><Close /></el-icon></el-button>
          </div>

          <div class="panel-body">
            <el-form :model="form" label-position="top" @submit.prevent="saveRule">

              <!-- Basic -->
              <el-form-item label="Name" required>
                <el-input v-model="form.name" placeholder="e.g. Brute force detection" />
              </el-form-item>
              <el-form-item label="Description">
                <el-input v-model="form.description" type="textarea" :rows="2" placeholder="Optional description" />
              </el-form-item>
              <div class="inline-row">
                <el-form-item label="Enabled">
                  <el-switch v-model="form.enabled" />
                </el-form-item>
                <el-form-item label="Scope">
                  <el-select v-model="form.scope" style="width:140px">
                    <el-option value="user" label="Personal" />
                    <el-option value="global" label="Global" :disabled="!isAdmin" />
                  </el-select>
                </el-form-item>
              </div>

              <!-- Condition -->
              <div class="section-label">Condition</div>
              <div class="inline-row three">
                <el-form-item label="Field">
                  <el-select v-model="form.condition_field" style="width:100%">
                    <el-option v-for="f in conditionFields" :key="f.value" :value="f.value" :label="f.label" />
                  </el-select>
                </el-form-item>
                <el-form-item label="Operator">
                  <el-select v-model="form.condition_operator" style="width:100%">
                    <el-option v-for="o in operators" :key="o.value" :value="o.value" :label="o.label" />
                  </el-select>
                </el-form-item>
                <el-form-item label="Value">
                  <template v-if="form.condition_operator === 'in'">
                    <div class="tag-input-wrap">
                      <el-tag
                        v-for="(t, i) in tagValues"
                        :key="i"
                        closable size="small"
                        @close="tagValues.splice(i, 1)"
                      >{{ t }}</el-tag>
                      <el-input
                        v-model="tagInput"
                        size="small"
                        placeholder="Add + Enter"
                        class="tag-inline-input"
                        @keyup.enter="addTag"
                      />
                    </div>
                  </template>
                  <el-input v-else v-model="form.condition_value" placeholder="e.g. deny" />
                </el-form-item>
              </div>

              <!-- Aggregation -->
              <div class="section-label">Aggregation</div>
              <div class="inline-row three">
                <el-form-item label="Type">
                  <el-select v-model="form.aggregation_type" style="width:100%">
                    <el-option v-for="a in aggregationTypes" :key="a.value" :value="a.value" :label="a.label" />
                  </el-select>
                </el-form-item>
                <el-form-item label="Field" v-if="showAggField">
                  <el-select v-model="form.aggregation_field" style="width:100%" clearable>
                    <el-option v-for="f in aggFields" :key="f.value" :value="f.value" :label="f.label" />
                  </el-select>
                </el-form-item>
                <el-form-item label="Threshold">
                  <el-input v-model.number="form.threshold" type="number" :min="1" placeholder="10" />
                </el-form-item>
              </div>
              <el-form-item label="Time Window (minutes)">
                <el-input v-model.number="form.time_window_minutes" type="number" :min="1" :max="1440" placeholder="10" style="width:140px" />
              </el-form-item>

              <!-- Target -->
              <div class="section-label">Target</div>
              <el-form-item label="Group by">
                <el-select v-model="form.target_entity" style="width:220px">
                  <el-option value="source_ip" label="Source IP" />
                  <el-option value="destination_ip" label="Destination IP" />
                  <el-option value="src_dst_pair" label="Src → Dst Pair" />
                </el-select>
              </el-form-item>

              <!-- Incident -->
              <div class="section-label">Incident Creation</div>
              <div class="inline-row three">
                <el-form-item label="Severity">
                  <el-select v-model="form.severity" style="width:100%">
                    <el-option value="low" label="Low" />
                    <el-option value="medium" label="Medium" />
                    <el-option value="high" label="High" />
                    <el-option value="critical" label="Critical" />
                  </el-select>
                </el-form-item>
                <el-form-item label="Behavior Type">
                  <el-select v-model="form.incident_behavior_type" style="width:100%">
                    <el-option value="blocked" label="Blocked" />
                    <el-option value="scanning" label="Scanning" />
                    <el-option value="unstable" label="Unstable" />
                    <el-option value="lateral_movement" label="Lateral Movement" />
                    <el-option value="suspicious" label="Suspicious" />
                  </el-select>
                </el-form-item>
                <el-form-item label="Cooldown (min)">
                  <el-input v-model.number="form.cooldown_minutes" type="number" :min="1" placeholder="30" />
                </el-form-item>
              </div>

              <el-alert v-if="saveError" type="error" :title="saveError" :closable="false" style="margin-bottom:12px" />

              <div class="panel-actions">
                <el-button @click="closeEditor">Cancel</el-button>
                <el-button type="primary" :loading="saving" @click="saveRule">
                  {{ isEditMode ? 'Update' : 'Create' }}
                </el-button>
              </div>
            </el-form>
          </div>
        </div>
      </div>
    </Transition>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import api from '@/api'
import {
  fetchCorrelationRules,
  createCorrelationRule,
  updateCorrelationRule,
  deleteCorrelationRule,
  toggleCorrelationRule,
} from '@/api'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const isAdmin = computed(() => auth.user?.is_admin ?? false)

// ── State ────────────────────────────────────────────────────────────────────

const rules = ref([])
const loading = ref(false)

const activeCount = computed(() => rules.value.filter(r => r.enabled).length)

// Editor
const editorOpen = ref(false)
const isEditMode = ref(false)
const editId = ref(null)
const saving = ref(false)
const saveError = ref('')

// Tag input for "in" operator
const tagValues = ref([])
const tagInput = ref('')

// Delete
const showDeleteDialog = ref(false)
const deleteTarget = ref(null)
const deleting = ref(false)

// Form defaults
const emptyForm = () => ({
  name: '',
  description: '',
  enabled: true,
  scope: 'user',
  condition_field: 'action',
  condition_operator: 'eq',
  condition_value: '',
  aggregation_type: 'count',
  aggregation_field: null,
  threshold: 10,
  time_window_minutes: 10,
  target_entity: 'source_ip',
  severity: 'medium',
  incident_behavior_type: 'blocked',
  cooldown_minutes: 30,
})
const form = ref(emptyForm())

// ── Dropdown options ─────────────────────────────────────────────────────────

const conditionFields = [
  { value: 'source_ip', label: 'Source IP' },
  { value: 'destination_ip', label: 'Destination IP' },
  { value: 'destination_port', label: 'Destination Port' },
  { value: 'protocol', label: 'Protocol' },
  { value: 'application', label: 'Application' },
  { value: 'flow_type', label: 'Flow Type' },
  { value: 'behavior_type', label: 'Behavior Type' },
  { value: 'action', label: 'Action' },
  { value: 'deny_ratio', label: 'Deny Ratio' },
  { value: 'reset_ratio', label: 'Reset Ratio' },
  { value: 'deviation_score', label: 'Deviation Score' },
]

const operators = [
  { value: 'eq', label: '= equals' },
  { value: 'neq', label: '≠ not equal' },
  { value: 'gt', label: '> greater than' },
  { value: 'lt', label: '< less than' },
  { value: 'gte', label: '≥ greater or equal' },
  { value: 'lte', label: '≤ less or equal' },
  { value: 'in', label: 'in (list)' },
  { value: 'contains', label: 'contains' },
]

const aggregationTypes = [
  { value: 'count', label: 'Count' },
  { value: 'distinct_count', label: 'Distinct Count' },
  { value: 'sum', label: 'Sum' },
  { value: 'avg', label: 'Average' },
  { value: 'any', label: 'Any (exists)' },
]

const aggFields = [
  { value: 'destination_port', label: 'Destination Port' },
  { value: 'destination_ip', label: 'Destination IP' },
  { value: 'source_ip', label: 'Source IP' },
  { value: 'deny_ratio', label: 'Deny Ratio' },
  { value: 'reset_ratio', label: 'Reset Ratio' },
]

const showAggField = computed(() =>
  form.value.aggregation_type !== 'count' && form.value.aggregation_type !== 'any'
)

// ── Helpers ──────────────────────────────────────────────────────────────────

const opSymbols = { eq: '=', neq: '≠', gt: '>', lt: '<', gte: '≥', lte: '≤', in: 'in', contains: '~' }
const aggLabels = { count: 'count', distinct_count: 'distinct', sum: 'sum', avg: 'avg', any: 'any' }

function conditionSummary(r) {
  const field = conditionFields.find(f => f.value === r.condition_field)?.label || r.condition_field
  const op = opSymbols[r.condition_operator] || r.condition_operator
  let val = r.condition_value
  try {
    const parsed = JSON.parse(val)
    if (Array.isArray(parsed)) val = `[${parsed.join(', ')}]`
  } catch { /* keep raw */ }

  const agg = aggLabels[r.aggregation_type] || r.aggregation_type
  const aggSuffix = r.aggregation_field ? `(${r.aggregation_field})` : ''
  return `${field} ${op} ${val}, ${agg}${aggSuffix} ≥ ${r.threshold} in ${r.time_window_minutes}min`
}

function addTag() {
  const v = tagInput.value.trim()
  if (v && !tagValues.value.includes(v)) {
    tagValues.value.push(v)
  }
  tagInput.value = ''
}

// ── Data loading ─────────────────────────────────────────────────────────────

async function loadRules() {
  loading.value = true
  try {
    const res = await fetchCorrelationRules()
    rules.value = res.data
  } catch (e) {
    console.error('Failed to load correlation rules', e)
  } finally {
    loading.value = false
  }
}

// ── Toggle ───────────────────────────────────────────────────────────────────

async function toggle(rule) {
  try {
    const res = await toggleCorrelationRule(rule.id)
    const idx = rules.value.findIndex(r => r.id === rule.id)
    if (idx !== -1) rules.value[idx] = res.data
  } catch (e) {
    console.error('Toggle failed', e)
  }
}

// ── Delete ───────────────────────────────────────────────────────────────────

function confirmDelete(rule) {
  deleteTarget.value = rule
  showDeleteDialog.value = true
}

async function doDelete() {
  deleting.value = true
  try {
    await deleteCorrelationRule(deleteTarget.value.id)
    rules.value = rules.value.filter(r => r.id !== deleteTarget.value.id)
    showDeleteDialog.value = false
    deleteTarget.value = null
  } catch (e) {
    console.error('Delete failed', e)
  } finally {
    deleting.value = false
  }
}

// ── Editor ───────────────────────────────────────────────────────────────────

function openCreate() {
  isEditMode.value = false
  editId.value = null
  form.value = emptyForm()
  tagValues.value = []
  tagInput.value = ''
  saveError.value = ''
  editorOpen.value = true
}

function openEdit(rule) {
  isEditMode.value = true
  editId.value = rule.id
  saveError.value = ''
  form.value = {
    name: rule.name,
    description: rule.description || '',
    enabled: rule.enabled,
    scope: rule.scope,
    condition_field: rule.condition_field,
    condition_operator: rule.condition_operator,
    condition_value: rule.condition_operator === 'in' ? '' : rule.condition_value,
    aggregation_type: rule.aggregation_type,
    aggregation_field: rule.aggregation_field,
    threshold: rule.threshold,
    time_window_minutes: rule.time_window_minutes,
    target_entity: rule.target_entity,
    severity: rule.severity,
    incident_behavior_type: rule.incident_behavior_type,
    cooldown_minutes: rule.cooldown_minutes,
  }
  // Parse tag values for "in" operator
  if (rule.condition_operator === 'in') {
    try {
      const parsed = JSON.parse(rule.condition_value)
      tagValues.value = Array.isArray(parsed) ? parsed.map(String) : [String(rule.condition_value)]
    } catch {
      tagValues.value = [rule.condition_value]
    }
  } else {
    tagValues.value = []
  }
  tagInput.value = ''
  editorOpen.value = true
}

function closeEditor() {
  editorOpen.value = false
}

async function saveRule() {
  saveError.value = ''

  // Validation
  if (!form.value.name.trim()) {
    saveError.value = 'Name is required'
    return
  }
  if (!form.value.threshold || form.value.threshold <= 0) {
    saveError.value = 'Threshold must be greater than 0'
    return
  }
  if (form.value.time_window_minutes < 1 || form.value.time_window_minutes > 1440) {
    saveError.value = 'Time window must be between 1 and 1440 minutes'
    return
  }

  // Build condition_value
  let condVal = form.value.condition_value
  if (form.value.condition_operator === 'in') {
    if (tagInput.value.trim()) {
      tagValues.value.push(tagInput.value.trim())
      tagInput.value = ''
    }
    condVal = JSON.stringify(tagValues.value)
  }

  const payload = {
    ...form.value,
    condition_value: condVal,
    description: form.value.description || null,
    aggregation_field: showAggField.value ? form.value.aggregation_field : null,
  }

  saving.value = true
  try {
    if (isEditMode.value) {
      const res = await updateCorrelationRule(editId.value, payload)
      const idx = rules.value.findIndex(r => r.id === editId.value)
      if (idx !== -1) rules.value[idx] = res.data
    } else {
      const res = await createCorrelationRule(payload)
      rules.value.unshift(res.data)
    }
    closeEditor()
  } catch (e) {
    saveError.value = e.response?.data?.detail || 'Failed to save rule'
  } finally {
    saving.value = false
  }
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

onMounted(loadRules)
</script>

<style scoped>
.correlation-rules-page {
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 8px;
}

/* ── Header ────────────────────────────────────────────────────────────────── */
.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.header-left {
  display: flex;
  align-items: center;
  gap: 16px;
}
.header-left h2 {
  margin: 0;
  font-size: 20px;
}
.header-badges {
  display: flex;
  gap: 8px;
}
.badge {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 10px;
  font-size: 12px;
  font-weight: 600;
}
.badge-active {
  background: #f0f9eb;
  color: #67c23a;
}
.badge-total {
  background: #f4f4f5;
  color: #909399;
}

/* ── Table ──────────────────────────────────────────────────────────────────── */
.table-wrap {
  background: white;
  border-radius: 8px;
  padding: 4px;
  box-shadow: 0 1px 4px rgba(0,0,0,0.06);
}
.mono {
  font-family: 'SF Mono', 'Menlo', 'Monaco', monospace;
  font-size: 12px;
}
.condition-summary {
  color: #606266;
  word-break: break-word;
}
.rule-name {
  font-weight: 600;
  font-size: 13px;
}

/* Status dot */
.status-dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  cursor: pointer;
  transition: background 0.15s;
}
.dot-on { background: #67c23a; }
.dot-off { background: #c0c4cc; }

/* Severity badges */
.sev-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.3px;
}
.sev-critical { background: #fef0f0; color: #f56c6c; }
.sev-high     { background: #fdf6ec; color: #e6a23c; }
.sev-medium   { background: #ecf5ff; color: #409eff; }
.sev-low      { background: #f4f4f5; color: #909399; }

/* Scope badges */
.scope-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
}
.scope-global { background: #ecf5ff; color: #409eff; }
.scope-user   { background: #f4f4f5; color: #909399; }

/* ── Editor panel ──────────────────────────────────────────────────────────── */
.panel-overlay {
  position: fixed;
  inset: 0;
  z-index: 200;
  display: flex;
  justify-content: flex-end;
  background: rgba(0,0,0,0.25);
}
.editor-panel {
  width: 480px;
  max-width: 95vw;
  height: 100vh;
  background: white;
  display: flex;
  flex-direction: column;
  box-shadow: -4px 0 16px rgba(0,0,0,0.12);
}
.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  border-bottom: 1px solid #ebeef5;
}
.panel-header h3 {
  margin: 0;
  font-size: 16px;
}
.panel-body {
  flex: 1;
  overflow-y: auto;
  padding: 20px;
}
.panel-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding-top: 16px;
  border-top: 1px solid #ebeef5;
  margin-top: 8px;
}

.section-label {
  font-size: 13px;
  font-weight: 600;
  color: #303133;
  margin: 16px 0 8px;
  padding-bottom: 4px;
  border-bottom: 1px solid #ebeef5;
}

.inline-row {
  display: flex;
  gap: 12px;
}
.inline-row > * { flex: 1; }
.inline-row.three > * { flex: 1; min-width: 0; }

/* Tag input */
.tag-input-wrap {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  padding: 4px 6px;
  min-height: 32px;
  background: white;
}
.tag-inline-input {
  flex: 1;
  min-width: 60px;
}
.tag-inline-input :deep(.el-input__wrapper) {
  box-shadow: none !important;
  padding: 0 !important;
}

/* ── Panel transition ──────────────────────────────────────────────────────── */
.panel-enter-active, .panel-leave-active {
  transition: transform 0.25s ease;
}
.panel-enter-from, .panel-leave-to {
  transform: translateX(100%);
}
</style>
