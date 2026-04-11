<template>
  <div class="path-analysis-tab">

    <!-- ── Saved Queries bar ───────────────────────────────────────────────── -->
    <el-card class="saved-queries-card" shadow="never">
      <template #header>
        <span class="card-title">Saved Queries</span>
        <span class="card-subtitle">Reusable investigation targets</span>
      </template>

      <div class="sq-bar">
        <el-select
          v-model="selectedQueryId"
          placeholder="Load a saved query…"
          clearable
          size="small"
          style="flex: 1; min-width: 0"
          :loading="queriesLoading"
          @change="applyQuery"
          @clear="clearQuerySelection"
        >
          <el-option
            v-for="q in savedQueries"
            :key="q.id"
            :value="q.id"
            :label="q.name"
          >
            <span>{{ q.name }}</span>
            <el-tag
              :type="scopeTagType(q.scope)"
              size="small"
              effect="plain"
              style="margin-left: 6px"
            >{{ scopeLabel(q.scope) }}</el-tag>
            <span class="sq-option-sub">
              {{ q.source_ip }} → {{ q.destination_ip
              }}<template v-if="q.destination_port">:{{ q.destination_port }}</template>
            </span>
          </el-option>
        </el-select>

        <el-button
          v-if="selectedQueryId && selectedQueryEditable"
          size="small"
          type="primary"
          plain
          :loading="querySaving"
          @click="updateQuery"
        >Update "{{ selectedQueryName }}"</el-button>

        <el-button
          size="small"
          plain
          :loading="querySaving"
          @click="showQueryDialog = true"
        >
          <el-icon style="margin-right: 4px"><Plus /></el-icon>Save current query
        </el-button>

        <el-button
          v-if="selectedQueryId && selectedQueryEditable"
          size="small"
          plain
          type="danger"
          :loading="queryDeleting"
          @click="deleteQuery"
        >Delete</el-button>

        <el-button
          v-if="selectedQueryId"
          size="small"
          plain
          type="success"
          :loading="monitorCreating"
          @click="enableMonitoring"
        >Monitor</el-button>

        <el-tag
          v-if="selectedQueryId && selectedQuery"
          :type="scopeTagType(selectedQuery.scope)"
          size="small"
          effect="plain"
        >{{ scopeLabel(selectedQuery.scope) }}<span v-if="!selectedQueryEditable"> · read-only</span></el-tag>
      </div>

      <div v-if="selectedQuery?.note" class="sq-note">
        {{ selectedQuery.note }}
      </div>

      <el-alert
        v-if="queryError"
        type="error"
        :title="queryError"
        show-icon
        :closable="true"
        style="margin-top: 8px"
        @close="queryError = ''"
      />
    </el-card>

    <!-- Save-query dialog -->
    <el-dialog
      v-model="showQueryDialog"
      title="Save Current Query"
      width="400px"
      :close-on-click-modal="false"
    >
      <el-form size="small" label-width="80px">
        <el-form-item label="Name" required>
          <el-input
            v-model="newQueryName"
            placeholder="e.g. Client → LB health check"
            clearable
            maxlength="200"
            show-word-limit
            autofocus
          />
        </el-form-item>
        <el-form-item label="Scope">
          <el-radio-group v-model="newQueryScope" size="small">
            <el-radio-button value="private">Private</el-radio-button>
            <el-radio-button value="team">Team</el-radio-button>
            <el-radio-button value="global">Global</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="Note">
          <el-input
            v-model="newQueryNote"
            type="textarea"
            :rows="2"
            placeholder="Optional context for this investigation"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button size="small" @click="showQueryDialog = false">Cancel</el-button>
        <el-button
          size="small"
          type="primary"
          :loading="querySaving"
          :disabled="!newQueryName.trim()"
          @click="saveNewQuery"
        >Save</el-button>
      </template>
    </el-dialog>

    <!-- Input form -->
    <el-card class="form-card" shadow="never">
      <template #header>
        <span class="card-title">Path Analysis</span>
        <span class="card-subtitle">Trace the causal path between two endpoints</span>
      </template>

      <el-form :model="form" label-width="160px" size="small">
        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item label="Source IP" required>
              <el-input v-model="form.source_ip" placeholder="e.g. 10.0.0.5" clearable />
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="Destination IP" required>
              <el-input v-model="form.destination_ip" placeholder="e.g. 10.0.0.1" clearable />
            </el-form-item>
          </el-col>
        </el-row>

        <el-row :gutter="16">
          <el-col :span="12">
            <el-form-item label="Destination Port">
              <el-input
                v-model="form.destination_port_raw"
                placeholder="optional (e.g. 443)"
                clearable
                style="width: 100%"
              />
            </el-form-item>
          </el-col>
        </el-row>

        <!-- Role hints collapsible -->
        <el-collapse v-model="activeCollapse" style="margin-bottom: 12px; border: none">
          <el-collapse-item title="Role Hints (optional)" name="roles">

            <!-- ── Preset bar ───────────────────────────────────────────── -->
            <div class="preset-bar">
              <el-select
                v-model="selectedPresetId"
                placeholder="Load a saved preset…"
                clearable
                size="small"
                style="flex: 1; min-width: 0"
                :loading="presetsLoading"
                @change="applyPreset"
                @clear="clearPresetSelection"
              >
                <el-option
                  v-for="p in presets"
                  :key="p.id"
                  :label="p.name"
                  :value="p.id"
                >
                  <span>{{ p.name }}</span>
                  <el-tag
                    :type="scopeTagType(p.scope)"
                    size="small"
                    effect="plain"
                    style="margin-left: 6px"
                  >{{ scopeLabel(p.scope) }}</el-tag>
                </el-option>
              </el-select>

              <!-- Save / update buttons -->
              <el-button
                v-if="selectedPresetId && selectedPresetEditable"
                size="small"
                type="primary"
                plain
                :loading="presetSaving"
                @click="updatePreset"
              >Update "{{ selectedPresetName }}"</el-button>

              <el-button
                size="small"
                plain
                :loading="presetSaving"
                @click="showSaveDialog = true"
              >
                <el-icon style="margin-right: 4px"><Plus /></el-icon>Save as preset
              </el-button>

              <el-button
                v-if="selectedPresetId && selectedPresetEditable"
                size="small"
                plain
                type="danger"
                :loading="presetDeleting"
                @click="deletePreset"
              >Delete</el-button>

              <el-tag
                v-if="selectedPresetId && selectedPreset"
                :type="scopeTagType(selectedPreset.scope)"
                size="small"
                effect="plain"
              >{{ scopeLabel(selectedPreset.scope) }}<span v-if="!selectedPresetEditable"> · read-only</span></el-tag>
            </div>

            <el-alert
              v-if="presetError"
              type="error"
              :title="presetError"
              show-icon
              :closable="true"
              style="margin-bottom: 8px"
              @close="presetError = ''"
            />

            <el-form-item label="Firewall IPs">
              <el-input v-model="form.firewall_ips_raw" placeholder="comma-separated, e.g. 10.0.0.254" clearable />
            </el-form-item>
            <el-form-item label="Load Balancer VIPs">
              <el-input v-model="form.lb_vips_raw" placeholder="comma-separated, e.g. 10.0.0.10" clearable />
            </el-form-item>
            <el-form-item label="Backend IPs">
              <el-input v-model="form.backend_ips_raw" placeholder="comma-separated" clearable />
            </el-form-item>
            <el-form-item label="Backend Subnets">
              <el-input v-model="form.backend_subnets_raw" placeholder="comma-separated CIDRs, e.g. 10.0.1.0/24" clearable />
            </el-form-item>
          </el-collapse-item>
        </el-collapse>

        <el-form-item>
          <el-button
            type="primary"
            :loading="loading"
            :disabled="!form.source_ip.trim() || !form.destination_ip.trim()"
            @click="runAnalysis"
          >
            Analyze Path
          </el-button>
          <el-button v-if="result" plain @click="clearResult">Clear Results</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- Save-as-preset dialog -->
    <el-dialog
      v-model="showSaveDialog"
      title="Save Role Hints as Preset"
      width="360px"
      :close-on-click-modal="false"
    >
      <el-form size="small" label-width="80px">
        <el-form-item label="Name" required>
          <el-input
            v-model="newPresetName"
            placeholder="e.g. Production LB cluster"
            clearable
            maxlength="120"
            show-word-limit
            autofocus
          />
        </el-form-item>
        <el-form-item label="Scope">
          <el-radio-group v-model="newPresetScope" size="small">
            <el-radio-button value="private">Private</el-radio-button>
            <el-radio-button value="team">Team</el-radio-button>
            <el-radio-button value="global">Global</el-radio-button>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button size="small" @click="showSaveDialog = false">Cancel</el-button>
        <el-button
          size="small"
          type="primary"
          :loading="presetSaving"
          :disabled="!newPresetName.trim()"
          @click="saveNewPreset"
        >Save</el-button>
      </template>
    </el-dialog>

    <!-- Error -->
    <el-alert v-if="error" type="error" :title="error" show-icon :closable="false" />

    <!-- Results -->
    <template v-if="result">

      <!-- Summary strip -->
      <div class="result-summary">
        <div class="summary-card" :class="outcomeClass">
          <span class="summary-val">{{ outcomeLabel }}</span>
          <span class="summary-lbl">Outcome</span>
        </div>
        <div class="summary-card impairment-card" v-if="result.primary_impairment">
          <span class="summary-val impairment-val">{{ formatToken(result.primary_impairment) }}</span>
          <span class="summary-lbl">Primary Impairment</span>
        </div>
        <div class="summary-card" v-else>
          <span class="summary-val" style="color: #67c23a">None</span>
          <span class="summary-lbl">Primary Impairment</span>
        </div>
        <div class="summary-card" :class="confidenceClass">
          <span class="summary-val">{{ result.path_confidence_score }}%</span>
          <span class="summary-lbl">Path Confidence</span>
        </div>
      </div>

      <!-- Low-confidence warning -->
      <el-alert
        v-if="result.path_confidence_score < 60"
        type="warning"
        title="Low confidence — results are indicative only"
        show-icon
        :closable="false"
      >
        <template #default>
          <p style="margin: 4px 0 0">
            Confidence is low due to limited capture visibility. Treat findings as
            indicative rather than conclusive.
          </p>
        </template>
      </el-alert>

      <!-- Verdict card -->
      <el-card class="result-card" shadow="never">
        <template #header>
          <span class="card-title">Verdict</span>
          <span class="endpoint-badge">
            {{ result.source_ip }} → {{ result.destination_ip
            }}<template v-if="result.destination_port">:{{ result.destination_port }}</template>
          </span>
        </template>
        <p class="verdict-text">{{ result.path_summary }}</p>
        <div v-if="result.path_impairments && result.path_impairments.length" class="impairment-tags">
          <el-tag
            v-for="imp in result.path_impairments"
            :key="imp"
            size="small"
            :type="imp === result.primary_impairment ? 'danger' : 'warning'"
            style="margin-right: 6px; margin-top: 4px"
          >
            {{ formatToken(imp) }}
          </el-tag>
        </div>
      </el-card>

      <!-- Path narrative -->
      <el-card class="result-card" shadow="never">
        <template #header><span class="card-title">Path Narrative</span></template>
        <ol class="path-steps" v-if="result.path_steps && result.path_steps.length">
          <li v-for="(step, i) in result.path_steps" :key="i" class="path-step">{{ step }}</li>
        </ol>
        <el-empty v-else description="No narrative steps generated" :image-size="60" />
      </el-card>

      <!-- Evidence items -->
      <el-card class="result-card" shadow="never" v-if="result.evidence_items && result.evidence_items.length">
        <template #header><span class="card-title">Evidence</span></template>
        <div class="evidence-list">
          <div
            v-for="(ev, i) in result.evidence_items"
            :key="i"
            class="evidence-item"
            :class="`strength-${ev.signal_strength}`"
          >
            <div class="evidence-header">
              <el-tag :type="strengthTagType(ev.signal_strength)" size="small" effect="plain">
                {{ ev.signal_strength }}
              </el-tag>
              <span class="evidence-type">{{ formatToken(ev.type) }}</span>
            </div>
            <p class="evidence-summary">{{ ev.summary }}</p>
            <div class="evidence-meta">
              <span v-if="ev.flow_id" class="meta-item">Flow: <code>{{ ev.flow_id }}</code></span>
              <span v-if="ev.packet_refs && ev.packet_refs.length" class="meta-item">Packets: {{ ev.packet_refs.join(', ') }}</span>
            </div>
          </div>
        </div>
      </el-card>

      <!-- Hypotheses + visibility -->
      <el-row :gutter="12">
        <el-col :span="12">
          <el-card class="result-card" shadow="never">
            <template #header><span class="card-title">Alternative Hypotheses</span></template>
            <ul class="note-list" v-if="result.alternative_hypotheses && result.alternative_hypotheses.length">
              <li v-for="(h, i) in result.alternative_hypotheses" :key="i">{{ h }}</li>
            </ul>
            <el-empty v-else description="No alternative hypotheses" :image-size="60" />
          </el-card>
        </el-col>
        <el-col :span="12">
          <el-card class="result-card" shadow="never">
            <template #header><span class="card-title">Visibility Gaps</span></template>
            <ul class="note-list" v-if="result.missing_visibility_notes && result.missing_visibility_notes.length">
              <li v-for="(n, i) in result.missing_visibility_notes" :key="i">{{ n }}</li>
            </ul>
            <el-empty v-else description="No visibility gaps noted" :image-size="60" />
          </el-card>
        </el-col>
      </el-row>

      <!-- Confidence reasons -->
      <el-card
        class="result-card"
        shadow="never"
        v-if="result.confidence_reasons && result.confidence_reasons.length"
      >
        <template #header><span class="card-title">Confidence Notes</span></template>
        <ul class="note-list">
          <li v-for="(r, i) in result.confidence_reasons" :key="i">{{ r }}</li>
        </ul>
      </el-card>

      <!-- ── Analyst Feedback ─────────────────────────────────────────────── -->
      <el-divider content-position="left">
        <span style="font-size: 12px; color: #909399">Analyst Feedback</span>
      </el-divider>

      <!-- Existing feedback (read-only) -->
      <el-card
        v-if="feedback && !feedbackEditing"
        class="result-card feedback-card"
        shadow="never"
      >
        <template #header>
          <span class="card-title">Your Verdict</span>
          <el-tag :type="verdictTagType(feedback.verdict)" size="small" style="margin-left: 8px">
            {{ verdictLabel(feedback.verdict) }}
          </el-tag>
          <span class="feedback-ts" v-if="feedback.updated_at">
            Updated {{ formatDate(feedback.updated_at) }}
          </span>
          <el-button
            size="small"
            plain
            style="margin-left: auto"
            @click="startEdit"
          >Edit</el-button>
        </template>

        <div class="feedback-body">
          <div v-if="feedback.actual_root_cause" class="fb-row">
            <span class="fb-label">Actual root cause</span>
            <span class="fb-value">{{ feedback.actual_root_cause }}</span>
          </div>
          <div v-if="feedback.misleading_step" class="fb-row">
            <span class="fb-label">Misleading step</span>
            <span class="fb-value fb-quote">{{ feedback.misleading_step }}</span>
          </div>
          <div v-if="feedback.analyst_note" class="fb-row">
            <span class="fb-label">Note</span>
            <span class="fb-value">{{ feedback.analyst_note }}</span>
          </div>
          <div class="fb-row fb-prediction">
            <span class="fb-label">Engine predicted</span>
            <span class="fb-value">
              {{ formatToken(feedback.predicted_outcome) }}
              <template v-if="feedback.predicted_impairment">
                · {{ formatToken(feedback.predicted_impairment) }}
              </template>
              · {{ feedback.predicted_confidence }}% confidence
            </span>
          </div>
        </div>
      </el-card>

      <!-- Feedback form (new or editing) -->
      <el-card
        v-else-if="!feedback || feedbackEditing"
        class="result-card"
        shadow="never"
      >
        <template #header>
          <span class="card-title">{{ feedback ? 'Edit Verdict' : 'Submit Verdict' }}</span>
          <span class="card-subtitle" style="margin-left: 8px">
            Was the engine's assessment correct?
          </span>
          <el-button
            v-if="feedback && feedbackEditing"
            size="small"
            plain
            style="margin-left: auto"
            @click="cancelEdit"
          >Cancel</el-button>
        </template>

        <el-form :model="feedbackForm" label-width="160px" size="small">
          <!-- Verdict -->
          <el-form-item label="Verdict" required>
            <el-radio-group v-model="feedbackForm.verdict">
              <el-radio-button value="correct">
                <span style="color: #67c23a">✓ Correct</span>
              </el-radio-button>
              <el-radio-button value="partially_correct">
                <span style="color: #e6a23c">~ Partially Correct</span>
              </el-radio-button>
              <el-radio-button value="incorrect">
                <span style="color: #f56c6c">✗ Incorrect</span>
              </el-radio-button>
            </el-radio-group>
          </el-form-item>

          <!-- Actual root cause — shown when not fully correct -->
          <el-form-item
            v-if="feedbackForm.verdict !== 'correct'"
            label="Actual root cause"
          >
            <el-input
              v-model="feedbackForm.actual_root_cause"
              placeholder="What actually caused the issue? (free text)"
              clearable
            />
          </el-form-item>

          <!-- Misleading step — shown when not fully correct, only if steps exist -->
          <el-form-item
            v-if="feedbackForm.verdict !== 'correct' && result.path_steps && result.path_steps.length"
            label="Misleading step"
          >
            <el-select
              v-model="feedbackForm.misleading_step"
              placeholder="Which step was wrong or misleading? (optional)"
              clearable
              style="width: 100%"
            >
              <el-option
                v-for="(step, i) in result.path_steps"
                :key="i"
                :label="`Step ${i + 1}: ${step.slice(0, 80)}${step.length > 80 ? '…' : ''}`"
                :value="step"
              />
            </el-select>
          </el-form-item>

          <!-- Note -->
          <el-form-item label="Note">
            <el-input
              v-model="feedbackForm.analyst_note"
              type="textarea"
              :rows="2"
              placeholder="Optional free-form note for future calibration"
            />
          </el-form-item>

          <el-form-item>
            <el-button
              type="primary"
              :loading="feedbackLoading"
              :disabled="!feedbackForm.verdict"
              @click="submitFeedback"
            >
              {{ feedback ? 'Update Verdict' : 'Submit Verdict' }}
            </el-button>
          </el-form-item>
        </el-form>

        <el-alert
          v-if="feedbackError"
          type="error"
          :title="feedbackError"
          show-icon
          :closable="false"
          style="margin-top: 8px"
        />
      </el-card>

      <!-- Export -->
      <div class="export-bar">
        <el-button size="small" plain :loading="exportJsonLoading" @click="exportJson">
          Export JSON
        </el-button>
        <el-button size="small" plain :loading="exportHtmlLoading" @click="exportHtml">
          Export HTML Report
        </el-button>
      </div>

    </template>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, reactive, watch, onMounted } from 'vue'
import { Plus } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import api from '@/api'
import type { PathAnalysisFeedback, PathAnalysisFeedbackVerdict } from '@/types/analysis'

const props = defineProps<{ analysisId: string }>()

// ── Analysis state ────────────────────────────────────────────────────────────
const loading = ref(false)
const error   = ref('')
const result  = ref<Record<string, any> | null>(null)
const activeCollapse = ref<string[]>([])

const form = reactive({
  source_ip: '',
  destination_ip: '',
  destination_port_raw: '',
  firewall_ips_raw: '',
  lb_vips_raw: '',
  backend_ips_raw: '',
  backend_subnets_raw: '',
})

// ── Preset state ──────────────────────────────────────────────────────────────
type SharingScope = 'private' | 'team' | 'global'

interface RolePreset {
  id: number
  name: string
  firewall_ips: string[]
  load_balancer_vips: string[]
  backend_ips: string[]
  backend_subnets: string[]
  scope: SharingScope
  team_id: number | null
  can_edit: boolean
}

const presets        = ref<RolePreset[]>([])
const presetsLoading = ref(false)
const selectedPresetId = ref<number | null>(null)
const presetSaving   = ref(false)
const presetDeleting = ref(false)
const presetError    = ref('')
const showSaveDialog = ref(false)
const newPresetName  = ref('')
const newPresetScope = ref<SharingScope>('private')

const selectedPreset = computed(
  () => presets.value.find(p => p.id === selectedPresetId.value) ?? null,
)
const selectedPresetName = computed(() => selectedPreset.value?.name ?? '')
const selectedPresetEditable = computed(() => selectedPreset.value?.can_edit ?? false)

async function loadPresets() {
  presetsLoading.value = true
  try {
    const res = await api.get('/path-analysis/presets')
    presets.value = res.data
  } catch {
    // Non-critical — silently ignore
  } finally {
    presetsLoading.value = false
  }
}

function applyPreset(id: number | null) {
  if (!id) return
  const preset = presets.value.find(p => p.id === id)
  if (!preset) return
  form.firewall_ips_raw    = preset.firewall_ips.join(', ')
  form.lb_vips_raw         = preset.load_balancer_vips.join(', ')
  form.backend_ips_raw     = preset.backend_ips.join(', ')
  form.backend_subnets_raw = preset.backend_subnets.join(', ')
  // Expand the Role Hints section so the user sees the populated values
  if (!activeCollapse.value.includes('roles')) {
    activeCollapse.value = [...activeCollapse.value, 'roles']
  }
}

function clearPresetSelection() {
  selectedPresetId.value = null
}

function currentRoleLists() {
  return {
    firewall_ips:       parseList(form.firewall_ips_raw),
    load_balancer_vips: parseList(form.lb_vips_raw),
    backend_ips:        parseList(form.backend_ips_raw),
    backend_subnets:    parseList(form.backend_subnets_raw),
  }
}

async function saveNewPreset() {
  if (!newPresetName.value.trim()) return
  presetSaving.value = true
  presetError.value  = ''
  try {
    const res = await api.post('/path-analysis/presets', {
      name: newPresetName.value.trim(),
      scope: newPresetScope.value,
      ...currentRoleLists(),
    })
    presets.value.unshift(res.data)
    selectedPresetId.value = res.data.id
    showSaveDialog.value   = false
    newPresetName.value    = ''
    newPresetScope.value   = 'private'
  } catch (e: any) {
    presetError.value = e.response?.data?.detail ?? 'Failed to save preset.'
  } finally {
    presetSaving.value = false
  }
}

async function updatePreset() {
  if (!selectedPresetId.value) return
  presetSaving.value = true
  presetError.value  = ''
  try {
    const res = await api.put(`/path-analysis/presets/${selectedPresetId.value}`, currentRoleLists())
    const idx = presets.value.findIndex(p => p.id === selectedPresetId.value)
    if (idx !== -1) presets.value[idx] = res.data
  } catch (e: any) {
    presetError.value = e.response?.data?.detail ?? 'Failed to update preset.'
  } finally {
    presetSaving.value = false
  }
}

async function deletePreset() {
  if (!selectedPresetId.value) return
  presetDeleting.value = true
  presetError.value    = ''
  try {
    await api.delete(`/path-analysis/presets/${selectedPresetId.value}`)
    presets.value      = presets.value.filter(p => p.id !== selectedPresetId.value)
    selectedPresetId.value = null
    // Clear role fields since the preset is gone
    form.firewall_ips_raw    = ''
    form.lb_vips_raw         = ''
    form.backend_ips_raw     = ''
    form.backend_subnets_raw = ''
  } catch (e: any) {
    presetError.value = e.response?.data?.detail ?? 'Failed to delete preset.'
  } finally {
    presetDeleting.value = false
  }
}

// ── Feedback state ────────────────────────────────────────────────────────────
const feedback        = ref<PathAnalysisFeedback | null>(null)
const feedbackEditing = ref(false)
const feedbackLoading = ref(false)
const feedbackError   = ref('')

const feedbackForm = reactive({
  verdict:           '' as PathAnalysisFeedbackVerdict | '',
  analyst_note:      '',
  actual_root_cause: '',
  misleading_step:   '',
})

function resetFeedbackForm(source?: PathAnalysisFeedback) {
  feedbackForm.verdict           = source?.verdict           ?? ''
  feedbackForm.analyst_note      = source?.analyst_note      ?? ''
  feedbackForm.actual_root_cause = source?.actual_root_cause ?? ''
  feedbackForm.misleading_step   = source?.misleading_step   ?? ''
}

function startEdit() {
  resetFeedbackForm(feedback.value ?? undefined)
  feedbackEditing.value = true
}

function cancelEdit() {
  feedbackEditing.value = false
  feedbackError.value   = ''
}

// ── Load existing feedback for a given query ──────────────────────────────────
async function loadFeedback(src: string, dst: string, port: number | null) {
  feedback.value        = null
  feedbackEditing.value = false
  feedbackError.value   = ''
  try {
    const res = await api.get(`/analyses/${props.analysisId}/path-analysis/feedback`)
    const all: PathAnalysisFeedback[] = res.data
    const match = all.find(
      f =>
        f.source_ip      === src &&
        f.destination_ip === dst &&
        (f.destination_port ?? null) === (port ?? null),
    )
    if (match) {
      feedback.value = match
      resetFeedbackForm(match)
    } else {
      resetFeedbackForm()
      feedbackEditing.value = true   // no prior feedback → show form
    }
  } catch {
    resetFeedbackForm()
    feedbackEditing.value = true
  }
}

// ── Submit feedback ───────────────────────────────────────────────────────────
async function submitFeedback() {
  if (!result.value || !feedbackForm.verdict) return
  feedbackError.value   = ''
  feedbackLoading.value = true

  const port = result.value.destination_port ?? null
  const payload = {
    source_ip:            result.value.source_ip,
    destination_ip:       result.value.destination_ip,
    destination_port:     port,
    predicted_outcome:    result.value.connection_outcome,
    predicted_impairment: result.value.primary_impairment ?? null,
    predicted_confidence: result.value.path_confidence_score,
    verdict:              feedbackForm.verdict,
    analyst_note:         feedbackForm.analyst_note      || null,
    actual_root_cause:    feedbackForm.actual_root_cause || null,
    misleading_step:      feedbackForm.misleading_step   || null,
  }

  try {
    const res = await api.post(
      `/analyses/${props.analysisId}/path-analysis/feedback`,
      payload,
    )
    feedback.value        = res.data
    feedbackEditing.value = false
  } catch (e: any) {
    feedbackError.value =
      e.response?.data?.detail ?? 'Failed to save feedback. Please try again.'
  } finally {
    feedbackLoading.value = false
  }
}

// ── Analysis execution ────────────────────────────────────────────────────────
function parseList(raw: string): string[] {
  return raw.split(',').map(s => s.trim()).filter(Boolean)
}

async function runAnalysis() {
  error.value  = ''
  result.value = null
  feedback.value = null
  feedbackEditing.value = false

  if (!form.source_ip.trim() || !form.destination_ip.trim()) return

  const payload: Record<string, any> = {
    source_ip:      form.source_ip.trim(),
    destination_ip: form.destination_ip.trim(),
  }

  const port = parseInt(form.destination_port_raw, 10)
  if (!isNaN(port) && port > 0 && port <= 65535) payload.destination_port = port

  const fw = parseList(form.firewall_ips_raw)
  const lb = parseList(form.lb_vips_raw)
  const be = parseList(form.backend_ips_raw)
  const sn = parseList(form.backend_subnets_raw)
  const roles: Record<string, string[]> = {}
  if (fw.length) roles.firewall_ips = fw
  if (lb.length) roles.load_balancer_vips = lb
  if (be.length) roles.backend_ips = be
  if (sn.length) roles.backend_subnets = sn
  if (Object.keys(roles).length) payload.roles = roles

  loading.value = true
  try {
    const res = await api.post(`/analyses/${props.analysisId}/path-analysis`, payload)
    result.value = res.data
    // Fetch any saved feedback for this exact query
    await loadFeedback(
      res.data.source_ip,
      res.data.destination_ip,
      res.data.destination_port ?? null,
    )
  } catch (e: any) {
    error.value =
      e.response?.data?.detail ??
      'Path analysis failed. Ensure the PCAP file is still available on the server.'
  } finally {
    loading.value = false
  }
}

function clearResult() {
  result.value          = null
  error.value           = ''
  feedback.value        = null
  feedbackEditing.value = false
  feedbackError.value   = ''
}

// ── Saved queries state ───────────────────────────────────────────────────────
interface SavedQuery {
  id: number
  name: string
  source_ip: string
  destination_ip: string
  destination_port: number | null
  role_preset_id: number | null
  firewall_ips: string[]
  load_balancer_vips: string[]
  backend_ips: string[]
  backend_subnets: string[]
  note: string | null
  scope: SharingScope
  team_id: number | null
  can_edit: boolean
}

const savedQueries      = ref<SavedQuery[]>([])
const queriesLoading    = ref(false)
const selectedQueryId   = ref<number | null>(null)
const querySaving       = ref(false)
const queryDeleting     = ref(false)
const monitorCreating   = ref(false)
const queryError        = ref('')
const showQueryDialog   = ref(false)
const newQueryName      = ref('')
const newQueryNote      = ref('')
const newQueryScope     = ref<SharingScope>('private')

const selectedQuery = computed(
  () => savedQueries.value.find(q => q.id === selectedQueryId.value) ?? null,
)
const selectedQueryName = computed(() => selectedQuery.value?.name ?? '')
const selectedQueryEditable = computed(() => selectedQuery.value?.can_edit ?? false)

async function loadSavedQueries() {
  queriesLoading.value = true
  try {
    const res = await api.get('/path-analysis/saved-queries')
    savedQueries.value = res.data
  } catch {
    // Non-critical — silently ignore
  } finally {
    queriesLoading.value = false
  }
}

function applyQuery(id: number | null) {
  if (!id) return
  const q = savedQueries.value.find(q => q.id === id)
  if (!q) return

  // Populate all form fields from the saved query
  form.source_ip           = q.source_ip
  form.destination_ip      = q.destination_ip
  form.destination_port_raw = q.destination_port != null ? String(q.destination_port) : ''
  form.firewall_ips_raw    = q.firewall_ips.join(', ')
  form.lb_vips_raw         = q.load_balancer_vips.join(', ')
  form.backend_ips_raw     = q.backend_ips.join(', ')
  form.backend_subnets_raw = q.backend_subnets.join(', ')

  // Sync preset selector if the query references one
  if (q.role_preset_id != null && presets.value.some(p => p.id === q.role_preset_id)) {
    selectedPresetId.value = q.role_preset_id
  } else {
    selectedPresetId.value = null
  }

  // Expand role hints so the user sees what was loaded
  if (!activeCollapse.value.includes('roles')) {
    activeCollapse.value = [...activeCollapse.value, 'roles']
  }
}

function clearQuerySelection() {
  selectedQueryId.value = null
}

function currentQueryPayload() {
  const port = parseInt(form.destination_port_raw, 10)
  return {
    source_ip:          form.source_ip.trim(),
    destination_ip:     form.destination_ip.trim(),
    destination_port:   !isNaN(port) && port > 0 ? port : null,
    role_preset_id:     selectedPresetId.value,
    firewall_ips:       parseList(form.firewall_ips_raw),
    load_balancer_vips: parseList(form.lb_vips_raw),
    backend_ips:        parseList(form.backend_ips_raw),
    backend_subnets:    parseList(form.backend_subnets_raw),
  }
}

async function saveNewQuery() {
  if (!newQueryName.value.trim()) return
  querySaving.value = true
  queryError.value  = ''
  try {
    const res = await api.post('/path-analysis/saved-queries', {
      name:  newQueryName.value.trim(),
      note:  newQueryNote.value.trim() || null,
      scope: newQueryScope.value,
      ...currentQueryPayload(),
    })
    savedQueries.value.unshift(res.data)
    selectedQueryId.value = res.data.id
    showQueryDialog.value = false
    newQueryName.value    = ''
    newQueryNote.value    = ''
    newQueryScope.value   = 'private'
  } catch (e: any) {
    queryError.value = e.response?.data?.detail ?? 'Failed to save query.'
  } finally {
    querySaving.value = false
  }
}

async function updateQuery() {
  if (!selectedQueryId.value) return
  querySaving.value = true
  queryError.value  = ''
  try {
    const res = await api.put(
      `/path-analysis/saved-queries/${selectedQueryId.value}`,
      {
        ...currentQueryPayload(),
        clear_port:   currentQueryPayload().destination_port == null,
        clear_preset: selectedPresetId.value == null,
      },
    )
    const idx = savedQueries.value.findIndex(q => q.id === selectedQueryId.value)
    if (idx !== -1) savedQueries.value[idx] = res.data
  } catch (e: any) {
    queryError.value = e.response?.data?.detail ?? 'Failed to update query.'
  } finally {
    querySaving.value = false
  }
}

async function deleteQuery() {
  if (!selectedQueryId.value) return
  queryDeleting.value = true
  queryError.value    = ''
  try {
    await api.delete(`/path-analysis/saved-queries/${selectedQueryId.value}`)
    savedQueries.value  = savedQueries.value.filter(q => q.id !== selectedQueryId.value)
    selectedQueryId.value = null
  } catch (e: any) {
    queryError.value = e.response?.data?.detail ?? 'Failed to delete query.'
  } finally {
    queryDeleting.value = false
  }
}

async function enableMonitoring() {
  if (!selectedQueryId.value) return
  monitorCreating.value = true
  queryError.value = ''
  try {
    await api.post('/path-monitors', {
      saved_query_id: selectedQueryId.value,
      analysis_id:    props.analysisId,
      schedule_interval_minutes: 60,
    })
    ElMessage.success(
      `Monitoring enabled for "${selectedQueryName.value}". See the Monitoring page for status.`,
    )
  } catch (e: any) {
    queryError.value = e.response?.data?.detail ?? 'Failed to create monitor.'
  } finally {
    monitorCreating.value = false
  }
}

// ── Export ────────────────────────────────────────────────────────────────────
const exportJsonLoading = ref(false)
const exportHtmlLoading = ref(false)

function buildExportPayload() {
  const port = parseInt(form.destination_port_raw, 10)
  const fw = parseList(form.firewall_ips_raw)
  const lb = parseList(form.lb_vips_raw)
  const be = parseList(form.backend_ips_raw)
  const sn = parseList(form.backend_subnets_raw)
  const roles: Record<string, string[]> = {}
  if (fw.length) roles.firewall_ips = fw
  if (lb.length) roles.load_balancer_vips = lb
  if (be.length) roles.backend_ips = be
  if (sn.length) roles.backend_subnets = sn
  return {
    analysis_id:      props.analysisId,
    source_ip:        result.value!.source_ip,
    destination_ip:   result.value!.destination_ip,
    destination_port: result.value?.destination_port ?? null,
    roles:            Object.keys(roles).length ? roles : null,
    saved_query_id:   selectedQueryId.value ?? null,
  }
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

async function exportJson() {
  if (!result.value) return
  exportJsonLoading.value = true
  try {
    const res = await api.post('/path-analysis/export/json', buildExportPayload(), { responseType: 'blob' })
    triggerDownload(res.data, `investigation_${props.analysisId}.json`)
  } catch {
    // Silent — download errors are transient and hard to surface usefully
  } finally {
    exportJsonLoading.value = false
  }
}

async function exportHtml() {
  if (!result.value) return
  exportHtmlLoading.value = true
  try {
    const res = await api.post('/path-analysis/export/html', buildExportPayload(), { responseType: 'blob' })
    triggerDownload(res.data, `investigation_${props.analysisId}.html`)
  } catch {
    // Silent
  } finally {
    exportHtmlLoading.value = false
  }
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────
onMounted(() => {
  loadPresets()
  loadSavedQueries()
})

// ── Display helpers ───────────────────────────────────────────────────────────
const outcomeLabel = computed(() => {
  const map: Record<string, string> = {
    success: 'Success', partial_success: 'Partial Success',
    failure: 'Failure', unknown: 'Unknown',
  }
  return map[result.value?.connection_outcome ?? ''] ?? result.value?.connection_outcome ?? '—'
})

const outcomeClass = computed(() => {
  const o = result.value?.connection_outcome
  if (o === 'success')         return 'outcome-success'
  if (o === 'failure')         return 'outcome-failure'
  if (o === 'partial_success') return 'outcome-warning'
  return ''
})

const confidenceClass = computed(() => {
  const s = result.value?.path_confidence_score ?? 0
  if (s >= 75) return 'conf-high'
  if (s >= 50) return 'conf-medium'
  return 'conf-low'
})

function formatToken(tok: string): string {
  return tok.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function strengthTagType(s: string): '' | 'success' | 'warning' | 'danger' | 'info' {
  if (s === 'high')   return 'danger'
  if (s === 'medium') return 'warning'
  return 'info'
}

function verdictLabel(v: string): string {
  if (v === 'correct')           return 'Correct'
  if (v === 'partially_correct') return 'Partially Correct'
  if (v === 'incorrect')         return 'Incorrect'
  return v
}

function verdictTagType(v: string): '' | 'success' | 'warning' | 'danger' {
  if (v === 'correct')           return 'success'
  if (v === 'partially_correct') return 'warning'
  if (v === 'incorrect')         return 'danger'
  return ''
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

function scopeLabel(s: SharingScope | undefined | null): string {
  if (s === 'team')   return 'Team'
  if (s === 'global') return 'Global'
  return 'Private'
}

function scopeTagType(
  s: SharingScope | undefined | null,
): '' | 'success' | 'warning' | 'info' {
  if (s === 'team')   return 'success'
  if (s === 'global') return 'warning'
  return 'info'
}
</script>

<style scoped>
.path-analysis-tab { display: flex; flex-direction: column; gap: 12px; }

/* Saved queries */
.saved-queries-card :deep(.el-card__header) { display: flex; align-items: baseline; gap: 10px; }
.sq-bar {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
}
.sq-option-sub {
  margin-left: 8px; font-size: 11px; color: #909399; font-family: monospace;
}
.sq-note {
  margin-top: 8px; font-size: 12px; color: #606266;
  border-left: 3px solid #dcdfe6; padding-left: 8px;
}

/* Form card header */
.form-card :deep(.el-card__header) { display: flex; align-items: baseline; gap: 10px; }
.card-title    { font-weight: 600; font-size: 14px; }
.card-subtitle { font-size: 12px; color: #909399; }

/* Preset bar */
.preset-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
  padding: 8px 10px;
  background: #f9f9fb;
  border: 1px solid #ebeef5;
  border-radius: 6px;
}

/* Summary strip */
.result-summary { display: flex; gap: 12px; flex-wrap: wrap; }
.summary-card {
  background: #fff; border: 1px solid #ebeef5; border-radius: 6px;
  padding: 12px 20px; text-align: center; min-width: 110px;
}
.summary-val { display: block; font-size: 18px; font-weight: 700; color: #303133; }
.summary-val.impairment-val { font-size: 12px; line-height: 1.4; }
.summary-lbl { font-size: 11px; color: #909399; margin-top: 2px; display: block; }

.outcome-success  { border-color: #67c23a; }
.outcome-success  .summary-val { color: #67c23a; }
.outcome-failure  { border-color: #f56c6c; }
.outcome-failure  .summary-val { color: #f56c6c; }
.outcome-warning  { border-color: #e6a23c; }
.outcome-warning  .summary-val { color: #e6a23c; }
.conf-high   .summary-val { color: #67c23a; }
.conf-medium .summary-val { color: #e6a23c; }
.conf-low    .summary-val { color: #f56c6c; }

/* Result cards */
.result-card :deep(.el-card__header) {
  display: flex; align-items: center; gap: 8px; padding: 10px 16px;
}
.endpoint-badge { font-size: 12px; color: #909399; font-family: monospace; }
.verdict-text   { font-size: 14px; color: #303133; margin: 0 0 8px; line-height: 1.6; }
.impairment-tags { margin-top: 4px; }

/* Path steps */
.path-steps { margin: 0; padding-left: 22px; }
.path-step  { font-size: 13px; color: #606266; margin-bottom: 8px; line-height: 1.6; }

/* Evidence */
.evidence-list { display: flex; flex-direction: column; gap: 10px; }
.evidence-item {
  border: 1px solid #ebeef5; border-radius: 6px; padding: 10px 14px;
}
.evidence-item.strength-high   { border-left: 3px solid #f56c6c; }
.evidence-item.strength-medium { border-left: 3px solid #e6a23c; }
.evidence-item.strength-low    { border-left: 3px solid #909399; }
.evidence-header  { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.evidence-type    { font-weight: 600; font-size: 13px; }
.evidence-summary { margin: 4px 0; font-size: 13px; color: #606266; }
.evidence-meta    { font-size: 12px; color: #909399; display: flex; gap: 14px; flex-wrap: wrap; margin-top: 4px; }
.meta-item code   { font-size: 11px; background: #f4f4f5; padding: 1px 5px; border-radius: 3px; }

/* Notes */
.note-list    { margin: 0; padding-left: 18px; }
.note-list li { font-size: 13px; color: #606266; margin-bottom: 4px; line-height: 1.6; }

/* Feedback card */
.feedback-card :deep(.el-card__header) { flex-wrap: wrap; }
.feedback-ts { font-size: 11px; color: #c0c4cc; margin-left: 6px; }

.feedback-body { display: flex; flex-direction: column; gap: 8px; }
.fb-row {
  display: flex; gap: 12px; align-items: flex-start;
  font-size: 13px; padding: 6px 0;
  border-bottom: 1px solid #f4f4f5;
}
.fb-row:last-child { border-bottom: none; }
.fb-label { color: #909399; min-width: 130px; flex-shrink: 0; }
.fb-value { color: #303133; flex: 1; }
.fb-quote {
  font-style: italic; color: #606266;
  border-left: 3px solid #dcdfe6; padding-left: 8px;
}
.fb-prediction { background: #fafafa; border-radius: 4px; padding: 6px 8px; }
.fb-prediction .fb-value { font-family: monospace; font-size: 12px; }

/* Export */
.export-bar { display: flex; gap: 8px; padding-top: 4px; }
</style>
