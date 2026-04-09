<template>
  <div class="calibration-view">
    <div class="page-header">
      <h2>Path Analysis Calibration</h2>
      <p class="page-desc">
        Accuracy reporting for analyst feedback on Path Analysis predictions.
        Use this view to identify where the engine is overconfident, underconfident,
        or producing misleading narratives.
      </p>
    </div>

    <div v-if="loading" class="loading-state">
      <el-icon class="is-loading" size="32"><Loading /></el-icon>
      <span>Loading calibration data…</span>
    </div>

    <el-alert v-else-if="error" type="error" :title="error" :closable="false" style="margin-bottom:16px" />

    <template v-else-if="data">
      <!-- Empty state -->
      <el-empty v-if="data.total === 0" description="No analyst feedback yet. Submit verdicts from the Path Analysis tab to populate this report." />

      <template v-else>
        <!-- ── Summary cards ── -->
        <el-row :gutter="16" class="summary-row">
          <el-col :span="6">
            <el-card class="stat-card">
              <div class="stat-value">{{ data.total }}</div>
              <div class="stat-label">Total Verdicts</div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card stat-correct">
              <div class="stat-value">{{ data.verdict_counts.correct }}</div>
              <div class="stat-label">Correct</div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card stat-partial">
              <div class="stat-value">{{ data.verdict_counts.partially_correct }}</div>
              <div class="stat-label">Partially Correct</div>
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card class="stat-card stat-incorrect">
              <div class="stat-value">{{ data.verdict_counts.incorrect }}</div>
              <div class="stat-label">Incorrect</div>
            </el-card>
          </el-col>
        </el-row>

        <!-- Overall accuracy bar -->
        <el-card class="section-card">
          <template #header><span class="card-label">Overall Accuracy</span></template>
          <div class="accuracy-bar-row">
            <span class="accuracy-pct">{{ overallAccuracyPct }}%</span>
            <el-progress
              :percentage="overallAccuracyPct"
              :color="accuracyColor(overallAccuracyPct)"
              :stroke-width="16"
              style="flex:1"
            />
            <span class="accuracy-note">{{ data.verdict_counts.correct + data.verdict_counts.partially_correct }} / {{ data.total }} correct or partial</span>
          </div>
        </el-card>

        <!-- ── Confidence bucket accuracy ── -->
        <el-card class="section-card">
          <template #header><span class="card-label">Accuracy by Confidence Bucket</span></template>
          <el-table :data="data.confidence_buckets" size="small" stripe>
            <el-table-column prop="label" label="Confidence Range" width="160" />
            <el-table-column prop="total" label="Total" width="80" align="center" />
            <el-table-column prop="correct" label="Correct" width="90" align="center">
              <template #default="{ row }">
                <el-tag type="success" size="small">{{ row.correct }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="partially_correct" label="Partial" width="80" align="center">
              <template #default="{ row }">
                <el-tag type="warning" size="small">{{ row.partially_correct }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="incorrect" label="Incorrect" width="90" align="center">
              <template #default="{ row }">
                <el-tag type="danger" size="small">{{ row.incorrect }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Accuracy" min-width="200">
              <template #default="{ row }">
                <template v-if="row.total > 0">
                  <div class="bucket-bar-row">
                    <el-progress
                      :percentage="pct(row.accuracy_rate)"
                      :color="accuracyColor(pct(row.accuracy_rate))"
                      :stroke-width="10"
                      style="flex:1"
                    />
                    <span class="bucket-pct">{{ pct(row.accuracy_rate) }}%</span>
                  </div>
                </template>
                <span v-else class="muted">—</span>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <!-- ── By impairment ── -->
        <el-card class="section-card">
          <template #header><span class="card-label">Accuracy by Predicted Impairment</span></template>
          <el-table :data="data.by_impairment" size="small" stripe>
            <el-table-column prop="predicted_impairment" label="Predicted Impairment" min-width="240">
              <template #default="{ row }">
                <el-tag :type="impairmentTagType(row.predicted_impairment)" size="small">
                  {{ row.predicted_impairment }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="total" label="Total" width="70" align="center" />
            <el-table-column prop="correct" label="Correct" width="80" align="center" />
            <el-table-column prop="partially_correct" label="Partial" width="70" align="center" />
            <el-table-column prop="incorrect" label="Incorrect" width="80" align="center" />
            <el-table-column label="Accuracy" min-width="160">
              <template #default="{ row }">
                <template v-if="row.total > 0">
                  <div class="bucket-bar-row">
                    <el-progress
                      :percentage="pct(row.accuracy_rate)"
                      :color="accuracyColor(pct(row.accuracy_rate))"
                      :stroke-width="10"
                      style="flex:1"
                    />
                    <span class="bucket-pct">{{ pct(row.accuracy_rate) }}%</span>
                  </div>
                </template>
                <span v-else class="muted">—</span>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <!-- ── By outcome ── -->
        <el-card class="section-card">
          <template #header><span class="card-label">Accuracy by Predicted Outcome</span></template>
          <el-table :data="data.by_outcome" size="small" stripe>
            <el-table-column prop="predicted_outcome" label="Predicted Outcome" min-width="200">
              <template #default="{ row }">
                <el-tag :type="outcomeTagType(row.predicted_outcome)" size="small">
                  {{ row.predicted_outcome }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="total" label="Total" width="70" align="center" />
            <el-table-column prop="correct" label="Correct" width="80" align="center" />
            <el-table-column prop="partially_correct" label="Partial" width="70" align="center" />
            <el-table-column prop="incorrect" label="Incorrect" width="80" align="center" />
            <el-table-column label="Accuracy" min-width="160">
              <template #default="{ row }">
                <template v-if="row.total > 0">
                  <div class="bucket-bar-row">
                    <el-progress
                      :percentage="pct(row.accuracy_rate)"
                      :color="accuracyColor(pct(row.accuracy_rate))"
                      :stroke-width="10"
                      style="flex:1"
                    />
                    <span class="bucket-pct">{{ pct(row.accuracy_rate) }}%</span>
                  </div>
                </template>
                <span v-else class="muted">—</span>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <!-- ── Top misleading steps ── -->
        <el-card v-if="data.misleading_steps.length > 0" class="section-card">
          <template #header><span class="card-label">Top Misleading Narrative Steps</span></template>
          <el-table :data="data.misleading_steps" size="small" stripe>
            <el-table-column prop="count" label="#" width="60" align="center">
              <template #default="{ row }">
                <el-badge :value="row.count" type="danger" />
              </template>
            </el-table-column>
            <el-table-column prop="step" label="Misleading Step" min-width="400">
              <template #default="{ row }">
                <span class="step-text">{{ row.step }}</span>
              </template>
            </el-table-column>
            <el-table-column label="Associated Impairments" min-width="240">
              <template #default="{ row }">
                <el-tag
                  v-for="imp in row.impairments"
                  :key="imp"
                  :type="impairmentTagType(imp)"
                  size="small"
                  style="margin-right:4px;margin-bottom:2px"
                >{{ imp }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <!-- ── Root-cause mismatch ── -->
        <el-card v-if="data.root_cause_mismatches.length > 0" class="section-card">
          <template #header><span class="card-label">Root Cause Mismatch Summary</span></template>
          <p class="section-desc">Predicted impairment vs analyst-confirmed actual root cause.</p>
          <el-table :data="data.root_cause_mismatches" size="small" stripe>
            <el-table-column prop="count" label="#" width="60" align="center" />
            <el-table-column label="Predicted Impairment" min-width="220">
              <template #default="{ row }">
                <el-tag :type="impairmentTagType(row.predicted_impairment)" size="small">
                  {{ row.predicted_impairment }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="actual_root_cause" label="Actual Root Cause" min-width="220" />
          </el-table>
        </el-card>

        <!-- ── Overconfident cases ── -->
        <el-card v-if="data.overconfident.length > 0" class="section-card">
          <template #header>
            <span class="card-label">Overconfident Cases</span>
            <el-tag type="danger" size="small" style="margin-left:8px">
              Confidence ≥ 75 + Incorrect
            </el-tag>
          </template>
          <el-table :data="data.overconfident" size="small" stripe>
            <el-table-column label="Analysis" width="120">
              <template #default="{ row }">
                <router-link :to="`/analysis/${row.analysis_id}`" class="analysis-link">
                  {{ row.analysis_id.slice(0, 8) }}…
                </router-link>
              </template>
            </el-table-column>
            <el-table-column prop="source_ip" label="Src IP" width="140" />
            <el-table-column prop="destination_ip" label="Dst IP" width="140" />
            <el-table-column prop="destination_port" label="Port" width="70" align="center">
              <template #default="{ row }">{{ row.destination_port ?? '—' }}</template>
            </el-table-column>
            <el-table-column label="Confidence" width="100" align="center">
              <template #default="{ row }">
                <el-tag type="danger" size="small">{{ row.predicted_confidence }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Predicted Impairment" min-width="200">
              <template #default="{ row }">
                <el-tag :type="impairmentTagType(row.predicted_impairment)" size="small">
                  {{ row.predicted_impairment ?? 'none' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="actual_root_cause" label="Actual Root Cause" min-width="180">
              <template #default="{ row }">{{ row.actual_root_cause ?? '—' }}</template>
            </el-table-column>
            <el-table-column prop="analyst_note" label="Analyst Note" min-width="200">
              <template #default="{ row }">
                <span class="muted">{{ row.analyst_note ?? '—' }}</span>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <!-- ── Underconfident cases ── -->
        <el-card v-if="data.underconfident.length > 0" class="section-card">
          <template #header>
            <span class="card-label">Underconfident Cases</span>
            <el-tag type="info" size="small" style="margin-left:8px">
              Confidence ≤ 50 + Correct
            </el-tag>
          </template>
          <el-table :data="data.underconfident" size="small" stripe>
            <el-table-column label="Analysis" width="120">
              <template #default="{ row }">
                <router-link :to="`/analysis/${row.analysis_id}`" class="analysis-link">
                  {{ row.analysis_id.slice(0, 8) }}…
                </router-link>
              </template>
            </el-table-column>
            <el-table-column prop="source_ip" label="Src IP" width="140" />
            <el-table-column prop="destination_ip" label="Dst IP" width="140" />
            <el-table-column prop="destination_port" label="Port" width="70" align="center">
              <template #default="{ row }">{{ row.destination_port ?? '—' }}</template>
            </el-table-column>
            <el-table-column label="Confidence" width="100" align="center">
              <template #default="{ row }">
                <el-tag type="info" size="small">{{ row.predicted_confidence }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Predicted Impairment" min-width="200">
              <template #default="{ row }">
                <el-tag :type="impairmentTagType(row.predicted_impairment)" size="small">
                  {{ row.predicted_impairment ?? 'none' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="analyst_note" label="Analyst Note" min-width="200">
              <template #default="{ row }">
                <span class="muted">{{ row.analyst_note ?? '—' }}</span>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </template>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { Loading } from '@element-plus/icons-vue'
import api from '@/api/index.js'

const loading = ref(false)
const error   = ref('')
const data    = ref(null)

const verdictCounts = computed(() => data.value?.verdict_counts ?? { correct: 0, partially_correct: 0, incorrect: 0 })

const overallAccuracyPct = computed(() => {
  if (!data.value || data.value.total === 0) return 0
  const n = verdictCounts.value.correct + verdictCounts.value.partially_correct
  return Math.round((n / data.value.total) * 100)
})

function pct(rate) {
  if (rate == null) return 0
  return Math.round(rate * 100)
}

function accuracyColor(pctVal) {
  if (pctVal >= 80) return '#67c23a'
  if (pctVal >= 60) return '#e6a23c'
  return '#f56c6c'
}

function impairmentTagType(imp) {
  if (!imp || imp === 'none') return 'info'
  if (imp.includes('failure') || imp.includes('firewall')) return 'danger'
  if (imp.includes('delay') || imp.includes('backend') || imp.includes('lb_')) return 'warning'
  return ''
}

function outcomeTagType(outcome) {
  if (!outcome || outcome === 'unknown') return 'info'
  if (outcome === 'success') return 'success'
  if (outcome === 'partial_success') return 'warning'
  if (outcome === 'failure') return 'danger'
  return ''
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await api.get('/path-analysis/feedback/calibration')
    data.value = res.data
  } catch (e) {
    error.value = e.response?.data?.detail ?? e.message ?? 'Failed to load calibration data'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.calibration-view {
  max-width: 1200px;
}

.page-header {
  margin-bottom: 24px;
}

.page-header h2 {
  margin: 0 0 6px;
  font-size: 22px;
  font-weight: 700;
  color: #1d2129;
}

.page-desc {
  margin: 0;
  color: #606266;
  font-size: 14px;
  line-height: 1.5;
}

.loading-state {
  display: flex;
  align-items: center;
  gap: 12px;
  color: #606266;
  padding: 40px 0;
  font-size: 15px;
}

.summary-row {
  margin-bottom: 16px;
}

.stat-card {
  text-align: center;
  padding: 8px 0;
}

.stat-value {
  font-size: 32px;
  font-weight: 700;
  color: #1d2129;
  line-height: 1.2;
}

.stat-label {
  font-size: 13px;
  color: #909399;
  margin-top: 4px;
}

.stat-correct .stat-value  { color: #67c23a; }
.stat-partial .stat-value  { color: #e6a23c; }
.stat-incorrect .stat-value { color: #f56c6c; }

.section-card {
  margin-bottom: 16px;
}

.card-label {
  font-weight: 600;
  font-size: 14px;
}

.section-desc {
  margin: 0 0 12px;
  color: #909399;
  font-size: 13px;
}

.accuracy-bar-row {
  display: flex;
  align-items: center;
  gap: 16px;
}

.accuracy-pct {
  font-size: 28px;
  font-weight: 700;
  color: #1d2129;
  min-width: 70px;
  text-align: right;
}

.accuracy-note {
  font-size: 13px;
  color: #909399;
  white-space: nowrap;
}

.bucket-bar-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.bucket-pct {
  font-size: 12px;
  color: #606266;
  min-width: 36px;
  text-align: right;
}

.step-text {
  font-size: 13px;
  color: #303133;
  word-break: break-word;
  white-space: pre-wrap;
}

.analysis-link {
  color: #409eff;
  text-decoration: none;
  font-family: monospace;
  font-size: 13px;
}

.analysis-link:hover {
  text-decoration: underline;
}

.muted {
  color: #909399;
  font-size: 13px;
}
</style>
