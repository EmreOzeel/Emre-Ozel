<template>
  <div class="trust-panel" v-if="trust" :class="panelClass">
    <div class="trust-header">
      <div class="trust-title-row">
        <span class="trust-title">Analysis Trust</span>
        <span class="trust-score-badge" :class="scoreBadgeClass">
          {{ trust.trust_score }}/100
        </span>
        <span class="trust-label-text">{{ trust.trust_label }}</span>
      </div>

      <!-- Component breakdown bar -->
      <div class="trust-components">
        <div class="comp-item">
          <span class="comp-label">Capture quality</span>
          <el-progress
            :percentage="Math.round(trust.components.capture_completeness)"
            :color="progressColor(trust.components.capture_completeness)"
            :stroke-width="7"
            :show-text="true"
          />
        </div>
        <div class="comp-item">
          <span class="comp-label">Evidence quality</span>
          <el-progress
            :percentage="Math.round(trust.components.finding_quality)"
            :color="progressColor(trust.components.finding_quality)"
            :stroke-width="7"
            :show-text="true"
          />
        </div>
        <div class="comp-item penalty" v-if="trust.components.contradiction_penalty > 0">
          <span class="comp-label">Contradiction penalty</span>
          <span class="penalty-val">−{{ trust.components.contradiction_penalty }} pts</span>
        </div>
      </div>
    </div>

    <!-- Expandable detail -->
    <div class="trust-detail" v-if="expanded">
      <!-- Reasons list -->
      <div class="reasons-section">
        <div class="section-heading">Why this score</div>
        <ul class="reasons-list">
          <li v-for="(r, i) in trust.trust_reasons" :key="i">{{ r }}</li>
        </ul>
      </div>

      <!-- Low-confidence findings -->
      <div class="low-conf-section" v-if="trust.low_confidence_findings?.length">
        <div class="section-heading warn">
          {{ trust.low_confidence_findings.length }} finding(s) with weak evidence — treat as preliminary
        </div>
        <div class="low-conf-item" v-for="f in trust.low_confidence_findings" :key="f.rule_id + f.title">
          <el-tag size="small" :type="sevTagType(f.severity)" plain>{{ f.severity.toUpperCase() }}</el-tag>
          <span class="lc-title">{{ f.title }}</span>
          <span class="lc-score">{{ f.confidence_score }}/100</span>
        </div>
        <div class="low-conf-note">
          These findings have fewer than 45/100 evidence points. They may be real but lack
          the packet volume or time coverage needed to confirm them. Verify with EDR telemetry
          or a longer capture before escalating.
        </div>
      </div>
    </div>

    <div class="trust-footer">
      <span class="expand-toggle" @click="expanded = !expanded">
        {{ expanded ? '▲ Hide detail' : '▼ Why this result may be wrong' }}
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import type { TrustScore } from '@/types/analysis'

const props = defineProps<{ trust: TrustScore | null | undefined }>()

const expanded = ref(false)

const panelClass = computed(() => {
  const s = props.trust?.trust_score ?? 100
  if (s >= 85) return 'trust-high'
  if (s >= 70) return 'trust-medium'
  if (s >= 50) return 'trust-low'
  return 'trust-poor'
})

const scoreBadgeClass = computed(() => {
  const s = props.trust?.trust_score ?? 100
  if (s >= 85) return 'badge-high'
  if (s >= 70) return 'badge-medium'
  if (s >= 50) return 'badge-low'
  return 'badge-poor'
})

function progressColor(val: number): string {
  if (val >= 80) return '#67c23a'
  if (val >= 60) return '#e6a23c'
  return '#f56c6c'
}

function sevTagType(sev: string): string {
  const m: Record<string, string> = { critical: 'danger', high: 'warning', medium: 'warning', low: 'info', info: 'info' }
  return m[sev] ?? 'info'
}
</script>

<style scoped>
.trust-panel {
  background: #fff;
  border: 1px solid #ebeef5;
  border-left: 4px solid #dcdfe6;
  border-radius: 6px;
  padding: 14px 18px;
  margin-bottom: 16px;
}
.trust-high   { border-left-color: #67c23a; }
.trust-medium { border-left-color: #e6a23c; }
.trust-low    { border-left-color: #f56c6c; }
.trust-poor   { border-left-color: #f56c6c; background: #fff5f5; }

.trust-header { display: flex; flex-direction: column; gap: 10px; }

.trust-title-row {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
}
.trust-title {
  font-size: 14px; font-weight: 700; color: #303133;
  text-transform: uppercase; letter-spacing: .04em;
}
.trust-score-badge {
  font-size: 18px; font-weight: 800; padding: 2px 10px;
  border-radius: 4px; font-variant-numeric: tabular-nums;
}
.badge-high   { background: #f0f9eb; color: #529b2e; border: 1px solid #b3e19d; }
.badge-medium { background: #fdf6ec; color: #b88230; border: 1px solid #f5dab1; }
.badge-low    { background: #fef0f0; color: #c45656; border: 1px solid #fbc4c4; }
.badge-poor   { background: #fef0f0; color: #c45656; border: 1px solid #f89898; }

.trust-label-text { font-size: 13px; color: #606266; flex: 1; }

.trust-components {
  display: grid;
  grid-template-columns: 160px 1fr;
  gap: 6px 12px;
  align-items: center;
}
.comp-item { display: contents; }
.comp-item.penalty { display: flex; align-items: center; gap: 8px; grid-column: 1 / -1; }
.comp-label {
  font-size: 12px; color: #909399; white-space: nowrap;
  font-weight: 600;
}
.penalty-val { font-size: 13px; font-weight: 700; color: #f56c6c; }

/* Detail section */
.trust-detail { margin-top: 12px; border-top: 1px solid #f0f0f0; padding-top: 12px; }

.reasons-section { margin-bottom: 12px; }
.section-heading {
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .05em; color: #909399; margin-bottom: 6px;
}
.section-heading.warn { color: #e6a23c; }

.reasons-list {
  margin: 0; padding-left: 18px; color: #606266;
  font-size: 13px; line-height: 1.7;
}
.reasons-list li { margin: 2px 0; }

.low-conf-section { background: #fdf6ec; border-radius: 4px; padding: 10px 12px; }
.low-conf-item {
  display: flex; align-items: center; gap: 8px;
  padding: 4px 0; font-size: 13px;
}
.lc-title { flex: 1; color: #303133; }
.lc-score {
  font-size: 12px; font-weight: 700; color: #e6a23c;
  font-variant-numeric: tabular-nums;
}

.low-conf-note {
  margin-top: 8px; font-size: 12px; color: #909399; line-height: 1.6;
  border-top: 1px solid #f5dab1; padding-top: 8px;
}

.trust-footer { margin-top: 10px; }
.expand-toggle {
  font-size: 12px; color: #409eff; cursor: pointer; user-select: none;
}
.expand-toggle:hover { text-decoration: underline; }
</style>
