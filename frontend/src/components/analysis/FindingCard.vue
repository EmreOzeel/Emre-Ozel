<template>
  <div class="finding-card" :class="`sev-${finding.severity}`">
    <!-- Header row -->
    <div class="finding-header">
      <el-tag :type="sevType" effect="dark" size="small">
        {{ finding.severity.toUpperCase() }}
      </el-tag>
      <el-tag size="small" type="info">{{ finding.category }}</el-tag>
      <el-tag size="small" :type="confType" plain>
        Confidence: {{ finding.confidence }}
      </el-tag>
      <el-tag size="small" plain>Score {{ finding.score?.toFixed(1) }}</el-tag>
      <span class="finding-title">{{ finding.title }}</span>
    </div>

    <!-- Short description -->
    <p class="finding-desc">{{ finding.description }}</p>

    <!-- What is happening -->
    <div class="interp-block blue" v-if="finding.explanation">
      <div class="iblock-label">What is happening</div>
      <p>{{ finding.explanation }}</p>
    </div>

    <!-- Likely root causes -->
    <div class="interp-block amber" v-if="finding.possible_causes?.length">
      <div class="iblock-label">Likely root causes</div>
      <ul>
        <li v-for="(c, i) in finding.possible_causes" :key="i">{{ c }}</li>
      </ul>
    </div>

    <!-- MITRE ATT&CK -->
    <div class="mitre-row" v-if="finding.mitre?.length">
      <a
        v-for="m in finding.mitre.slice(0, 4)"
        :key="m.technique_id"
        :href="m.url"
        target="_blank"
        class="mitre-badge"
      >
        {{ m.technique_id }}: {{ m.technique_name }}
      </a>
    </div>

    <!-- Evidence samples -->
    <div class="evidence-row" v-if="finding.evidence?.samples?.length">
      <div class="iblock-label">Evidence</div>
      <code v-for="(s, i) in finding.evidence.samples.slice(0, 5)" :key="i">{{ s }}</code>
    </div>

    <!-- Affected hosts -->
    <div class="affected-row" v-if="finding.affected_hosts?.length">
      <span class="iblock-label">Affected hosts:</span>
      <el-tag
        v-for="h in finding.affected_hosts.slice(0, 6)"
        :key="h" size="small" type="danger" plain
      >{{ h }}</el-tag>
    </div>

    <!-- Recommended actions -->
    <div class="actions-block" v-if="finding.recommended_actions?.length">
      <div class="iblock-label">Recommended actions</div>
      <ul>
        <li v-for="(a, i) in finding.recommended_actions" :key="i">{{ a }}</li>
      </ul>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { Finding } from '@/types/analysis'

const props = defineProps<{ finding: Finding }>()

const sevType = computed(() => {
  const m: Record<string, string> = {
    critical: 'danger', high: 'warning', medium: 'warning', low: 'info', info: 'info',
  }
  return m[props.finding.severity] ?? 'info'
})

const confType = computed(() => {
  if (props.finding.confidence === 'high') return 'success'
  if (props.finding.confidence === 'medium') return 'warning'
  return 'info'
})
</script>

<style scoped>
.finding-card {
  border: 1px solid #ebeef5; border-left: 4px solid #dcdfe6;
  border-radius: 6px; padding: 14px 16px; background: #fff;
}
.sev-critical { border-left-color: #f56c6c; }
.sev-high     { border-left-color: #e6a23c; }
.sev-medium   { border-left-color: #f0c040; }
.sev-low      { border-left-color: #409eff; }
.sev-info     { border-left-color: #909399; }

.finding-header { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; }
.finding-title  { font-weight: 600; font-size: 14px; flex: 1; min-width: 200px; }
.finding-desc   { font-size: 13px; color: #606266; margin: 0 0 10px; line-height: 1.6; }

.interp-block { border-radius: 0 4px 4px 0; padding: 8px 12px; margin: 8px 0; font-size: 13px; line-height: 1.7; }
.interp-block.blue { background: #f0f9ff; border-left: 3px solid #409eff; }
.interp-block.amber { background: #fdf6ec; border-left: 3px solid #e6a23c; }
.interp-block p { margin: 0; }
.interp-block ul { margin: 0; padding-left: 18px; color: #606266; }
.interp-block li { margin: 2px 0; }

.iblock-label {
  font-size: 11px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .05em; color: #909399; margin-bottom: 4px;
}

.mitre-row { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
.mitre-badge {
  display: inline-flex; padding: 2px 8px; background: #ecf5ff;
  border: 1px solid #c6e2ff; border-radius: 3px; font-size: 11px;
  color: #409eff; text-decoration: none;
}
.mitre-badge:hover { background: #c6e2ff; }

.evidence-row { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; align-items: center; }
.evidence-row code {
  background: #f5f7fa; padding: 2px 6px; border-radius: 3px;
  font-size: 11px; color: #606266; font-family: monospace;
}

.affected-row { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; margin: 6px 0; }
.affected-row .iblock-label { margin-bottom: 0; }

.actions-block { background: #f0f9eb; border-radius: 4px; padding: 8px 12px; margin-top: 8px; font-size: 13px; }
.actions-block ul { margin: 0; padding-left: 18px; color: #529b2e; line-height: 1.8; }
</style>
