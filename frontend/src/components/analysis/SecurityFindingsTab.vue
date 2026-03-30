<template>
  <div class="security-tab">
    <div class="empty-state" v-if="!securityFindings.length">
      <el-icon size="48" color="#67c23a"><CircleCheck /></el-icon>
      <p>No security findings detected in this capture.</p>
    </div>

    <template v-else>
      <!-- Severity summary row -->
      <div class="sev-summary">
        <div
          v-for="(cnt, sev) in severityCounts"
          :key="sev"
          class="sev-chip"
          :class="sev"
        >
          <span class="sev-val">{{ cnt }}</span>
          <span class="sev-lbl">{{ sev }}</span>
        </div>
      </div>

      <FindingCard
        v-for="f in securityFindings"
        :key="f.id"
        :finding="f"
      />
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { CircleCheck } from '@element-plus/icons-vue'
import FindingCard from './FindingCard.vue'
import type { Finding } from '@/types/analysis'

const SECURITY_CATEGORIES = new Set([
  'reconnaissance', 'dos', 'c2', 'lateral_movement',
  'spoofing', 'exfiltration', 'scan', 'malware',
])

const props = defineProps<{ findings: Finding[] }>()

const securityFindings = computed(() =>
  props.findings.filter(f =>
    SECURITY_CATEGORIES.has(f.category?.toLowerCase()) ||
    f.tags?.some(t => ['scan', 'attack', 'malware', 'c2', 'lateral'].includes(t))
  )
)

const severityCounts = computed(() => {
  const counts: Record<string, number> = {}
  for (const f of securityFindings.value) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1
  }
  return counts
})
</script>

<style scoped>
.security-tab { display: flex; flex-direction: column; gap: 12px; }
.empty-state { text-align: center; padding: 60px 20px; }
.empty-state p { color: #909399; margin-top: 8px; }

.sev-summary { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 4px; }
.sev-chip {
  padding: 10px 18px; border-radius: 6px; text-align: center;
  border: 1px solid #ebeef5; background: #fff;
}
.sev-chip.critical { border-color: #f56c6c; background: #fef0f0; }
.sev-chip.high     { border-color: #e6a23c; background: #fdf6ec; }
.sev-chip.medium   { border-color: #f0c040; background: #fefbe6; }
.sev-val { display: block; font-size: 22px; font-weight: 700; }
.sev-chip.critical .sev-val { color: #f56c6c; }
.sev-chip.high     .sev-val { color: #e6a23c; }
.sev-lbl { font-size: 11px; color: #909399; }
</style>
