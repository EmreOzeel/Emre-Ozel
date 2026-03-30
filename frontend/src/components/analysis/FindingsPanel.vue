<template>
  <div class="findings-panel">
    <!-- Filters -->
    <div class="filters-row">
      <el-select v-model="filters.severity" placeholder="All severities" clearable size="small" style="width:150px">
        <el-option label="Critical" value="critical" />
        <el-option label="High" value="high" />
        <el-option label="Medium" value="medium" />
        <el-option label="Low" value="low" />
        <el-option label="Info" value="info" />
      </el-select>
      <el-select v-model="filters.category" placeholder="All categories" clearable size="small" style="width:170px">
        <el-option v-for="c in categories" :key="c" :label="c" :value="c" />
      </el-select>
      <el-input
        v-model="filters.search"
        placeholder="Search findings..."
        size="small"
        clearable
        style="width:220px"
      />
      <span class="result-count">{{ filtered.length }} finding(s)</span>
    </div>

    <!-- Empty state -->
    <div class="empty-state" v-if="!filtered.length">
      <el-icon size="48" color="#67c23a"><CircleCheck /></el-icon>
      <p>No findings match the current filters.</p>
    </div>

    <!-- Grouped by severity -->
    <template v-else>
      <div
        v-for="sev in severityOrder"
        :key="sev"
      >
        <div
          v-if="bySeverity[sev]?.length"
          class="sev-group"
        >
          <div class="sev-group-header">
            <el-tag :type="sevTagType(sev)" effect="dark" size="small">
              {{ sev.toUpperCase() }}
            </el-tag>
            <span class="group-count">{{ bySeverity[sev].length }} finding(s)</span>
          </div>
          <div class="group-cards">
            <FindingCard
              v-for="f in bySeverity[sev]"
              :key="f.id"
              :finding="f"
            />
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { CircleCheck } from '@element-plus/icons-vue'
import FindingCard from './FindingCard.vue'
import type { Finding, FindingFilters } from '@/types/analysis'

// FindingFilters lives in composable but re-declare for prop typing clarity
interface Filters { severity: string; category: string; search: string }

const props = defineProps<{
  findings: Finding[]
  filters: Filters
}>()

const severityOrder = ['critical', 'high', 'medium', 'low', 'info'] as const

const categories = computed(() =>
  [...new Set(props.findings.map(f => f.category))].sort()
)

const filtered = computed(() => {
  let list = props.findings
  if (props.filters.severity) list = list.filter(f => f.severity === props.filters.severity)
  if (props.filters.category) list = list.filter(f => f.category === props.filters.category)
  if (props.filters.search) {
    const q = props.filters.search.toLowerCase()
    list = list.filter(f =>
      f.title.toLowerCase().includes(q) ||
      f.description.toLowerCase().includes(q) ||
      f.explanation?.toLowerCase().includes(q)
    )
  }
  return list
})

const bySeverity = computed(() => {
  const groups: Record<string, Finding[]> = {}
  for (const sev of severityOrder) {
    groups[sev] = filtered.value.filter(f => f.severity === sev)
  }
  return groups
})

function sevTagType(sev: string): string {
  const m: Record<string, string> = {
    critical: 'danger', high: 'warning', medium: 'warning', low: 'info', info: 'info',
  }
  return m[sev] ?? 'info'
}
</script>

<style scoped>
.findings-panel { display: flex; flex-direction: column; gap: 12px; }
.filters-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 4px; }
.result-count { font-size: 12px; color: #909399; margin-left: 4px; }

.empty-state { text-align: center; padding: 60px 20px; }
.empty-state p { color: #909399; margin-top: 8px; }

.sev-group { margin-bottom: 16px; }
.sev-group-header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.group-count { font-size: 12px; color: #909399; }
.group-cards { display: flex; flex-direction: column; gap: 10px; }
</style>
