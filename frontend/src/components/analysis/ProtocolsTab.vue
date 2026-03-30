<template>
  <div class="protocols-tab">
    <el-table :data="sortedProtocols" stripe size="small">
      <el-table-column label="Protocol" min-width="120">
        <template #default="{ row }">
          <span class="proto-name">{{ row.name }}</span>
        </template>
      </el-table-column>

      <el-table-column label="Packets" width="100" align="right">
        <template #default="{ row }">
          {{ row.count.toLocaleString() }}
        </template>
      </el-table-column>

      <el-table-column label="Share" width="90" align="right">
        <template #default="{ row }">
          {{ pct(row.count) }}%
        </template>
      </el-table-column>

      <el-table-column label="Distribution" min-width="200">
        <template #default="{ row }">
          <div class="bar-track">
            <div class="bar-fill" :style="{ width: barWidth(row.count) }" />
          </div>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  protocolStats: Record<string, number>
  totalPackets: number
}>()

interface ProtoRow {
  name: string
  count: number
}

const sortedProtocols = computed<ProtoRow[]>(() =>
  Object.entries(props.protocolStats)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
)

function pct(count: number): string {
  if (!props.totalPackets) return '0.0'
  return ((count / props.totalPackets) * 100).toFixed(1)
}

function barWidth(count: number): string {
  if (!props.totalPackets) return '0%'
  const p = Math.min((count / props.totalPackets) * 100, 100)
  return p.toFixed(2) + '%'
}
</script>

<style scoped>
.protocols-tab {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.proto-name {
  font-family: monospace;
  font-size: 13px;
  font-weight: 600;
  color: #303133;
}

.bar-track {
  background: #f0f2f5;
  border-radius: 4px;
  height: 10px;
  width: 100%;
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  background: linear-gradient(90deg, #409eff, #79bbff);
  border-radius: 4px;
  transition: width 0.3s ease;
}
</style>
