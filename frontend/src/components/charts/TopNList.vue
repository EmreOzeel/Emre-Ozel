<template>
  <div class="tnl">
    <div v-if="!rows.length" class="tnl-empty">{{ emptyText }}</div>
    <div v-for="(r, i) in rows" :key="`${r.key}-${i}`" class="tnl-row" :title="rowTitle(r)">
      <div class="tnl-top">
        <span class="tnl-key mono">{{ r.key || '—' }}</span>
        <span v-if="r.denied > 0" class="tnl-denied">{{ r.denied.toLocaleString() }} denied</span>
        <span class="tnl-count">{{ r.count.toLocaleString() }}</span>
      </div>
      <div class="tnl-bar">
        <div class="tnl-fill" :style="{ width: pct(r.count) + '%' }"></div>
        <div v-if="r.denied > 0" class="tnl-fill tnl-fill-denied" :style="{ width: pct(r.denied) + '%' }"></div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  /** Array of { key, count, denied_count, bytes_total } — tolerant to missing fields */
  items: { type: Array, default: () => [] },
  emptyText: { type: String, default: 'No data' },
})

const rows = computed(() =>
  (Array.isArray(props.items) ? props.items : [])
    .filter(it => it && typeof it === 'object')
    .map(it => ({
      key: it.key != null ? String(it.key) : '',
      count: Number(it.count) || 0,
      denied: Number(it.denied_count) || 0,
      bytes: Number(it.bytes_total) || 0,
    }))
)

const maxCount = computed(() => Math.max(1, ...rows.value.map(r => r.count)))

function pct(v) {
  return Math.min(100, Math.max(0, (v / maxCount.value) * 100))
}

function fmtBytes(n) {
  if (!n) return '0B'
  if (n < 1024) return `${n}B`
  if (n < 1048576) return `${(n / 1024).toFixed(1)}K`
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)}M`
  return `${(n / 1073741824).toFixed(1)}G`
}

function rowTitle(r) {
  const parts = [`${r.key || '—'}: ${r.count.toLocaleString()} transactions`]
  if (r.denied > 0) parts.push(`${r.denied.toLocaleString()} denied`)
  if (r.bytes > 0) parts.push(`${fmtBytes(r.bytes)} total`)
  return parts.join(' · ')
}
</script>

<style scoped>
.tnl { display: flex; flex-direction: column; gap: 7px; }
.tnl-row { cursor: default; }
.tnl-top { display: flex; align-items: baseline; gap: 8px; margin-bottom: 2px; }
.tnl-key {
  flex: 1; min-width: 0;
  font-size: 12px; color: #303133;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.mono { font-family: 'SF Mono', 'Menlo', monospace; }
.tnl-denied {
  font-size: 10px; font-weight: 600; color: #f56c6c;
  background: #fde2e2; border-radius: 8px; padding: 1px 6px;
  white-space: nowrap;
}
.tnl-count { font-size: 12px; font-weight: 600; color: #606266; white-space: nowrap; }
.tnl-bar { position: relative; height: 6px; background: #f0f2f5; border-radius: 3px; overflow: hidden; }
.tnl-fill {
  position: absolute; top: 0; left: 0; height: 100%;
  background: #409eff; border-radius: 3px;
  transition: width 0.3s ease;
}
.tnl-fill-denied { background: #f56c6c; }
.tnl-empty { font-size: 12px; color: #c0c4cc; text-align: center; padding: 16px 0; }
</style>
