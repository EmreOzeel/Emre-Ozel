<template>
  <div class="tsc" :class="{ 'tsc-spark': sparkline }">
    <template v-if="points.length">
      <div class="tsc-plot" :style="{ height: height + 'px' }">
        <svg class="tsc-svg" :viewBox="`0 0 ${W} ${H}`" preserveAspectRatio="none">
          <!-- horizontal gridlines -->
          <template v-if="!sparkline">
            <line
              v-for="g in gridYs"
              :key="g"
              :x1="0" :x2="W" :y1="g" :y2="g"
              class="tsc-grid"
              vector-effect="non-scaling-stroke"
            />
          </template>

          <!-- total series (area + line) -->
          <path v-if="countArea" :d="countArea" class="tsc-area" />
          <path v-if="countLine" :d="countLine" class="tsc-line" vector-effect="non-scaling-stroke" />

          <!-- denied series (line) -->
          <path
            v-if="hasDenied && deniedLine"
            :d="deniedLine"
            class="tsc-line-denied"
            vector-effect="non-scaling-stroke"
          />

          <!-- hover slots with native tooltips -->
          <g v-if="!sparkline">
            <rect
              v-for="(p, i) in points"
              :key="i"
              :x="slotX(i)" :y="0" :width="slotW" :height="H"
              class="tsc-hover"
            >
              <title>{{ tooltip(p) }}</title>
            </rect>
          </g>
        </svg>
        <span v-if="!sparkline" class="tsc-ymax">{{ maxLabel }}</span>
        <div v-if="!sparkline" class="tsc-legend">
          <span class="tsc-lg tsc-lg-total">Total</span>
          <span v-if="hasDenied" class="tsc-lg tsc-lg-denied">Denied</span>
        </div>
      </div>
      <div v-if="!sparkline" class="tsc-x">
        <span v-for="(lbl, i) in xLabels" :key="i">{{ lbl }}</span>
      </div>
    </template>
    <div v-else class="tsc-empty" :style="{ height: height + 'px' }">No data for this range</div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  /** Array of { bucket: RFC3339, count: N, denied_count: N, ... } — tolerant to missing fields */
  series: { type: Array, default: () => [] },
  /** Plot height in px */
  height: { type: Number, default: 160 },
  /** Compact mode: no axes, no legend, no tooltips */
  sparkline: { type: Boolean, default: false },
})

// Virtual coordinate space (stretched to fill via preserveAspectRatio="none")
const W = 600
const H = 100
const PAD = 4

const points = computed(() =>
  (Array.isArray(props.series) ? props.series : [])
    .filter(b => b && typeof b === 'object')
    .map(b => ({
      bucket: b.bucket || '',
      count: Number(b.count) || 0,
      denied: Number(b.denied_count) || 0,
    }))
)

const maxY = computed(() => Math.max(1, ...points.value.map(p => p.count), ...points.value.map(p => p.denied)))
const hasDenied = computed(() => points.value.some(p => p.denied > 0))
const maxLabel = computed(() => maxY.value.toLocaleString())
const gridYs = computed(() => [yOf(maxY.value / 2), yOf(maxY.value)])

function xOf(i) {
  const n = points.value.length
  if (n <= 1) return W / 2
  return (i / (n - 1)) * W
}
function yOf(v) {
  return H - PAD - (v / maxY.value) * (H - 2 * PAD)
}
function buildLine(key) {
  const pts = points.value
  if (!pts.length) return ''
  if (pts.length === 1) {
    const yy = yOf(pts[0][key]).toFixed(2)
    return `M0,${yy} L${W},${yy}`
  }
  return pts.map((p, i) => `${i ? 'L' : 'M'}${xOf(i).toFixed(2)},${yOf(p[key]).toFixed(2)}`).join(' ')
}

const countLine = computed(() => buildLine('count'))
const countArea = computed(() => {
  const lp = countLine.value
  return lp ? `${lp} L${W},${H} L0,${H} Z` : ''
})
const deniedLine = computed(() => buildLine('denied'))

const slotW = computed(() => W / Math.max(1, points.value.length))
function slotX(i) {
  return i * slotW.value
}

const spanMs = computed(() => {
  const pts = points.value
  if (pts.length < 2) return 0
  return Math.abs(new Date(pts[pts.length - 1].bucket) - new Date(pts[0].bucket))
})
const withDate = computed(() => spanMs.value > 24 * 3600 * 1000)

function fmtBucket(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (isNaN(d)) return String(iso)
  const opts = { hour: '2-digit', minute: '2-digit', hour12: false }
  if (withDate.value) { opts.month = '2-digit'; opts.day = '2-digit' }
  return d.toLocaleString(undefined, opts)
}

const xLabels = computed(() => {
  const pts = points.value
  if (!pts.length) return []
  if (pts.length === 1) return [fmtBucket(pts[0].bucket)]
  const mid = pts[Math.floor(pts.length / 2)]
  return [fmtBucket(pts[0].bucket), fmtBucket(mid.bucket), fmtBucket(pts[pts.length - 1].bucket)]
})

function tooltip(p) {
  const lines = [`${fmtBucket(p.bucket)}`, `${p.count.toLocaleString()} transactions`]
  if (p.denied > 0) lines.push(`${p.denied.toLocaleString()} denied`)
  return lines.join('\n')
}
</script>

<style scoped>
.tsc { width: 100%; }
.tsc-plot { position: relative; width: 100%; }
.tsc-svg { display: block; width: 100%; height: 100%; overflow: visible; }

.tsc-grid { stroke: #ebeef5; stroke-width: 1; }
.tsc-area { fill: rgba(64, 158, 255, 0.12); stroke: none; }
.tsc-line { fill: none; stroke: #409eff; stroke-width: 1.5; stroke-linejoin: round; }
.tsc-line-denied { fill: none; stroke: #f56c6c; stroke-width: 1.5; stroke-linejoin: round; }
.tsc-hover { fill: transparent; }
.tsc-hover:hover { fill: rgba(64, 158, 255, 0.08); }

.tsc-ymax {
  position: absolute; top: 0; left: 2px;
  font-size: 10px; color: #c0c4cc;
  font-family: 'SF Mono', 'Menlo', monospace;
  pointer-events: none;
}
.tsc-legend {
  position: absolute; top: 0; right: 2px;
  display: flex; gap: 10px;
  pointer-events: none;
}
.tsc-lg { font-size: 10px; color: #909399; display: flex; align-items: center; gap: 4px; }
.tsc-lg::before { content: ''; width: 8px; height: 2px; border-radius: 1px; display: inline-block; }
.tsc-lg-total::before { background: #409eff; }
.tsc-lg-denied::before { background: #f56c6c; }

.tsc-x {
  display: flex; justify-content: space-between;
  font-size: 10px; color: #909399; margin-top: 4px;
  font-family: 'SF Mono', 'Menlo', monospace;
}
.tsc-empty {
  display: flex; align-items: center; justify-content: center;
  font-size: 12px; color: #c0c4cc;
}
.tsc-spark .tsc-line { stroke-width: 1.2; }
</style>
