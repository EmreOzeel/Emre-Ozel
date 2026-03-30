<template>
  <div class="timeline-tab">
    <!-- Filters -->
    <div class="filters-row">
      <el-select v-model="localType" placeholder="All event types" clearable size="small" style="width:180px">
        <el-option label="DNS" value="dns" />
        <el-option label="HTTP" value="http" />
        <el-option label="TLS" value="tls" />
        <el-option label="Security" value="finding" />
        <el-option label="TCP" value="tcp" />
      </el-select>
      <el-select v-model="localSev" placeholder="All severities" clearable size="small" style="width:150px">
        <el-option label="Critical" value="critical" />
        <el-option label="High" value="high" />
        <el-option label="Medium" value="medium" />
        <el-option label="Info" value="info" />
      </el-select>
      <span class="event-count">{{ filtered.length }} events</span>
    </div>

    <el-empty v-if="!filtered.length" description="No events match filters" />

    <el-timeline v-else class="event-timeline">
      <el-timeline-item
        v-for="(ev, i) in filtered.slice(0, 300)"
        :key="i"
        :type="timelineItemType(ev.severity)"
        :timestamp="formatTs(ev.ts)"
        placement="top"
        size="normal"
      >
        <div class="tl-event">
          <div class="tl-header">
            <el-tag :type="sevType(ev.severity)" size="small" effect="plain">
              {{ ev.protocol || ev.type }}
            </el-tag>
            <strong>{{ ev.label }}</strong>
          </div>
          <p class="tl-detail" v-if="ev.detail">{{ ev.detail }}</p>
          <div class="tl-hosts" v-if="ev.src_ip || ev.dst_ip">
            <span v-if="ev.src_ip" class="host-chip">{{ ev.src_ip }}</span>
            <span v-if="ev.dst_ip" class="arrow">→</span>
            <span v-if="ev.dst_ip" class="host-chip">{{ ev.dst_ip }}</span>
          </div>
        </div>
      </el-timeline-item>
    </el-timeline>

    <div class="truncate-note" v-if="filtered.length > 300">
      Showing first 300 of {{ filtered.length }} events
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import type { TimelineEvent } from '@/types/analysis'

const props = defineProps<{ events: TimelineEvent[] }>()

const localType = ref('')
const localSev  = ref('')

const filtered = computed(() => {
  let evs = props.events
  if (localType.value) evs = evs.filter(e => e.type?.includes(localType.value))
  if (localSev.value)  evs = evs.filter(e => e.severity === localSev.value)
  return evs
})

function formatTs(ts: number): string {
  if (!ts || ts === 0) return '—'
  return new Date(ts * 1000).toISOString().replace('T', ' ').substring(0, 19)
}

function sevType(sev: string): string {
  if (sev === 'critical') return 'danger'
  if (sev === 'high') return 'warning'
  if (sev === 'medium') return 'warning'
  return 'info'
}

function timelineItemType(sev: string): '' | 'success' | 'warning' | 'danger' | 'info' | 'primary' {
  if (sev === 'critical') return 'danger'
  if (sev === 'high' || sev === 'medium') return 'warning'
  return 'primary'
}
</script>

<style scoped>
.timeline-tab { display: flex; flex-direction: column; gap: 12px; }
.filters-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.event-count { font-size: 12px; color: #909399; margin-left: 4px; }

.event-timeline { padding: 8px 0; }
.tl-event { padding: 2px 0; }
.tl-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.tl-detail { font-size: 12px; color: #606266; margin: 2px 0 4px; line-height: 1.6; }
.tl-hosts { display: flex; align-items: center; gap: 6px; font-size: 12px; }
.host-chip { font-family: monospace; color: #409eff; }
.arrow { color: #909399; }

.truncate-note { text-align: center; font-size: 12px; color: #909399; }
</style>
