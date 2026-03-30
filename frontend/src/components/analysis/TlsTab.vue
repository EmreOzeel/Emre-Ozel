<template>
  <div class="tls-tab">
    <el-empty v-if="!tls" description="No TLS data captured" />

    <template v-else>
      <!-- Stats row -->
      <div class="summary-chips">
        <div class="chip">
          <span class="chip-val">{{ tls.total_streams.toLocaleString() }}</span>
          <span class="chip-lbl">TLS Streams</span>
        </div>
        <div class="chip">
          <span class="chip-val">{{ tls.unique_sni.toLocaleString() }}</span>
          <span class="chip-lbl">Unique SNI</span>
        </div>
        <div class="chip" :class="tls.deprecated_count > 0 ? 'danger' : ''">
          <span class="chip-val">{{ tls.deprecated_count.toLocaleString() }}</span>
          <span class="chip-lbl">Deprecated Versions</span>
        </div>
        <div class="chip" :class="tls.weak_cipher_count > 0 ? 'warn' : ''">
          <span class="chip-val">{{ tls.weak_cipher_count.toLocaleString() }}</span>
          <span class="chip-lbl">Weak Ciphers</span>
        </div>
      </div>

      <!-- Deprecated TLS warning alert -->
      <el-alert
        v-if="tls.deprecated_count > 0"
        type="warning"
        :closable="false"
        show-icon
      >
        <template #title>
          {{ tls.deprecated_count }} connection{{ tls.deprecated_count === 1 ? '' : 's' }}
          use deprecated TLS (1.0/1.1). These provide insufficient encryption.
        </template>
      </el-alert>

      <!-- Two-column grid -->
      <div class="grid-2">
        <!-- TLS Versions -->
        <div class="grid-card">
          <div class="card-title">TLS Versions</div>
          <el-table :data="versionRows" size="small" stripe>
            <el-table-column label="Version" min-width="160">
              <template #default="{ row }">
                <span :class="isDeprecated(row.key) ? 'version-deprecated' : 'version-ok'">
                  {{ row.key }}
                </span>
                <el-tag
                  v-if="isDeprecated(row.key)"
                  size="small"
                  type="danger"
                  style="margin-left: 6px"
                >Deprecated</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="value" label="Streams" width="80" align="right" />
          </el-table>
        </div>

        <!-- Top SNI Hosts -->
        <div class="grid-card">
          <div class="card-title">Top SNI Hosts</div>
          <el-table :data="tls.top_sni" size="small" stripe>
            <el-table-column label="SNI" min-width="200">
              <template #default="{ row }">
                <span class="mono">{{ row.sni }}</span>
              </template>
            </el-table-column>
            <el-table-column prop="count" label="Streams" width="80" align="right" />
          </el-table>
        </div>

        <!-- Handshake Types (only if data) -->
        <div v-if="handshakeRows.length" class="grid-card">
          <div class="card-title">Handshake Types</div>
          <el-table :data="handshakeRows" size="small" stripe>
            <el-table-column label="Type" min-width="160">
              <template #default="{ row }">
                <el-tag size="small" type="info">{{ row.key }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="value" label="Count" width="80" align="right" />
          </el-table>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { TlsStats } from '@/types/analysis'

const props = defineProps<{
  tls: TlsStats | null
}>()

interface KvRow {
  key: string
  value: number
}

const DEPRECATED_VERSIONS = new Set(['TLSv1', 'TLSv1.0', 'TLSv1.1', 'TLS 1.0', 'TLS 1.1'])

const versionRows = computed<KvRow[]>(() => {
  if (!props.tls) return []
  return Object.entries(props.tls.version_counts)
    .map(([key, value]) => ({ key, value }))
    .sort((a, b) => b.value - a.value)
})

const handshakeRows = computed<KvRow[]>(() => {
  if (!props.tls) return []
  return Object.entries(props.tls.handshake_counts)
    .map(([key, value]) => ({ key, value }))
    .sort((a, b) => b.value - a.value)
})

function isDeprecated(version: string): boolean {
  return DEPRECATED_VERSIONS.has(version)
}
</script>

<style scoped>
.tls-tab {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.summary-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.chip {
  background: #fff;
  border: 1px solid #ebeef5;
  border-radius: 6px;
  padding: 10px 16px;
  text-align: center;
  min-width: 110px;
}

.chip.warn  { border-color: #f0c040; }
.chip.danger { border-color: #f56c6c; }

.chip-val {
  display: block;
  font-size: 20px;
  font-weight: 700;
  color: #303133;
}

.chip.warn  .chip-val { color: #e6a23c; }
.chip.danger .chip-val { color: #f56c6c; }

.chip-lbl {
  font-size: 11px;
  color: #909399;
  margin-top: 2px;
  display: block;
}

.grid-2 {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

@media (max-width: 900px) {
  .grid-2 { grid-template-columns: 1fr; }
}

.grid-card {
  background: #fff;
  border: 1px solid #ebeef5;
  border-radius: 8px;
  padding: 14px;
}

.card-title {
  font-size: 13px;
  font-weight: 600;
  color: #303133;
  margin-bottom: 10px;
}

.mono { font-family: monospace; font-size: 12px; }

.version-deprecated { font-family: monospace; font-weight: 600; color: #f56c6c; }
.version-ok         { font-family: monospace; font-weight: 600; color: #67c23a; }
</style>
