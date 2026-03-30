<template>
  <div class="flow-interp">
    <!-- Confidence + handshake badges -->
    <div class="badge-row">
      <el-tag :type="hsTagType" size="small" effect="plain">
        {{ session.handshake_label || session.handshake_status }}
      </el-tag>
      <el-tag :type="closeTagType" size="small" effect="plain">
        {{ session.close_label || session.close_behavior }}
      </el-tag>
      <el-tag :type="confTagType" size="small" plain>
        Confidence: {{ session.confidence }}
      </el-tag>
    </div>

    <!-- Confidence note — only if mid-stream or low -->
    <div class="conf-note" v-if="session.confidence !== 'high' && session.confidence_note">
      <el-icon><Warning /></el-icon>
      {{ session.confidence_note }}
    </div>

    <!-- What -->
    <div class="section" v-if="session.interp_what">
      <div class="section-label">What is happening</div>
      <p>{{ session.interp_what }}</p>
    </div>

    <!-- Why it matters -->
    <div class="section amber" v-if="session.interp_why">
      <div class="section-label">Why it matters</div>
      <p>{{ session.interp_why }}</p>
    </div>

    <!-- Root cause -->
    <div class="section" v-if="session.interp_root_cause">
      <div class="section-label">Root cause assessment</div>
      <p>{{ session.interp_root_cause }}</p>
    </div>

    <!-- Check next -->
    <div class="check-next" v-if="session.interp_check_next?.length">
      <div class="section-label">What to check next</div>
      <ul>
        <li v-for="(c, i) in session.interp_check_next" :key="i">{{ c }}</li>
      </ul>
    </div>

    <!-- Asymmetry note -->
    <div class="asym-note" v-if="session.asymmetry_note">
      <el-icon><InfoFilled /></el-icon>
      {{ session.asymmetry_note }}
    </div>

    <!-- Quality notes (retrans, dup acks, zero win) -->
    <div class="quality-note" v-for="(q, i) in session.quality_notes" :key="i">
      <el-icon><WarningFilled /></el-icon>
      {{ q }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Warning, InfoFilled, WarningFilled } from '@element-plus/icons-vue'
import type { TCPSession } from '@/types/analysis'

const props = defineProps<{ session: TCPSession }>()

const hsTagType = computed(() => {
  if (props.session.handshake_status === 'complete') return 'success'
  if (props.session.handshake_status === 'failed') return 'danger'
  return 'warning' // mid_stream
})

const closeTagType = computed(() => {
  if (props.session.close_behavior === 'fin') return 'success'
  if (props.session.close_behavior === 'rst') return 'danger'
  return 'info'
})

const confTagType = computed(() => {
  if (props.session.confidence === 'high') return 'success'
  if (props.session.confidence === 'medium') return 'warning'
  return 'danger'
})
</script>

<style scoped>
.flow-interp { padding: 12px 16px; background: #fafafa; font-size: 13px; line-height: 1.7; }

.badge-row { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px; }

.conf-note {
  display: flex; align-items: flex-start; gap: 6px;
  background: #fdf6ec; border-left: 3px solid #e6a23c;
  padding: 6px 10px; border-radius: 0 4px 4px 0;
  font-size: 12px; color: #b8741a; margin-bottom: 10px; line-height: 1.6;
}

.section { margin-bottom: 10px; padding: 8px 12px; border-radius: 0 4px 4px 0; }
.section:not(.amber) { background: #f0f9ff; border-left: 3px solid #409eff; }
.section.amber { background: #fdf6ec; border-left: 3px solid #e6a23c; }
.section p { margin: 0; color: #303133; }

.section-label {
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .06em; color: #909399; margin-bottom: 4px;
}

.check-next { margin-bottom: 10px; }
.check-next ul { margin: 4px 0 0; padding-left: 18px; color: #529b2e; }
.check-next li { margin: 2px 0; }

.asym-note, .quality-note {
  display: flex; align-items: flex-start; gap: 6px;
  font-size: 12px; color: #606266; margin-top: 6px;
}
.asym-note .el-icon { color: #409eff; margin-top: 2px; }
.quality-note .el-icon { color: #e6a23c; margin-top: 2px; }
</style>
