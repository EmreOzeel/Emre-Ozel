<template>
  <div class="workflow-controls" v-if="workflow">
    <!-- Status badge / dropdown -->
    <el-dropdown
      v-if="workflow.can_edit_state"
      trigger="click"
      @command="onChangeState"
    >
      <el-tag
        :type="stateTagType"
        effect="dark"
        size="small"
        class="clickable-tag"
      >
        {{ stateLabel }}
        <el-icon class="caret"><ArrowDown /></el-icon>
      </el-tag>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item
            v-for="s in WORKFLOW_STATES"
            :key="s.value"
            :command="s.value"
            :disabled="s.value === workflow.workflow_state"
          >
            {{ s.label }}
          </el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>
    <el-tag v-else :type="stateTagType" effect="dark" size="small">
      {{ stateLabel }}
    </el-tag>

    <!-- Assignee -->
    <el-tooltip
      :content="assigneeTooltip"
      placement="top"
    >
      <el-tag
        v-if="!workflow.can_assign"
        size="small"
        effect="plain"
        type="info"
      >
        {{ assigneeLabel }}
      </el-tag>
      <el-dropdown
        v-else
        trigger="click"
        @command="onChangeAssignee"
      >
        <el-tag
          size="small"
          effect="plain"
          type="info"
          class="clickable-tag"
        >
          {{ assigneeLabel }}
          <el-icon class="caret"><ArrowDown /></el-icon>
        </el-tag>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item :command="null">Unassigned</el-dropdown-item>
            <el-dropdown-item
              v-for="u in users"
              :key="u.id"
              :command="u.id"
              :disabled="u.id === workflow.assigned_user_id"
            >
              {{ u.username }}
            </el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </el-tooltip>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { ArrowDown } from '@element-plus/icons-vue'
import api from '@/api'
import type {
  UserPickerEntry,
  WorkflowResponse,
  WorkflowState,
} from '@/types/analysis'

const props = defineProps<{
  analysisId: string
}>()

const emit = defineEmits<{
  (e: 'updated', workflow: WorkflowResponse): void
}>()

const workflow = ref<WorkflowResponse | null>(null)
const users = ref<UserPickerEntry[]>([])

const WORKFLOW_STATES: { value: WorkflowState; label: string }[] = [
  { value: 'new',          label: 'New' },
  { value: 'in_progress',  label: 'In Progress' },
  { value: 'needs_review', label: 'Needs Review' },
  { value: 'resolved',     label: 'Resolved' },
  { value: 'dismissed',    label: 'Dismissed' },
]

const stateLabel = computed(() => {
  const s = workflow.value?.workflow_state ?? 'new'
  return WORKFLOW_STATES.find(x => x.value === s)?.label ?? s
})

const stateTagType = computed(() => {
  const s = workflow.value?.workflow_state ?? 'new'
  switch (s) {
    case 'new':          return 'info'
    case 'in_progress':  return 'warning'
    case 'needs_review': return 'danger'
    case 'resolved':     return 'success'
    case 'dismissed':    return ''
    default:             return 'info'
  }
})

const assigneeLabel = computed(() => {
  const w = workflow.value
  if (!w) return 'Unassigned'
  if (w.assigned_user_id == null) return 'Unassigned'
  return w.assignee_username ?? `User ${w.assigned_user_id}`
})

const assigneeTooltip = computed(() => {
  if (!workflow.value) return ''
  if (!workflow.value.can_assign) {
    return 'Only the owner or an admin can reassign this investigation.'
  }
  return 'Click to reassign'
})

async function loadWorkflow() {
  try {
    const res = await api.get(`/analyses/${props.analysisId}/workflow`)
    workflow.value = res.data
    emit('updated', res.data)
  } catch {
    workflow.value = null
  }
}

async function loadUsers() {
  try {
    const res = await api.get('/users')
    users.value = res.data
  } catch {
    users.value = []
  }
}

async function onChangeState(state: WorkflowState) {
  if (!workflow.value) return
  if (state === workflow.value.workflow_state) return
  try {
    const res = await api.put(
      `/analyses/${props.analysisId}/workflow/state`,
      { state },
    )
    workflow.value = res.data
    emit('updated', res.data)
    ElMessage.success(`Workflow set to ${stateLabel.value}`)
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail ?? 'Failed to update workflow state')
  }
}

async function onChangeAssignee(userId: number | null) {
  if (!workflow.value) return
  if (userId === workflow.value.assigned_user_id) return
  try {
    const res = await api.put(
      `/analyses/${props.analysisId}/workflow/assignee`,
      { user_id: userId },
    )
    workflow.value = res.data
    emit('updated', res.data)
    ElMessage.success(
      userId == null ? 'Assignee cleared' : `Assigned to ${res.data.assignee_username}`,
    )
  } catch (e: any) {
    ElMessage.error(e?.response?.data?.detail ?? 'Failed to update assignee')
  }
}

watch(
  () => props.analysisId,
  (id) => {
    if (id) loadWorkflow()
  },
)

onMounted(() => {
  loadWorkflow()
  loadUsers()
})
</script>

<style scoped>
.workflow-controls {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.clickable-tag {
  cursor: pointer;
}
.caret {
  margin-left: 4px;
  font-size: 11px;
  vertical-align: middle;
}
</style>
