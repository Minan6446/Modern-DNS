<script setup lang="ts">
/**
 * AclTextarea — multi-line ACL editor with per-line validation,
 * an inline error list, a「填入我的 IP」shortcut, and a soft cap on
 * the line count.
 *
 * Wire contract
 * ─────────────
 *  modelValue:        v-model string, newline-separated entries.
 *  rows:              row count (matches the el-input prop).
 *  placeholder:       textarea placeholder (newline-aware).
 *  allowNegation:     when false, lines starting with "!" are flagged.
 *                     Defaults to true (BIND-style allow-with-deny).
 *  hint:              optional small grey text under the label, e.g.
 *                     "支持 CIDR、IP、主机名；以 # 开头为注释".
 *  maxLines:          soft warning threshold; values > this surface a
 *                     yellow banner but do NOT block saving.
 *  showWhoami:        adds the「填入我的 IP」button. Defaults to true.
 *
 * Why a soft cap (not hard reject)
 * ────────────────────────────────
 * Real-world deployments do occasionally cross 200 lines (e.g. office
 * CIDR blocks). We warn (yellow stripe) instead of rejecting so the
 * operator gets a heads-up about possible engine-lookup overhead
 * without being blocked from saving a legitimate large list.
 *
 * Why we don't gate "save" on errors
 * ──────────────────────────────────
 * Same philosophy as the validateZoneOptions in the backend: errors
 * are surfaced inline + reflected in `:has-errors` event the parent
 * can react to (we emit `update:hasErrors` separately). It's the
 * parent's choice whether a save with errors is blocked — for the
 * zone-options dialog we recommend disabling the save button, which
 * the parent does via `:confirm-disabled`.
 */
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { ElMessage } from 'element-plus'
import { parseAcl, type AclLineResult } from '../utils/aclParser'
import { whoami } from '../api/system'

const props = withDefaults(
  defineProps<{
    modelValue: string
    rows?: number
    placeholder?: string
    allowNegation?: boolean
    hint?: string
    maxLines?: number
    showWhoami?: boolean
  }>(),
  {
    rows: 3,
    placeholder: '',
    allowNegation: true,
    hint: '',
    maxLines: 200,
    showWhoami: true,
  },
)

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void
  /** Mirrors `errors.length > 0` — parent can disable Save when truthy. */
  (e: 'update:hasErrors', value: boolean): void
}>()

const { t } = useI18n()

const local = computed({
  get: () => props.modelValue,
  set: (v: string) => emit('update:modelValue', v),
})

// Recompute on every keystroke. parseAcl is regex-based and O(n) in
// line count — comfortably under 1 ms for the soft cap. No need to
// debounce.
const summary = computed(() => parseAcl(local.value))

// Post-process: if negation is disallowed, flag any line where a `!`
// prefix produced a valid kind. We don't change the parser API for
// this — easier to apply the policy here than to thread a flag through.
const effectiveErrors = computed<AclLineResult[]>(() => {
  if (props.allowNegation) {
    return summary.value.errors
  }
  const extras = summary.value.lines
    .filter((l) => l.negated && l.error === '')
    .map((l) => ({
      ...l,
      error: t('acl.negationNotAllowed'),
    }))
  return [...summary.value.errors, ...extras]
})

const overLimit = computed(() => summary.value.validEntries > props.maxLines)

// Emit hasErrors whenever the boolean flips so the parent can react.
watch(
  effectiveErrors,
  (errs) => emit('update:hasErrors', errs.length > 0),
  { immediate: true },
)

const whoamiLoading = ref(false)
const handleFillMyIp = async () => {
  if (whoamiLoading.value) return
  whoamiLoading.value = true
  try {
    const { data } = await whoami()
    const ip = (data?.ip || '').trim()
    if (!ip) {
      ElMessage.warning(t('acl.whoamiEmpty'))
      return
    }
    // Insert as a new line. If the existing content already ends with
    // a newline (or is empty) we don't add an extra one — keeps the
    // textarea tidy when the operator clicks repeatedly.
    const current = local.value
    const needsNewline = current.length > 0 && !current.endsWith('\n')
    local.value = current + (needsNewline ? '\n' : '') + ip
    ElMessage.success(t('acl.whoamiFilled', { ip }))
  } finally {
    whoamiLoading.value = false
  }
}
</script>

<template>
  <div class="acl-textarea">
    <el-input
      v-model="local"
      type="textarea"
      :rows="rows"
      :placeholder="placeholder"
      class="acl-textarea__input"
      :class="{ 'acl-textarea__input--error': effectiveErrors.length > 0 }"
    />

    <div class="acl-textarea__toolbar">
      <span class="acl-textarea__stats">
        {{ t('acl.statsValid', { n: summary.validEntries }) }}
        <template v-if="effectiveErrors.length > 0">
          ·
          <span class="acl-textarea__stats--error">
            {{ t('acl.statsErrors', { n: effectiveErrors.length }) }}
          </span>
        </template>
      </span>
      <el-button
        v-if="showWhoami"
        size="small"
        link
        type="primary"
        :loading="whoamiLoading"
        @click="handleFillMyIp"
      >
        {{ t('acl.fillMyIp') }}
      </el-button>
    </div>

    <div v-if="hint" class="acl-textarea__hint">{{ hint }}</div>

    <!-- Soft-cap warning. Yellow banner, doesn't block save. -->
    <div v-if="overLimit" class="acl-textarea__warn">
      {{ t('acl.overLimit', { max: maxLines, n: summary.validEntries }) }}
    </div>

    <!-- Per-line error list. Capped at 5 visible to avoid huge red
         walls on a mass-paste; we still emit hasErrors=true so the
         parent can disable save. -->
    <ul v-if="effectiveErrors.length > 0" class="acl-textarea__errors">
      <li v-for="err in effectiveErrors.slice(0, 5)" :key="err.lineNumber">
        {{ t('acl.errLine', { n: err.lineNumber }) }} {{ err.error }}
      </li>
      <li v-if="effectiveErrors.length > 5" class="acl-textarea__errors-more">
        {{ t('acl.errMore', { n: effectiveErrors.length - 5 }) }}
      </li>
    </ul>
  </div>
</template>

<style scoped>
.acl-textarea {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.acl-textarea__input :deep(.el-textarea__inner) {
  font-family: 'JetBrains Mono', 'Consolas', monospace;
  font-size: 12px;
  line-height: 1.7;
}
.acl-textarea__input--error :deep(.el-textarea__inner) {
  /* Subtle red ring so the operator knows *this* textarea is the
     one with the bad lines, but we don't paint the whole field
     red — that'd be too noisy when only one of 30 lines is off. */
  border-color: var(--el-color-danger);
  box-shadow: 0 0 0 1px var(--el-color-danger-light-7);
}
.acl-textarea__toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.acl-textarea__stats {
  font-size: 11px;
  color: var(--app-text-assist, #909399);
}
.acl-textarea__stats--error {
  color: var(--el-color-danger);
  font-weight: 600;
}
.acl-textarea__hint {
  font-size: 11px;
  color: var(--app-text-assist, #909399);
}
.acl-textarea__warn {
  font-size: 11px;
  color: var(--el-color-warning);
  background: var(--el-color-warning-light-9, #faecd8);
  border: 1px solid var(--el-color-warning-light-7, #f3d19e);
  border-radius: 4px;
  padding: 4px 8px;
}
.acl-textarea__errors {
  margin: 0;
  padding: 4px 8px 4px 24px;
  list-style: disc;
  background: var(--el-color-danger-light-9, #fef0f0);
  border: 1px solid var(--el-color-danger-light-7, #fbc4c4);
  border-radius: 4px;
}
.acl-textarea__errors li {
  font-size: 11px;
  color: var(--el-color-danger);
  line-height: 1.6;
}
.acl-textarea__errors-more {
  list-style: none;
  margin-left: -16px;
  font-style: italic;
}
</style>
