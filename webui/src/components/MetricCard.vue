<template>
  <el-card shadow="never" class="metric-card" :class="`tone-${tone}`">
    <div class="metric-head">
      <span>{{ title }}</span>
      <component :is="icon" :size="18" />
    </div>
    <strong>{{ value }}</strong>
    <small>{{ subtitle }}</small>
  </el-card>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { Activity, ArrowDownToLine, ArrowUpFromLine, RadioTower } from 'lucide-vue-next'

const props = defineProps<{
  title: string
  value: string
  subtitle: string
  tone: 'blue' | 'green' | 'amber' | 'violet'
}>()

const icon = computed(() => {
  if (props.tone === 'blue') return ArrowUpFromLine
  if (props.tone === 'green') return ArrowDownToLine
  if (props.tone === 'amber') return Activity
  return RadioTower
})
</script>
