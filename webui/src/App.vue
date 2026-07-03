<template>
  <el-config-provider>
    <div class="shell">
      <aside class="sidebar">
        <div class="brand">
          <div class="brand-mark"><Activity :size="22" /></div>
          <div>
            <strong>netdoctor</strong>
            <span>eBPF Network Console</span>
          </div>
        </div>
        <el-menu class="menu" default-active="overview">
          <el-menu-item index="overview"><Gauge :size="18" />Overview</el-menu-item>
          <el-menu-item index="interfaces"><Network :size="18" />Interfaces</el-menu-item>
          <el-menu-item index="processes"><Cpu :size="18" />Processes</el-menu-item>
        </el-menu>
      </aside>

      <main class="content">
        <header class="topbar">
          <div>
            <h1>Network Diagnosis</h1>
            <p>{{ hostname }} · {{ platform }}</p>
          </div>
          <div class="top-actions">
            <el-tag :type="healthType" effect="dark">Health {{ snapshot.host?.health_score ?? 0 }}</el-tag>
            <el-tag type="info" effect="plain">{{ timestamp }}</el-tag>
          </div>
        </header>

        <section class="metric-grid">
          <MetricCard title="TCP TX" :value="formatBytes(totals.tx)" subtitle="egress bytes" tone="blue" />
          <MetricCard title="TCP RX" :value="formatBytes(totals.rx)" subtitle="ingress bytes" tone="green" />
          <MetricCard title="Retrans" :value="formatBytes(totals.retrans)" subtitle="retransmitted bytes" tone="amber" />
          <MetricCard title="Hooked NICs" :value="String(nics.length)" subtitle="TC eBPF hooks" tone="violet" />
        </section>

        <section class="main-grid">
          <el-card shadow="never" class="chart-card">
            <template #header>
              <div class="card-title">
                <span>Traffic Trend</span>
                <el-segmented v-model="trendWindow" :options="['1m', '5m', '15m']" size="small" />
              </div>
            </template>
            <div ref="trendChartRef" class="chart"></div>
          </el-card>

          <el-card shadow="never" class="chart-card">
            <template #header>
              <div class="card-title">
                <span>Interface Load</span>
                <el-tag size="small" type="success">eBPF</el-tag>
              </div>
            </template>
            <div ref="nicChartRef" class="chart"></div>
          </el-card>
        </section>

        <section class="table-grid">
          <el-card shadow="never">
            <template #header>
              <div class="card-title">
                <span>Per-Interface TCP</span>
                <el-button :icon="RefreshCcw" circle size="small" @click="refresh" />
              </div>
            </template>
            <el-table :data="nics" height="330" empty-text="No hooked interface data">
              <el-table-column prop="interface" label="Interface" min-width="140">
                <template #default="{ row }">
                  <div class="nic-name">
                    <Network :size="16" />
                    <span>{{ row.interface || `if${row.ifindex}` }}</span>
                  </div>
                </template>
              </el-table-column>
              <el-table-column label="TX" min-width="120" align="right">
                <template #default="{ row }">{{ formatBytes(row.tx_bytes) }}</template>
              </el-table-column>
              <el-table-column label="RX" min-width="120" align="right">
                <template #default="{ row }">{{ formatBytes(row.rx_bytes) }}</template>
              </el-table-column>
              <el-table-column label="Retrans" min-width="120" align="right">
                <template #default="{ row }">{{ formatBytes(row.retrans_bytes) }}</template>
              </el-table-column>
              <el-table-column label="Rate" min-width="150">
                <template #default="{ row }">
                  <el-progress :percentage="percentValue(row.retrans_rate)" :status="row.retrans_rate > 0.03 ? 'warning' : 'success'" />
                </template>
              </el-table-column>
            </el-table>
          </el-card>

          <el-card shadow="never">
            <template #header>
              <div class="card-title">
                <span>Top Processes</span>
                <el-input v-model="processQuery" class="search" clearable placeholder="Search process" :prefix-icon="Search" />
              </div>
            </template>
            <el-table :data="filteredProcesses" height="330" empty-text="No process traffic">
              <el-table-column prop="pid" label="PID" width="100" />
              <el-table-column prop="command" label="Process" min-width="160" show-overflow-tooltip />
              <el-table-column prop="protocol" label="Proto" width="90">
                <template #default="{ row }"><el-tag size="small">{{ row.protocol }}</el-tag></template>
              </el-table-column>
              <el-table-column label="TX" min-width="110" align="right">
                <template #default="{ row }">{{ formatBytes(row.tx_bytes) }}</template>
              </el-table-column>
              <el-table-column label="RX" min-width="110" align="right">
                <template #default="{ row }">{{ formatBytes(row.rx_bytes) }}</template>
              </el-table-column>
            </el-table>
          </el-card>
        </section>
      </main>
    </div>
  </el-config-provider>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import * as echarts from 'echarts'
import { Activity, Cpu, Gauge, Network, RefreshCcw, Search } from 'lucide-vue-next'
import MetricCard from './components/MetricCard.vue'
import type { Snapshot, SystemTCPInterfaceStats } from './types'

const snapshot = ref<Snapshot>({ host: {}, ebpf: {}, process_traffic: [], system_tcp: [] })
const processQuery = ref('')
const trendWindow = ref('5m')
const trendChartRef = ref<HTMLDivElement>()
const nicChartRef = ref<HTMLDivElement>()
const history = ref<Array<{ time: string; tx: number; rx: number; retrans: number }>>([])

let trendChart: echarts.ECharts | undefined
let nicChart: echarts.ECharts | undefined
let timer: number | undefined

const hostname = computed(() => snapshot.value.host?.hostname || 'localhost')
const platform = computed(() => snapshot.value.host?.platform || 'linux')
const nics = computed(() => snapshot.value.system_tcp || [])
const timestamp = computed(() => snapshot.value.generated_at ? new Date(snapshot.value.generated_at).toLocaleString() : 'loading')
const totals = computed(() => nics.value.reduce((acc, row) => {
  acc.tx += row.tx_bytes || 0
  acc.rx += row.rx_bytes || 0
  acc.retrans += row.retrans_bytes || 0
  return acc
}, { tx: 0, rx: 0, retrans: 0 }))
const healthType = computed(() => {
  const score = snapshot.value.host?.health_score || 0
  if (score >= 90) return 'success'
  if (score >= 70) return 'warning'
  return 'danger'
})
const filteredProcesses = computed(() => {
  const query = processQuery.value.trim().toLowerCase()
  const rows = snapshot.value.process_traffic || []
  if (!query) return rows.slice(0, 100)
  return rows.filter(row => `${row.pid} ${row.command || ''} ${row.protocol}`.toLowerCase().includes(query)).slice(0, 100)
})

function formatBytes(value?: number): string {
  const n = Number(value || 0)
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GiB`
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(1)} MiB`
  if (n >= 1024) return `${(n / 1024).toFixed(1)} KiB`
  return `${n} B`
}

function percentValue(value?: number): number {
  return Math.min(100, Number(((value || 0) * 100).toFixed(2)))
}

async function refresh() {
  const res = await fetch('/api/snapshot', { cache: 'no-store' })
  snapshot.value = await res.json()
  const now = new Date().toLocaleTimeString()
  history.value.push({ time: now, tx: totals.value.tx, rx: totals.value.rx, retrans: totals.value.retrans })
  const max = trendWindow.value === '1m' ? 30 : trendWindow.value === '15m' ? 450 : 150
  history.value = history.value.slice(-max)
  await nextTick()
  renderCharts()
}

function renderCharts() {
  renderTrendChart()
  renderNicChart()
}

function renderTrendChart() {
  if (!trendChartRef.value) return
  trendChart ||= echarts.init(trendChartRef.value)
  trendChart.setOption({
    tooltip: { trigger: 'axis' },
    legend: { bottom: 0 },
    grid: { top: 24, left: 48, right: 18, bottom: 46 },
    xAxis: { type: 'category', data: history.value.map(row => row.time), boundaryGap: false },
    yAxis: { type: 'value' },
    series: [
      { name: 'TCP TX', type: 'line', smooth: true, showSymbol: false, areaStyle: {}, data: history.value.map(row => row.tx) },
      { name: 'TCP RX', type: 'line', smooth: true, showSymbol: false, areaStyle: {}, data: history.value.map(row => row.rx) },
      { name: 'Retrans', type: 'line', smooth: true, showSymbol: false, data: history.value.map(row => row.retrans) }
    ]
  })
}

function renderNicChart() {
  if (!nicChartRef.value) return
  nicChart ||= echarts.init(nicChartRef.value)
  const rows = nics.value.slice().sort((a: SystemTCPInterfaceStats, b: SystemTCPInterfaceStats) => (b.tx_bytes + b.rx_bytes) - (a.tx_bytes + a.rx_bytes))
  nicChart.setOption({
    tooltip: { trigger: 'axis' },
    legend: { bottom: 0 },
    grid: { top: 24, left: 48, right: 18, bottom: 46 },
    xAxis: { type: 'category', data: rows.map(row => row.interface || `if${row.ifindex}`) },
    yAxis: { type: 'value' },
    series: [
      { name: 'TX', type: 'bar', stack: 'traffic', data: rows.map(row => row.tx_bytes || 0) },
      { name: 'RX', type: 'bar', stack: 'traffic', data: rows.map(row => row.rx_bytes || 0) },
      { name: 'Retrans', type: 'bar', data: rows.map(row => row.retrans_bytes || 0) }
    ]
  })
}

function resizeCharts() {
  trendChart?.resize()
  nicChart?.resize()
}

onMounted(() => {
  refresh()
  timer = window.setInterval(refresh, 2000)
  window.addEventListener('resize', resizeCharts)
})

onUnmounted(() => {
  if (timer) window.clearInterval(timer)
  window.removeEventListener('resize', resizeCharts)
  trendChart?.dispose()
  nicChart?.dispose()
})
</script>
