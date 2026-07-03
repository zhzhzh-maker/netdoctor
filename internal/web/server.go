package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/netdoctor/netdoctor/internal/doctor"
)

type Server struct {
	service *doctor.Service
	handler http.Handler
}

func New(service *doctor.Service) *Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	server := &Server{service: service, handler: router}
	router.GET("/", server.index)
	router.GET("/api/snapshot", server.snapshot)
	router.GET("/api/events", server.events)
	router.GET("/api/processes", server.processes)
	router.GET("/api/interfaces", server.interfaces)
	return server
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) index(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(indexHTML))
}

func (s *Server) snapshot(c *gin.Context) {
	snapshot := s.service.Snapshot()
	snapshot.Events = nil
	snapshot.Interfaces = nil
	c.JSON(http.StatusOK, snapshot)
}

func (s *Server) events(c *gin.Context) {
	c.JSON(http.StatusOK, s.service.Snapshot().Events)
}

func (s *Server) processes(c *gin.Context) {
	c.JSON(http.StatusOK, s.service.Snapshot().ProcessTraffic)
}

func (s *Server) interfaces(c *gin.Context) {
	c.JSON(http.StatusOK, s.service.Snapshot().SystemTCP)
}

const indexHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>netdoctor</title>
  <script src="https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.prod.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; background: #080c14; color: #e5edf7; }
    #app { position: relative; min-height: 100vh; }
    header { height: 72px; padding: 0 28px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(148,163,184,.16); background: rgba(8,12,20,.78); backdrop-filter: blur(18px); }
    h1 { margin: 0; font-size: 20px; letter-spacing: 0; }
    .subtitle { margin-top: 3px; color: #8ea2bd; font-size: 12px; }
    main { padding: 22px 28px 32px; display: grid; gap: 18px; }
    .toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; justify-content: flex-end; }
    .pill { padding: 7px 10px; border: 1px solid rgba(148,163,184,.18); border-radius: 999px; background: rgba(15,23,42,.7); color: #cfe0f6; font-size: 12px; }
    .hero { display: grid; grid-template-columns: 1.2fr .8fr; gap: 18px; align-items: stretch; }
    .kpis { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .panel { border: 1px solid rgba(148,163,184,.16); border-radius: 8px; background: rgba(15,23,42,.78); box-shadow: 0 18px 50px rgba(0,0,0,.25); min-width: 0; overflow: hidden; }
    .card { padding: 16px; }
    .label { color: #8ea2bd; font-size: 12px; font-weight: 700; text-transform: uppercase; }
    .value { font-size: 28px; margin-top: 8px; color: #f8fafc; overflow-wrap: anywhere; }
    .hint { margin-top: 8px; color: #7dd3fc; font-size: 12px; }
    .section-title { padding: 16px 16px 0; display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .section-title strong { font-size: 14px; }
    .section-title span { color: #8ea2bd; font-size: 12px; }
    .layout { display: grid; grid-template-columns: minmax(0, 1fr) minmax(360px, 500px); gap: 18px; align-items: start; }
    .chart-box { padding: 0 16px 16px; height: 360px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px 14px; border-bottom: 1px solid rgba(148,163,184,.12); text-align: left; font-size: 13px; vertical-align: middle; white-space: nowrap; }
    th { color: #8ea2bd; font-weight: 700; background: rgba(30,41,59,.56); }
    tr:last-child td { border-bottom: 0; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; color: #bae6fd; }
    .muted { color: #8ea2bd; }
    .ok { color: #34d399; }
    .warn { color: #fbbf24; }
    .bar { height: 8px; min-width: 100px; border-radius: 999px; background: rgba(148,163,184,.16); overflow: hidden; }
    .bar span { display: block; height: 100%; border-radius: inherit; background: #38bdf8; }
    canvas { width: 100%; height: 100%; }
    @media (max-width: 1180px) { .hero, .layout { grid-template-columns: 1fr; } .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
    @media (max-width: 640px) { header, main { padding-left: 14px; padding-right: 14px; } header { height: auto; min-height: 72px; align-items: flex-start; flex-direction: column; padding-top: 14px; padding-bottom: 14px; } .toolbar { justify-content: flex-start; } .kpis { grid-template-columns: 1fr; } th, td { padding: 10px; } }
  </style>
</head>
<body>
  <div id="app">
    <header>
      <div>
        <h1>netdoctor</h1>
        <div class="subtitle">eBPF traffic diagnosis</div>
      </div>
      <div class="toolbar">
        <span class="pill">{{ stamp }}</span>
        <span class="pill">programs {{ snapshot.ebpf?.attached?.length || 0 }}</span>
        <span class="pill">hooked NICs {{ tcpInterfaces.length }}</span>
      </div>
    </header>
    <main>
      <section class="hero">
        <div class="kpis">
          <metric-card label="Health" :value="snapshot.host?.health_score || 0" hint="collector"></metric-card>
          <metric-card label="TCP TX" :value="formatBytes(totalTcp.tx)" hint="egress"></metric-card>
          <metric-card label="TCP RX" :value="formatBytes(totalTcp.rx)" hint="ingress"></metric-card>
          <metric-card label="Retrans Rate" :value="percent(totalTcp.rate)" hint="tcp"></metric-card>
        </div>
        <div class="panel card">
          <div class="label">Top eBPF NIC</div>
          <div class="value">{{ topInterface.name }}</div>
          <div class="hint">TX {{ formatBytes(topInterface.tx) }} / RX {{ formatBytes(topInterface.rx) }}</div>
        </div>
      </section>

      <section class="layout">
        <div class="panel">
          <div class="section-title">
            <strong>TCP Traffic By Hooked Interface</strong>
            <span>{{ tcpInterfaces.length }} NICs</span>
          </div>
          <div class="chart-box"><canvas id="tcpChart"></canvas></div>
        </div>
        <div class="panel">
          <data-table :headers="['Interface','TCP TX','TCP RX','Retrans','Rate']" :rows="tcpInterfaceRows"></data-table>
        </div>
      </section>

      <section class="panel">
        <div class="section-title">
          <strong>Process Traffic</strong>
          <span>{{ processes.length }} processes</span>
        </div>
        <data-table :headers="['PID','Process','Proto','TX','RX','Retrans Rate']" :rows="processRows"></data-table>
      </section>
    </main>
  </div>
  <script>
    const { createApp, computed, onMounted, ref, nextTick } = Vue;

    const MetricCard = {
      props: ['label', 'value', 'hint'],
      template: '<div class="panel card"><div class="label">{{ label }}</div><div class="value">{{ value }}</div><div class="hint">{{ hint }}</div></div>'
    };

    const DataTable = {
      props: ['headers', 'rows'],
      template: '<table><thead><tr><th v-for="h in headers" :key="h">{{ h }}</th></tr></thead><tbody><tr v-if="!rows.length"><td :colspan="headers.length" class="muted">No data yet</td></tr><tr v-for="(row,i) in rows" :key="i"><td v-for="(cell,j) in row" :key="j" v-html="cell"></td></tr></tbody></table>'
    };

    createApp({
      components: { MetricCard, DataTable },
      setup() {
        const snapshot = ref({host: {}, ebpf: {}});
        const chart = ref(null);
        const stamp = computed(() => snapshot.value.generated_at ? new Date(snapshot.value.generated_at).toLocaleString() : 'loading');
        const processes = computed(() => snapshot.value.process_traffic || []);
        const tcpInterfaces = computed(() => snapshot.value.system_tcp || []);
        const totalTcp = computed(() => {
          const total = tcpInterfaces.value.reduce((acc, row) => {
            acc.tx += row.tx_bytes || 0; acc.rx += row.rx_bytes || 0; acc.retrans += row.retrans_bytes || 0; return acc;
          }, {tx: 0, rx: 0, retrans: 0});
          total.rate = total.tx + total.rx ? total.retrans / (total.tx + total.rx) : 0;
          return total;
        });
        const topInterface = computed(() => {
          const top = tcpInterfaces.value.slice().sort((a, b) => ((b.tx_bytes || 0) + (b.rx_bytes || 0)) - ((a.tx_bytes || 0) + (a.rx_bytes || 0)))[0];
          if (!top) return {name: 'waiting', tx: 0, rx: 0};
          return {name: top.interface || ('if' + top.ifindex), tx: top.tx_bytes || 0, rx: top.rx_bytes || 0};
        });
        const formatBytes = n => {
          n = Number(n || 0);
          if (n > 1073741824) return (n / 1073741824).toFixed(1) + ' GiB';
          if (n > 1048576) return (n / 1048576).toFixed(1) + ' MiB';
          if (n > 1024) return (n / 1024).toFixed(1) + ' KiB';
          return String(n);
        };
        const percent = n => ((Number(n || 0) * 100).toFixed(2) + '%');
        const tcpInterfaceRows = computed(() => tcpInterfaces.value.map(r => [
          '<code>' + (r.interface || ('if' + r.ifindex)) + '</code>',
          formatBytes(r.tx_bytes),
          formatBytes(r.rx_bytes),
          formatBytes(r.retrans_bytes),
          '<span class="' + (r.retrans_rate > 0.03 ? 'warn' : 'ok') + '">' + percent(r.retrans_rate) + '</span>'
        ]));
        const processRows = computed(() => processes.value.slice(0, 100).map(r => [
          '<code>' + String(r.pid) + '</code>', r.command || '', r.protocol, formatBytes(r.tx_bytes), formatBytes(r.rx_bytes), percent(r.retrans_rate)
        ]));
        const refresh = async () => {
          const res = await fetch('/api/snapshot', {cache: 'no-store'});
          snapshot.value = await res.json();
          await nextTick();
          renderChart();
        };
        const renderChart = () => {
          if (typeof Chart === 'undefined') return;
          const labels = tcpInterfaces.value.map(r => r.interface || ('if' + r.ifindex));
          const data = {
            labels,
            datasets: [
              {label: 'TCP TX', data: tcpInterfaces.value.map(r => r.tx_bytes || 0), backgroundColor: '#2563eb'},
              {label: 'TCP RX', data: tcpInterfaces.value.map(r => r.rx_bytes || 0), backgroundColor: '#16a34a'},
              {label: 'Retrans', data: tcpInterfaces.value.map(r => r.retrans_bytes || 0), backgroundColor: '#dc2626'}
            ]
          };
          if (!chart.value) {
            chart.value = new Chart(document.getElementById('tcpChart'), {
              type: 'bar',
              data,
              options: {
                maintainAspectRatio: false,
                responsive: true,
                plugins: {legend: {position: 'bottom', labels: {color: '#cbd5e1'}}},
                scales: {
                  x: {ticks: {color: '#94a3b8'}, grid: {color: 'rgba(148,163,184,.08)'}},
                  y: {beginAtZero: true, ticks: {color: '#94a3b8'}, grid: {color: 'rgba(148,163,184,.12)'}}
                }
              }
            });
          } else {
            chart.value.data = data; chart.value.update();
          }
        };
        onMounted(() => { refresh(); setInterval(refresh, 2000); });
        return { snapshot, stamp, processes, tcpInterfaces, totalTcp, topInterface, tcpInterfaceRows, processRows, formatBytes, percent };
      }
    }).mount('#app');
  </script>
</body>
</html>`
