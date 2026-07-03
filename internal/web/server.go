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
	c.JSON(http.StatusOK, snapshot)
}

func (s *Server) events(c *gin.Context) {
	c.JSON(http.StatusOK, s.service.Snapshot().Events)
}

func (s *Server) processes(c *gin.Context) {
	c.JSON(http.StatusOK, s.service.Snapshot().ProcessTraffic)
}

func (s *Server) interfaces(c *gin.Context) {
	c.JSON(http.StatusOK, s.service.Snapshot().Interfaces)
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
    :root { color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; background: #eef2f7; color: #111827; }
    header { height: 58px; padding: 0 22px; display: flex; align-items: center; justify-content: space-between; background: #0f172a; color: #f8fafc; }
    h1 { margin: 0; font-size: 18px; letter-spacing: 0; }
    main { padding: 18px 22px 28px; display: grid; gap: 16px; }
    .toolbar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    .pill { padding: 5px 9px; border-radius: 999px; background: #1e293b; color: #dbeafe; font-size: 12px; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .panel { border: 1px solid #d7dde6; border-radius: 8px; background: #fff; padding: 14px; min-width: 0; box-shadow: 0 1px 2px rgba(15,23,42,.05); }
    .label { color: #64748b; font-size: 12px; }
    .value { font-size: 24px; margin-top: 6px; overflow-wrap: anywhere; }
    .layout { display: grid; grid-template-columns: minmax(0, 1fr) minmax(360px, 460px); gap: 16px; align-items: start; }
    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d7dde6; border-radius: 8px; overflow: hidden; }
    th, td { padding: 10px 12px; border-bottom: 1px solid #e5e7eb; text-align: left; font-size: 13px; vertical-align: top; }
    th { color: #64748b; font-weight: 700; background: #f8fafc; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }
    .ok { color: #047857; } .bad { color: #b91c1c; }
    .muted { color: #64748b; }
    canvas { width: 100%; max-height: 300px; }
    @media (max-width: 1000px) { .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .layout { grid-template-columns: 1fr; } }
    @media (max-width: 560px) { header, main { padding-left: 14px; padding-right: 14px; } .grid { grid-template-columns: 1fr; } }
    @media (prefers-color-scheme: dark) {
      body { background: #0b1120; color: #e5e7eb; }
      .panel, table { background: #111827; border-color: #273244; }
      th { background: #172033; color: #cbd5e1; }
      th, td { border-bottom-color: #273244; }
      .label, .muted { color: #94a3b8; }
    }
  </style>
</head>
<body>
  <div id="app">
    <header>
      <h1>netdoctor</h1>
      <div class="toolbar">
        <span class="pill">{{ stamp }}</span>
        <span class="pill">attached {{ snapshot.ebpf?.attached?.length || 0 }}</span>
        <span class="pill">interfaces {{ allInterfaces.length }}</span>
      </div>
    </header>
    <main>
      <section class="grid">
        <metric-card label="Health" :value="snapshot.host?.health_score || 0"></metric-card>
        <metric-card label="Processes" :value="processes.length"></metric-card>
        <metric-card label="TCP TX/RX" :value="formatBytes(totalTcp.tx) + ' / ' + formatBytes(totalTcp.rx)"></metric-card>
        <metric-card label="Retrans Rate" :value="percent(totalTcp.rate)"></metric-card>
      </section>

      <section class="layout">
        <div class="panel">
          <div class="label">System TCP By Interface</div>
          <canvas id="tcpChart"></canvas>
        </div>
        <div>
          <data-table :headers="['Interface','TCP TX','TCP RX','Retrans','Rate']" :rows="tcpInterfaceRows"></data-table>
        </div>
      </section>

      <section>
        <div class="panel" style="padding:0">
          <data-table :headers="['PID','Process','Proto','TX','RX','Retrans Rate']" :rows="processRows"></data-table>
        </div>
      </section>

      <section>
        <div class="panel" style="padding:0">
          <data-table :headers="['Index','Interface','State','Type','MTU','MAC','IPs']" :rows="allInterfaceRows"></data-table>
        </div>
      </section>
    </main>
  </div>
  <script>
    const { createApp, computed, onMounted, ref, nextTick } = Vue;

    const MetricCard = {
      props: ['label', 'value'],
      template: '<div class="panel"><div class="label">{{ label }}</div><div class="value">{{ value }}</div></div>'
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
        const allInterfaces = computed(() => snapshot.value.interfaces || []);
        const totalTcp = computed(() => {
          const total = tcpInterfaces.value.reduce((acc, row) => {
            acc.tx += row.tx_bytes || 0; acc.rx += row.rx_bytes || 0; acc.retrans += row.retrans_bytes || 0; return acc;
          }, {tx: 0, rx: 0, retrans: 0});
          total.rate = total.tx + total.rx ? total.retrans / (total.tx + total.rx) : 0;
          return total;
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
          r.interface || ('if' + r.ifindex), formatBytes(r.tx_bytes), formatBytes(r.rx_bytes), formatBytes(r.retrans_bytes), percent(r.retrans_rate)
        ]));
        const processRows = computed(() => processes.value.slice(0, 100).map(r => [
          String(r.pid), r.command || '', r.protocol, formatBytes(r.tx_bytes), formatBytes(r.rx_bytes), percent(r.retrans_rate)
        ]));
        const allInterfaceRows = computed(() => allInterfaces.value.map(r => [
          String(r.index || ''),
          r.name || '',
          '<span class="' + (r.state === 'up' ? 'ok' : 'bad') + '">' + (r.state || '') + '</span>',
          r.type || '',
          String(r.mtu || ''),
          '<code>' + (r.mac || '-') + '</code>',
          '<code>' + ((r.ips || []).join('<br>') || '-') + '</code>'
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
            chart.value = new Chart(document.getElementById('tcpChart'), {type: 'bar', data, options: {responsive: true, plugins: {legend: {position: 'bottom'}}, scales: {y: {beginAtZero: true}}}});
          } else {
            chart.value.data = data; chart.value.update();
          }
        };
        onMounted(() => { refresh(); setInterval(refresh, 2000); });
        return { snapshot, stamp, processes, allInterfaces, totalTcp, tcpInterfaceRows, processRows, allInterfaceRows, formatBytes, percent };
      }
    }).mount('#app');
  </script>
</body>
</html>`
