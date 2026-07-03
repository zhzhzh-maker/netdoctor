package web

import (
	"encoding/json"
	"net/http"

	"github.com/netdoctor/netdoctor/internal/doctor"
)

type Server struct {
	service *doctor.Service
	handler http.Handler
}

func New(service *doctor.Service) *Server {
	server := &Server{service: service}
	mux := http.NewServeMux()
	mux.HandleFunc("/", server.index)
	mux.HandleFunc("/api/snapshot", server.snapshot)
	mux.HandleFunc("/api/events", server.events)
	server.handler = mux
	return server
}

func (s *Server) Handler() http.Handler {
	return s.handler
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.service.Snapshot())
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.service.Snapshot().Events)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(value); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

const indexHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>netdoctor</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; background: #f7f8fa; color: #15171a; }
    header { padding: 18px 24px; border-bottom: 1px solid #d8dde3; background: #ffffff; display: flex; gap: 16px; align-items: baseline; }
    h1 { font-size: 20px; margin: 0; letter-spacing: 0; }
    main { padding: 20px 24px; display: grid; gap: 16px; }
    .grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
    .card { border: 1px solid #d8dde3; border-radius: 8px; background: #ffffff; padding: 14px; min-width: 0; }
    .label { color: #667085; font-size: 12px; }
    .value { font-size: 24px; margin-top: 6px; overflow-wrap: anywhere; }
    table { width: 100%; border-collapse: collapse; background: #ffffff; border: 1px solid #d8dde3; border-radius: 8px; overflow: hidden; }
    th, td { padding: 10px 12px; border-bottom: 1px solid #e7eaee; text-align: left; font-size: 13px; vertical-align: top; }
    th { color: #667085; font-weight: 600; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }
    .ok { color: #087443; }
    .bad { color: #b42318; }
    @media (max-width: 900px) { .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
    @media (max-width: 560px) { header, main { padding-left: 14px; padding-right: 14px; } .grid { grid-template-columns: 1fr; } }
    @media (prefers-color-scheme: dark) {
      body { background: #101418; color: #eef2f6; }
      header, .card, table { background: #171c22; border-color: #303844; }
      th, td { border-bottom-color: #28313b; }
      .label, th { color: #aab4c0; }
    }
  </style>
</head>
<body>
  <header><h1>netdoctor</h1><span id="stamp"></span></header>
  <main>
    <section class="grid">
      <div class="card"><div class="label">Health</div><div class="value" id="health">--</div></div>
      <div class="card"><div class="label">eBPF</div><div class="value" id="ebpf">--</div></div>
      <div class="card"><div class="label">Attached</div><div class="value" id="attached">--</div></div>
      <div class="card"><div class="label">Events</div><div class="value" id="eventCount">--</div></div>
    </section>
    <section>
      <table>
        <thead><tr><th>Time</th><th>Kind</th><th>Process</th><th>Flow</th><th>Metrics</th><th>Summary</th></tr></thead>
        <tbody id="events"></tbody>
      </table>
    </section>
  </main>
  <script>
    async function refresh() {
      const res = await fetch('/api/snapshot', {cache: 'no-store'});
      const data = await res.json();
      document.getElementById('stamp').textContent = new Date(data.generated_at).toLocaleString();
      document.getElementById('health').textContent = data.host.health_score;
      const enabled = data.ebpf.enabled ? 'attached' : (data.ebpf.available ? 'probe' : 'off');
      document.getElementById('ebpf').innerHTML = '<span class="' + (data.ebpf.available ? 'ok' : 'bad') + '">' + enabled + '</span>';
      document.getElementById('attached').textContent = (data.ebpf.attached || []).length;
      const events = data.events || [];
      document.getElementById('eventCount').textContent = events.length;
      const endpoint = e => {
        if (!e) return '';
        const addr = e.address || '';
        const port = e.port ? ':' + e.port : '';
        return addr + port;
      };
      const flow = e => {
        const left = endpoint(e.local);
        const right = endpoint(e.remote);
        if (!left && !right) return '';
        return left + ' -> ' + right;
      };
      const metrics = e => [
        e.direction,
        e.duration_us ? ('lat=' + e.duration_us + 'us') : '',
        e.bytes ? ('bytes=' + e.bytes) : '',
        e.old_state || e.new_state ? ((e.old_state || '-') + '->' + (e.new_state || '-')) : '',
        e.srtt_us ? ('srtt=' + e.srtt_us + 'us') : '',
        e.retransmits ? ('retrans=' + e.retransmits) : '',
        e.icmp_type || e.icmp_code ? ('icmp=' + (e.icmp_type || 0) + '/' + (e.icmp_code || 0)) : ''
      ].filter(Boolean).join(' ');
      document.getElementById('events').innerHTML = events.slice(-80).reverse().map(e =>
        '<tr><td>' + new Date(e.time).toLocaleTimeString() + '</td><td>' + (e.kind || '') + '<br><code>' + (e.protocol || '') + '</code></td><td>' + (e.command || '') + '<br><code>' + (e.pid || '') + '</code></td><td><code>' + flow(e) + '</code></td><td>' + metrics(e) + '</td><td>' + (e.summary || '') + '</td></tr>'
      ).join('');
    }
    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>`
