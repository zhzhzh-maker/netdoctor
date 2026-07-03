package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ndconfig "github.com/netdoctor/netdoctor/internal/config"
	"github.com/netdoctor/netdoctor/internal/doctor"
	"github.com/netdoctor/netdoctor/internal/model"
	"github.com/netdoctor/netdoctor/internal/output"
	"github.com/netdoctor/netdoctor/internal/web"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return errors.New("missing command")
	}

	switch os.Args[1] {
	case "probe":
		return probe(os.Args[2:])
	case "run":
		return runCollector(os.Args[2:])
	case "serve":
		return serve(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func probe(args []string) error {
	cfg, err := loadCommandConfig(args)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	configPath := fs.String("config", "netdoctor.yaml", "configuration file path")
	objectPath := fs.String("object", cfg.Object, "optional compiled eBPF object path")
	eventLimit := fs.Int("event-limit", cfg.EventLimit, "number of recent eBPF events kept in memory")
	protocols := fs.String("protocol", strings.Join(cfg.Protocols, ","), "comma-separated protocol filter, for example tcp,udp")
	ifname := fs.String("ifname", cfg.Interface, "network interface for TC packet parser, for example eth0")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = configPath

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	service := doctor.New(doctor.Options{ObjectPath: *objectPath, EventLimit: *eventLimit, Protocols: splitCSV(*protocols), IfNames: splitCSV(*ifname)})
	if err := service.Start(ctx); err != nil {
		return output.JSON(os.Stdout, service.Snapshot())
	}
	defer service.Close()
	return output.JSON(os.Stdout, service.Snapshot())
}

func runCollector(args []string) error {
	cfg, err := loadCommandConfig(args)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "netdoctor.yaml", "configuration file path")
	objectPath := fs.String("object", cfg.Object, "compiled eBPF object path")
	eventLimit := fs.Int("event-limit", cfg.EventLimit, "number of recent eBPF events kept in memory")
	protocols := fs.String("protocol", strings.Join(cfg.Protocols, ","), "comma-separated protocol filter, for example tcp,udp")
	ifname := fs.String("ifname", cfg.Interface, "network interface for TC packet parser, for example eth0")
	interval := fs.Duration("interval", time.Second, "event polling interval")
	jsonLines := fs.Bool("json", false, "print summary snapshots as JSON")
	showEvents := fs.Bool("events", false, "print individual decoded eBPF events")
	webEnabled := fs.Bool("web", cfg.Web, "start the Web UI/API while tailing events")
	addr := fs.String("addr", cfg.Listen, "HTTP listen address when -web is enabled")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = configPath
	if strings.TrimSpace(*objectPath) == "" {
		return errors.New("run requires -object")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	service := doctor.New(doctor.Options{ObjectPath: *objectPath, EventLimit: *eventLimit, Protocols: splitCSV(*protocols), IfNames: splitCSV(*ifname)})
	if err := service.Start(ctx); err != nil {
		return err
	}
	defer service.Close()

	printRunStatus(service.Snapshot().EBPF)
	var server *http.Server
	var errCh <-chan error
	if *webEnabled {
		server, errCh = startWeb(service, *addr)
		fmt.Fprintf(os.Stderr, "web listening on %s\n", displayURL(*addr))
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	var lastSeq uint64
	for {
		select {
		case <-ctx.Done():
			if server != nil {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				return server.Shutdown(shutdownCtx)
			}
			return nil
		case err := <-errCh:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ticker.C:
			snapshot := service.Snapshot()
			if *showEvents {
				for _, event := range snapshot.Events {
					if event.Sequence <= lastSeq {
						continue
					}
					if err := printEvent(os.Stdout, event, *jsonLines); err != nil {
						return err
					}
					lastSeq = event.Sequence
				}
				continue
			}
			snapshot.Events = nil
			if *jsonLines {
				if err := json.NewEncoder(os.Stdout).Encode(snapshot); err != nil {
					return err
				}
				continue
			}
			printSummary(os.Stdout, snapshot)
		}
	}
}

func serve(args []string) error {
	cfg, err := loadCommandConfig(args)
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "netdoctor.yaml", "configuration file path")
	addr := fs.String("addr", cfg.Listen, "HTTP listen address")
	objectPath := fs.String("object", cfg.Object, "optional compiled eBPF object path")
	eventLimit := fs.Int("event-limit", cfg.EventLimit, "number of recent eBPF events kept in memory")
	protocols := fs.String("protocol", strings.Join(cfg.Protocols, ","), "comma-separated protocol filter, for example tcp,udp")
	ifname := fs.String("ifname", cfg.Interface, "network interface for TC packet parser, for example eth0")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = configPath

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	service := doctor.New(doctor.Options{ObjectPath: *objectPath, EventLimit: *eventLimit, Protocols: splitCSV(*protocols), IfNames: splitCSV(*ifname)})
	if err := service.Start(ctx); err != nil {
		return err
	}
	defer service.Close()

	server, errCh := startWeb(service, *addr)
	log.Printf("netdoctor web listening on %s", displayURL(*addr))

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `netdoctor

Usage:
  netdoctor probe [-config netdoctor.yaml]
  netdoctor run [-config netdoctor.yaml] [-protocol tcp,udp] [-ifname eth0] [-json] [-events]
  netdoctor serve [-config netdoctor.yaml]

Commands:
  probe   check cilium/ebpf availability and optionally attach an object once
  run     attach an eBPF object, start the Web UI by default, and print summaries
  serve   start the optional web UI and JSON API`)
}

func printRunStatus(status model.EBPFStatus) {
	fmt.Fprintf(os.Stderr, "netdoctor attached %d eBPF programs\n", len(status.Attached))
	for _, section := range status.Attached {
		fmt.Fprintf(os.Stderr, "  attached %s\n", section)
	}
	for _, section := range status.Skipped {
		fmt.Fprintf(os.Stderr, "  skipped  %s\n", section)
	}
	fmt.Fprintln(os.Stderr, "waiting for traffic summaries...")
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func loadCommandConfig(args []string) (ndconfig.Config, error) {
	path := "netdoctor.yaml"
	for i := 0; i < len(args); i++ {
		if args[i] == "-config" && i+1 < len(args) {
			path = args[i+1]
			break
		}
		if strings.HasPrefix(args[i], "-config=") {
			path = strings.TrimPrefix(args[i], "-config=")
			break
		}
	}
	return ndconfig.Load(path)
}

func startWeb(service *doctor.Service, addr string) (*http.Server, <-chan error) {
	server := &http.Server{
		Addr:    addr,
		Handler: web.New(service).Handler(),
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()
	return server, errCh
}

func displayURL(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "http://0.0.0.0" + addr
	}
	return "http://" + addr
}

func printEvent(file *os.File, event model.NetworkEvent, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(file)
		return enc.Encode(event)
	}

	fmt.Fprintf(file, "%s seq=%d %s\n",
		event.Time.Format(time.RFC3339),
		event.Sequence,
		event.Summary,
	)
	return nil
}

func printSummary(file *os.File, snapshot model.Snapshot) {
	total := tcpTotals(snapshot.SystemTCP)
	fmt.Fprintf(file, "%s interfaces=%d processes=%d tcp_tx=%s tcp_rx=%s retrans=%s retrans_rate=%.2f%%\n",
		snapshot.GeneratedAt.Format(time.RFC3339),
		len(snapshot.Interfaces),
		len(snapshot.ProcessTraffic),
		humanBytes(total.tx),
		humanBytes(total.rx),
		humanBytes(total.retrans),
		total.rate*100,
	)

	if len(snapshot.SystemTCP) > 0 {
		fmt.Fprintln(file, "  system tcp by interface:")
		for _, row := range snapshot.SystemTCP {
			name := row.Interface
			if name == "" {
				name = fmt.Sprintf("if%d", row.IfIndex)
			}
			fmt.Fprintf(file, "    %-12s tx=%-10s rx=%-10s retrans=%-10s rate=%.2f%%\n",
				name,
				humanBytes(row.TXBytes),
				humanBytes(row.RXBytes),
				humanBytes(row.RetransBytes),
				row.RetransRate*100,
			)
		}
	}

	limit := 5
	if len(snapshot.ProcessTraffic) < limit {
		limit = len(snapshot.ProcessTraffic)
	}
	if limit > 0 {
		fmt.Fprintln(file, "  top processes:")
		for _, row := range snapshot.ProcessTraffic[:limit] {
			fmt.Fprintf(file, "    pid=%-7d %-16s %-3s tx=%-10s rx=%-10s retrans_rate=%.2f%%\n",
				row.PID,
				truncate(row.Command, 16),
				row.Protocol,
				humanBytes(row.TXBytes),
				humanBytes(row.RXBytes),
				row.RetransRate*100,
			)
		}
	}
}

type tcpTotal struct {
	tx      uint64
	rx      uint64
	retrans uint64
	rate    float64
}

func tcpTotals(rows []model.SystemTCPInterfaceStats) tcpTotal {
	var total tcpTotal
	for _, row := range rows {
		total.tx += row.TXBytes
		total.rx += row.RXBytes
		total.retrans += row.RetransBytes
	}
	if total.tx+total.rx > 0 {
		total.rate = float64(total.retrans) / float64(total.tx+total.rx)
	}
	return total
}

func humanBytes(value uint64) string {
	const unit = 1024
	if value < unit {
		return fmt.Sprintf("%dB", value)
	}
	div, exp := uint64(unit), 0
	for n := value / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(value)/float64(div), "KMGTPE"[exp])
}

func truncate(value string, limit int) string {
	if value == "" {
		return "-"
	}
	if len(value) <= limit {
		return value
	}
	if limit <= 1 {
		return value[:limit]
	}
	return value[:limit-1] + "~"
}
