package doctor

import (
	"context"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	ebpfcollector "github.com/netdoctor/netdoctor/internal/collector/ebpf"
	"github.com/netdoctor/netdoctor/internal/model"
)

type Options struct {
	ObjectPath string
	EventLimit int
	Protocols  []string
	IfNames    []string
}

type Service struct {
	ebpf      *ebpfcollector.Collector
	protocols map[string]struct{}
}

func New(options Options) *Service {
	return &Service{
		ebpf: ebpfcollector.New(ebpfcollector.Options{
			ObjectPath: options.ObjectPath,
			EventLimit: options.EventLimit,
			IfNames:    options.IfNames,
		}),
		protocols: protocolSet(options.Protocols),
	}
}

func (s *Service) Start(ctx context.Context) error {
	return s.ebpf.Start(ctx)
}

func (s *Service) Close() error {
	return s.ebpf.Close()
}

func (s *Service) Snapshot() model.Snapshot {
	hostname, _ := os.Hostname()
	status := s.ebpf.Status()
	findings := findings(status)
	events := s.filterEvents(s.ebpf.Events())

	return model.Snapshot{
		GeneratedAt: time.Now(),
		Host: model.HostOverview{
			Hostname:    hostname,
			Platform:    runtime.GOOS + "/" + runtime.GOARCH,
			HealthScore: healthScore(status, findings),
		},
		EBPF:         status,
		Events:       events,
		NICProtocols: aggregateNICProtocols(events),
		Findings:     findings,
	}
}

func protocolSet(values []string) map[string]struct{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.ToUpper(strings.TrimSpace(part))
			if part != "" && part != "ALL" {
				out[part] = struct{}{}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Service) filterEvents(events []model.NetworkEvent) []model.NetworkEvent {
	if len(s.protocols) == 0 {
		return events
	}
	filtered := make([]model.NetworkEvent, 0, len(events))
	for _, event := range events {
		if event.Protocol == "" {
			continue
		}
		if _, ok := s.protocols[strings.ToUpper(event.Protocol)]; ok {
			filtered = append(filtered, event)
		}
	}
	return filtered
}

func aggregateNICProtocols(events []model.NetworkEvent) []model.NICProtocolStats {
	type key struct {
		ifindex  uint32
		protocol string
	}
	stats := map[key]*model.NICProtocolStats{}
	for _, event := range events {
		if event.IfIndex == 0 || event.Protocol == "" {
			continue
		}
		k := key{ifindex: event.IfIndex, protocol: event.Protocol}
		stat := stats[k]
		if stat == nil {
			stat = &model.NICProtocolStats{
				IfIndex:   event.IfIndex,
				Interface: interfaceName(event.IfIndex),
				Protocol:  event.Protocol,
			}
			stats[k] = stat
		}
		stat.Events++
		stat.Bytes += event.Bytes
		stat.Packets += event.Packets
		switch event.Kind {
		case "tcp-retransmit":
			stat.Retransmits++
		case "tcp-reset":
			stat.Resets++
		case "tcp-connect":
			stat.Connects++
		case "tcp-connect-fail":
			stat.ConnectFails++
		}
	}
	out := make([]model.NICProtocolStats, 0, len(stats))
	for _, stat := range stats {
		out = append(out, *stat)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IfIndex == out[j].IfIndex {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].IfIndex < out[j].IfIndex
	})
	return out
}

func interfaceName(ifindex uint32) string {
	iface, err := net.InterfaceByIndex(int(ifindex))
	if err != nil {
		return ""
	}
	return iface.Name
}

func findings(status model.EBPFStatus) []model.Finding {
	if status.Error == "" {
		return nil
	}
	return []model.Finding{{
		Severity: "critical",
		Category: "ebpf",
		Title:    "eBPF collector is not running",
		Detail:   status.Error,
	}}
}

func healthScore(status model.EBPFStatus, findings []model.Finding) int {
	if len(findings) > 0 {
		return 40
	}
	if status.Enabled {
		return 100
	}
	if status.Available {
		return 80
	}
	return 50
}
