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
		EBPF:           status,
		Events:         events,
		NICProtocols:   aggregateNICProtocols(events),
		ProcessTraffic: aggregateProcessTraffic(events),
		SystemTCP:      aggregateSystemTCP(events),
		Findings:       findings,
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

func aggregateProcessTraffic(events []model.NetworkEvent) []model.ProcessTrafficStats {
	type key struct {
		pid      uint32
		protocol string
	}
	stats := map[key]*model.ProcessTrafficStats{}
	for _, event := range events {
		if event.PID == 0 || event.Protocol == "" {
			continue
		}
		k := key{pid: event.PID, protocol: event.Protocol}
		stat := stats[k]
		if stat == nil {
			stat = &model.ProcessTrafficStats{
				PID:      event.PID,
				Command:  event.Command,
				Protocol: event.Protocol,
			}
			stats[k] = stat
		}
		if stat.Command == "" {
			stat.Command = event.Command
		}
		stat.Events++
		switch event.Kind {
		case "tcp-send", "udp-send":
			stat.TXBytes += event.Bytes
		case "tcp-recv", "udp-recv":
			stat.RXBytes += event.Bytes
		case "tcp-retransmit":
			stat.Retransmits++
			stat.RetransBytes += event.Bytes
		}
	}

	out := make([]model.ProcessTrafficStats, 0, len(stats))
	for _, stat := range stats {
		total := stat.TXBytes + stat.RXBytes
		if total > 0 {
			stat.RetransRate = float64(stat.RetransBytes) / float64(total)
		}
		out = append(out, *stat)
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].RXBytes + out[i].TXBytes
		right := out[j].RXBytes + out[j].TXBytes
		if left == right {
			return out[i].PID < out[j].PID
		}
		return left > right
	})
	return out
}

func aggregateSystemTCP(events []model.NetworkEvent) []model.SystemTCPInterfaceStats {
	stats := map[uint32]*model.SystemTCPInterfaceStats{}
	for _, event := range events {
		if event.IfIndex == 0 || event.Protocol != "TCP" {
			continue
		}
		stat := stats[event.IfIndex]
		if stat == nil {
			stat = &model.SystemTCPInterfaceStats{
				IfIndex:   event.IfIndex,
				Interface: interfaceName(event.IfIndex),
			}
			stats[event.IfIndex] = stat
		}
		stat.Events++
		switch event.Direction {
		case "egress":
			stat.TXBytes += event.Bytes
		case "ingress":
			stat.RXBytes += event.Bytes
		}
		if event.Kind == "tcp-retransmit" {
			stat.Retransmits++
			stat.RetransBytes += event.Bytes
		}
	}
	out := make([]model.SystemTCPInterfaceStats, 0, len(stats))
	for _, stat := range stats {
		total := stat.TXBytes + stat.RXBytes
		if total > 0 {
			stat.RetransRate = float64(stat.RetransBytes) / float64(total)
		}
		out = append(out, *stat)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Interface < out[j].Interface
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
