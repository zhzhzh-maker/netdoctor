package doctor

import (
	"context"
	"os"
	"runtime"
	"time"

	ebpfcollector "github.com/netdoctor/netdoctor/internal/collector/ebpf"
	"github.com/netdoctor/netdoctor/internal/model"
)

type Options struct {
	ObjectPath string
	EventLimit int
}

type Service struct {
	ebpf *ebpfcollector.Collector
}

func New(options Options) *Service {
	return &Service{
		ebpf: ebpfcollector.New(ebpfcollector.Options{
			ObjectPath: options.ObjectPath,
			EventLimit: options.EventLimit,
		}),
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

	return model.Snapshot{
		GeneratedAt: time.Now(),
		Host: model.HostOverview{
			Hostname:    hostname,
			Platform:    runtime.GOOS + "/" + runtime.GOARCH,
			HealthScore: healthScore(status, findings),
		},
		EBPF:     status,
		Events:   s.ebpf.Events(),
		Findings: findings,
	}
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
