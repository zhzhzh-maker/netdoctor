//go:build linux

package ebpfcollector

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/netdoctor/netdoctor/internal/model"
)

type Options struct {
	ObjectPath string
	EventLimit int
}

type Collector struct {
	options Options
	events  *eventStore

	mu      sync.RWMutex
	status  model.EBPFStatus
	spec    *ebpf.CollectionSpec
	objects *ebpf.Collection
	links   []link.Link
	readers []*ringbuf.Reader
	cancel  context.CancelFunc
}

func New(options Options) *Collector {
	return &Collector{
		options: options,
		events:  newEventStore(options.EventLimit),
		status: model.EBPFStatus{
			Mode:       "cilium/ebpf",
			ObjectPath: options.ObjectPath,
		},
	}
}

func (c *Collector) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel

	status, err := probeKernel()
	if err != nil {
		c.setStatus(status)
		return err
	}
	status.ObjectPath = c.options.ObjectPath

	if c.options.ObjectPath == "" {
		status.Available = true
		status.Enabled = false
		status.Mode = "cilium/ebpf probe"
		status.Capabilities = append(status.Capabilities, "map-create")
		c.setStatus(status)
		return nil
	}

	if err := c.loadAndAttach(ctx, &status); err != nil {
		status.Error = err.Error()
		c.setStatus(status)
		return err
	}

	status.Available = true
	status.Enabled = true
	status.Mode = "cilium/ebpf attached"
	c.setStatus(status)
	return nil
}

func (c *Collector) Close() error {
	if c.cancel != nil {
		c.cancel()
	}

	var errs []error
	for _, reader := range c.readers {
		if err := reader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, attached := range c.links {
		if err := attached.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if c.objects != nil {
		c.objects.Close()
	}
	return errors.Join(errs...)
}

func (c *Collector) Status() model.EBPFStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.status
}

func (c *Collector) Events() []model.NetworkEvent {
	return c.events.list()
}

func (c *Collector) loadAndAttach(ctx context.Context, status *model.EBPFStatus) error {
	file, err := os.Open(c.options.ObjectPath)
	if err != nil {
		return fmt.Errorf("open BPF object: %w", err)
	}
	defer file.Close()

	spec, err := ebpf.LoadCollectionSpecFromReader(file)
	if err != nil {
		return fmt.Errorf("load BPF collection spec: %w", err)
	}

	objects, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load BPF collection: %w", err)
	}

	c.spec = spec
	c.objects = objects

	for name, program := range objects.Programs {
		programSpec := spec.Programs[name]
		if programSpec == nil {
			continue
		}
		attached, label, err := attachProgram(program, programSpec.SectionName)
		if err != nil {
			if shouldSkipAttach(programSpec.SectionName, err) {
				status.Skipped = append(status.Skipped, fmt.Sprintf("%s: %s", programSpec.SectionName, err))
				continue
			}
			slog.Warn("skip eBPF program", "name", name, "section", programSpec.SectionName, "error", err)
			continue
		}
		c.links = append(c.links, attached)
		status.Attached = append(status.Attached, label)
	}

	for name, m := range objects.Maps {
		if !strings.Contains(strings.ToLower(name), "events") {
			continue
		}
		reader, err := ringbuf.NewReader(m)
		if err != nil {
			slog.Warn("skip ring buffer map", "map", name, "error", err)
			continue
		}
		c.readers = append(c.readers, reader)
		go c.readRing(ctx, name, reader)
	}

	if len(status.Attached) == 0 {
		return errors.New("no supported eBPF programs were attached")
	}
	return nil
}

func (c *Collector) readRing(ctx context.Context, name string, reader *ringbuf.Reader) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			slog.Warn("read eBPF ring buffer", "map", name, "error", err)
			continue
		}

		c.events.add(model.NetworkEvent{
			Time:   time.Now(),
			Source: name,
			Kind:   "raw-ebpf-event",
			Raw:    hex.EncodeToString(record.RawSample),
		})
	}
}

func probeKernel() (model.EBPFStatus, error) {
	status := model.EBPFStatus{
		Available:    false,
		Enabled:      false,
		Mode:         "cilium/ebpf probe",
		Capabilities: []string{"rlimit-remove-memlock"},
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		status.Error = err.Error()
		return status, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	probeMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "netdoctor_probe",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		status.Error = err.Error()
		return status, fmt.Errorf("create eBPF probe map: %w", err)
	}
	probeMap.Close()

	status.Available = true
	status.Capabilities = append(status.Capabilities, "map-create")
	return status, nil
}

func attachProgram(program *ebpf.Program, section string) (link.Link, string, error) {
	parts := strings.Split(section, "/")
	if len(parts) == 0 {
		return nil, "", fmt.Errorf("empty section")
	}

	switch parts[0] {
	case "tracepoint":
		if len(parts) != 3 {
			return nil, "", fmt.Errorf("tracepoint section must be tracepoint/category/name")
		}
		attached, err := link.Tracepoint(parts[1], parts[2], program, nil)
		return attached, section, err
	case "kprobe":
		if len(parts) != 2 {
			return nil, "", fmt.Errorf("kprobe section must be kprobe/symbol")
		}
		attached, err := link.Kprobe(parts[1], program, nil)
		return attached, section, err
	case "kretprobe":
		if len(parts) != 2 {
			return nil, "", fmt.Errorf("kretprobe section must be kretprobe/symbol")
		}
		attached, err := link.Kretprobe(parts[1], program, nil)
		return attached, section, err
	case "xdp":
		return nil, "", errors.New("xdp programs need an interface, use a dedicated module for that attach path")
	case "tc", "classifier":
		return nil, "", errors.New("tc classifier programs need an interface and ingress/egress attach path")
	default:
		return nil, "", fmt.Errorf("unsupported eBPF section %q", section)
	}
}

func shouldSkipAttach(section string, err error) bool {
	if strings.HasPrefix(section, "classifier/") || strings.HasPrefix(section, "tc/") || strings.HasPrefix(section, "xdp/") {
		return true
	}
	if (section == "kprobe/icmp_send" || section == "kprobe/icmpv6_send") && strings.Contains(err.Error(), "not found") {
		return true
	}
	return false
}

func (c *Collector) setStatus(status model.EBPFStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = status
}
