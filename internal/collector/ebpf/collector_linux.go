//go:build linux

package ebpfcollector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netdoctor/netdoctor/internal/model"
)

type Options struct {
	ObjectPath string
	EventLimit int
	IfNames    []string
}

type Collector struct {
	options Options
	events  *eventStore

	mu      sync.RWMutex
	status  model.EBPFStatus
	spec    *ebpf.CollectionSpec
	objects *ebpf.Collection
	links   []io.Closer
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
			Interfaces: options.IfNames,
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
	status.Interfaces = c.options.IfNames

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
	status.Interfaces = nil

	for name, program := range objects.Programs {
		programSpec := spec.Programs[name]
		if programSpec == nil {
			continue
		}
		if isTCSection(programSpec.SectionName) {
			attached, labels, ifnames, err := c.attachTCX(program, programSpec.SectionName)
			if err != nil {
				if shouldSkipAttach(programSpec.SectionName, err) {
					status.Skipped = append(status.Skipped, fmt.Sprintf("%s: %s", programSpec.SectionName, err))
					continue
				}
				slog.Warn("skip eBPF program", "name", name, "section", programSpec.SectionName, "error", err)
				continue
			}
			c.links = append(c.links, attached...)
			status.Attached = append(status.Attached, labels...)
			status.Interfaces = mergeStrings(status.Interfaces, ifnames)
			continue
		}
		attached, label, err := c.attachProgram(program, programSpec.SectionName)
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

		event := decodeRawEvent(record.RawSample)
		event.Time = time.Now()
		event.Source = name
		c.events.add(event)
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

func (c *Collector) attachProgram(program *ebpf.Program, section string) (link.Link, string, error) {
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
		return nil, "", errors.New("tc classifier programs use multi-interface attach path")
	default:
		return nil, "", fmt.Errorf("unsupported eBPF section %q", section)
	}
}

func (c *Collector) attachTCX(program *ebpf.Program, section string) ([]io.Closer, []string, []string, error) {
	var attach ebpf.AttachType
	var legacyParent uint32
	switch {
	case strings.Contains(section, "ingress"):
		attach = ebpf.AttachTCXIngress
		legacyParent = netlink.HANDLE_MIN_INGRESS
	case strings.Contains(section, "egress"):
		attach = ebpf.AttachTCXEgress
		legacyParent = netlink.HANDLE_MIN_EGRESS
	default:
		return nil, nil, nil, fmt.Errorf("tc classifier section must contain ingress or egress")
	}

	ifaces, err := c.tcInterfaces()
	if err != nil {
		return nil, nil, nil, err
	}
	if len(ifaces) == 0 {
		return nil, nil, nil, errors.New("tc classifier programs found no usable interfaces")
	}

	attached := make([]io.Closer, 0, len(ifaces))
	labels := make([]string, 0, len(ifaces))
	names := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		var l io.Closer
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   program,
			Attach:    attach,
		})
		if err != nil {
			l, err = attachLegacyTC(program, section, iface, legacyParent)
			if err != nil {
				for _, opened := range attached {
					_ = opened.Close()
				}
				return nil, nil, nil, fmt.Errorf("attach %s to %s: %w", section, iface.Name, err)
			}
			attached = append(attached, l)
			labels = append(labels, fmt.Sprintf("%s[%s legacy-tc]", section, iface.Name))
			names = append(names, iface.Name)
			continue
		}
		attached = append(attached, l)
		labels = append(labels, fmt.Sprintf("%s[%s tcx]", section, iface.Name))
		names = append(names, iface.Name)
	}
	return attached, labels, names, nil
}

func attachLegacyTC(program *ebpf.Program, section string, iface net.Interface, parent uint32) (io.Closer, error) {
	qdisc := &netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil, fmt.Errorf("add clsact qdisc: %w", err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Parent:    parent,
			Handle:    legacyTCHandle(section),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           program.FD(),
		Name:         "netdoctor_" + legacyTCDirection(section),
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("replace bpf filter: %w", err)
	}
	return legacyTCLink{filter: filter}, nil
}

func legacyTCHandle(section string) uint32 {
	if strings.Contains(section, "egress") {
		return netlink.MakeHandle(0, 2)
	}
	return netlink.MakeHandle(0, 1)
}

func legacyTCDirection(section string) string {
	if strings.Contains(section, "egress") {
		return "egress"
	}
	return "ingress"
}

type legacyTCLink struct {
	filter netlink.Filter
}

func (l legacyTCLink) Close() error {
	return netlink.FilterDel(l.filter)
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

func isTCSection(section string) bool {
	return strings.HasPrefix(section, "classifier/") || strings.HasPrefix(section, "tc/")
}

func (c *Collector) tcInterfaces() ([]net.Interface, error) {
	if len(c.options.IfNames) > 0 && !hasAllInterface(c.options.IfNames) {
		out := make([]net.Interface, 0, len(c.options.IfNames))
		for _, name := range c.options.IfNames {
			iface, err := net.InterfaceByName(name)
			if err != nil {
				return nil, fmt.Errorf("lookup interface %s: %w", name, err)
			}
			out = append(out, *iface)
		}
		return out, nil
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	out := make([]net.Interface, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		out = append(out, iface)
	}
	return out, nil
}

func hasAllInterface(values []string) bool {
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "all" || value == "*" {
			return true
		}
	}
	return false
}

func mergeStrings(base []string, values []string) []string {
	seen := make(map[string]struct{}, len(base)+len(values))
	out := make([]string, 0, len(base)+len(values))
	for _, value := range append(base, values...) {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func (c *Collector) setStatus(status model.EBPFStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = status
}
