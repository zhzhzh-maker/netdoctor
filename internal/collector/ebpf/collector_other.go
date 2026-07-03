//go:build !linux

package ebpfcollector

import (
	"context"
	"runtime"

	"github.com/netdoctor/netdoctor/internal/model"
)

type Options struct {
	ObjectPath string
	EventLimit int
}

type Collector struct {
	status model.EBPFStatus
	events *eventStore
}

func New(options Options) *Collector {
	return &Collector{
		status: model.EBPFStatus{
			Available: false,
			Mode:      "unsupported",
			Error:     "cilium/ebpf collectors require Linux; current OS is " + runtime.GOOS,
		},
		events: newEventStore(options.EventLimit),
	}
}

func (c *Collector) Start(context.Context) error {
	return nil
}

func (c *Collector) Close() error {
	return nil
}

func (c *Collector) Status() model.EBPFStatus {
	return c.status
}

func (c *Collector) Events() []model.NetworkEvent {
	return c.events.list()
}
