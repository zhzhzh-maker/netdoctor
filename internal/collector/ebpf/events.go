package ebpfcollector

import (
	"sync"

	"github.com/netdoctor/netdoctor/internal/model"
)

const defaultEventLimit = 2048

type eventStore struct {
	mu     sync.RWMutex
	limit  int
	next   uint64
	events []model.NetworkEvent
}

func newEventStore(limit int) *eventStore {
	if limit <= 0 {
		limit = defaultEventLimit
	}
	return &eventStore{limit: limit}
}

func (s *eventStore) add(event model.NetworkEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.next++
	event.Sequence = s.next

	if len(s.events) >= s.limit {
		copy(s.events, s.events[1:])
		s.events[len(s.events)-1] = event
		return
	}
	s.events = append(s.events, event)
}

func (s *eventStore) list() []model.NetworkEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]model.NetworkEvent, len(s.events))
	copy(out, s.events)
	return out
}
