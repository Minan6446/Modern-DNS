package cluster

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"
)

// Event is the unit of work pushed to subscribers of the cluster SSE stream.
// Type tells the frontend which page to refresh; Payload is type-specific
// freeform data (most subscribers just refetch on any event of interest).
type Event struct {
	Type      string         `json:"type"`              // "node-state" / "sync-started" / "sync-finished"
	NodeID    string         `json:"nodeId,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
	Timestamp time.Time      `json:"timestamp"`
}

// Subscribe returns a buffered channel that receives every subsequent event
// until Unsubscribe is called or the channel is dropped. The buffer size is
// generous so a slow consumer doesn't block publishers; events that overflow
// are silently dropped (best-effort delivery — operators always have the
// REST endpoints to fall back on for canonical state).
func Subscribe() (id uint64, ch <-chan Event) {
	subID := atomic.AddUint64(&subSeq, 1)
	c := make(chan Event, 64)
	subMu.Lock()
	subs[subID] = c
	subMu.Unlock()
	return subID, c
}

// Unsubscribe removes the channel from the fanout list and closes it.
func Unsubscribe(id uint64) {
	subMu.Lock()
	c, ok := subs[id]
	if ok {
		delete(subs, id)
	}
	subMu.Unlock()
	if ok {
		close(c)
	}
}

// Publish fans an event out to all current subscribers. Non-blocking on a
// per-subscriber basis; a saturated buffer means that consumer drops the
// event but other subscribers still receive it.
func Publish(t string, nodeID string, payload map[string]any) {
	ev := Event{Type: t, NodeID: nodeID, Payload: payload, Timestamp: time.Now()}
	subMu.RLock()
	defer subMu.RUnlock()
	for _, c := range subs {
		select {
		case c <- ev:
		default:
			// drop — slow consumer
		}
	}
}

// Marshal returns the JSON form of the event for SSE framing.
func (e Event) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

var (
	subMu  sync.RWMutex
	subs   = make(map[uint64]chan Event)
	subSeq uint64
)
