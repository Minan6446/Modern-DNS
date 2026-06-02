package handler

import (
	"fmt"
	"io"
	"time"

	"modern-dns/pkg/cluster"

	"github.com/gin-gonic/gin"
)

// GET /api/cluster/stream
//
// Server-Sent Events feed of cluster lifecycle events: node join / leave,
// state transitions, sync started / finished. Three pages (overview /
// nodes / sync) all subscribe so they can refresh without polling.
//
// We implement SSE by hand rather than pulling in a library: gin's
// c.Stream + a buffered subscriber channel from pkg/cluster is plenty.
// Heartbeat comments every 25s keep proxies (nginx, AWS ALB) from
// killing idle connections.
func StreamClusterEvents(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // disable nginx proxy_buffering
	c.Writer.Flush()

	subID, events := cluster.Subscribe()
	defer cluster.Unsubscribe(subID)

	// Initial sync hello so the client knows the stream is alive even if
	// nothing is happening yet.
	fmt.Fprintf(c.Writer, "event: hello\ndata: %s\n\n", time.Now().Format(time.RFC3339))
	c.Writer.Flush()

	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()

	c.Stream(func(w io.Writer) bool {
		select {
		case <-c.Request.Context().Done():
			return false
		case ev, ok := <-events:
			if !ok {
				return false
			}
			data, err := ev.Marshal()
			if err != nil {
				return true
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
			return true
		case <-heartbeat.C:
			// SSE comment line — clients ignore but proxies see traffic
			fmt.Fprint(w, ": keepalive\n\n")
			return true
		}
	})
}
