package alertmetrics

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	evalBuckets      = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5}
	notifyLatBuckets = []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10}

	evalHist      = newHistogram(evalBuckets)
	notifyLatHist = newHistogram(notifyLatBuckets)

	eventsFired    atomic.Int64
	eventsResolved atomic.Int64

	notifyErrMu sync.Mutex
	notifyErr   = make(map[string]int64)
)

type histogram struct {
	buckets []float64
	counts  []atomic.Int64
	sum     atomic.Uint64 // stores math.Float64bits
	total   atomic.Int64
}

func newHistogram(buckets []float64) *histogram {
	h := &histogram{buckets: append([]float64(nil), buckets...)}
	h.counts = make([]atomic.Int64, len(buckets)+1) // +Inf bucket
	return h
}

func (h *histogram) observe(v float64) {
	idx := len(h.buckets)
	for i, b := range h.buckets {
		if v <= b {
			idx = i
			break
		}
	}
	h.counts[idx].Add(1)
	h.total.Add(1)
	for {
		oldBits := h.sum.Load()
		old := float64FromBits(oldBits)
		nextBits := float64Bits(old + v)
		if h.sum.CompareAndSwap(oldBits, nextBits) {
			break
		}
	}
}

func ObserveRuleEvalDuration(seconds float64) {
	if seconds < 0 {
		return
	}
	evalHist.observe(seconds)
}

func IncEventFired() {
	eventsFired.Add(1)
}

func IncEventResolved(n int64) {
	if n <= 0 {
		return
	}
	eventsResolved.Add(n)
}

func IncNotifyError(channel string) {
	if strings.TrimSpace(channel) == "" {
		channel = "unknown"
	}
	notifyErrMu.Lock()
	notifyErr[channel]++
	notifyErrMu.Unlock()
}

func ObserveNotifyLatency(seconds float64) {
	if seconds < 0 {
		return
	}
	notifyLatHist.observe(seconds)
}

func RenderPrometheus() string {
	var sb strings.Builder

	sb.WriteString("# HELP alert_events_total Total alert events by status\n")
	sb.WriteString("# TYPE alert_events_total counter\n")
	sb.WriteString(fmt.Sprintf("alert_events_total{status=\"fired\"} %d\n", eventsFired.Load()))
	sb.WriteString(fmt.Sprintf("alert_events_total{status=\"resolved\"} %d\n", eventsResolved.Load()))

	sb.WriteString("# HELP alert_notify_errors_total Notification send failures by channel\n")
	sb.WriteString("# TYPE alert_notify_errors_total counter\n")
	notifyErrMu.Lock()
	chs := make([]string, 0, len(notifyErr))
	for ch := range notifyErr {
		chs = append(chs, ch)
	}
	sort.Strings(chs)
	for _, ch := range chs {
		sb.WriteString(fmt.Sprintf("alert_notify_errors_total{channel=\"%s\"} %d\n", ch, notifyErr[ch]))
	}
	notifyErrMu.Unlock()

	renderHistogram(&sb, "alert_rule_eval_duration_seconds", "Rule evaluation duration", evalHist)
	renderHistogram(&sb, "alert_notify_latency_seconds", "Alert trigger-to-delivery latency", notifyLatHist)

	return sb.String()
}

func renderHistogram(sb *strings.Builder, name, help string, h *histogram) {
	sb.WriteString("# HELP ")
	sb.WriteString(name)
	sb.WriteString(" ")
	sb.WriteString(help)
	sb.WriteString("\n")
	sb.WriteString("# TYPE ")
	sb.WriteString(name)
	sb.WriteString(" histogram\n")

	cum := int64(0)
	for i, b := range h.buckets {
		cum += h.counts[i].Load()
		sb.WriteString(fmt.Sprintf("%s_bucket{le=\"%.3f\"} %d\n", name, b, cum))
	}
	cum += h.counts[len(h.buckets)].Load()
	sb.WriteString(fmt.Sprintf("%s_bucket{le=\"+Inf\"} %d\n", name, cum))
	sb.WriteString(fmt.Sprintf("%s_sum %f\n", name, float64FromBits(h.sum.Load())))
	sb.WriteString(fmt.Sprintf("%s_count %d\n", name, h.total.Load()))
}

func float64Bits(v float64) uint64     { return math.Float64bits(v) }
func float64FromBits(v uint64) float64 { return math.Float64frombits(v) }
