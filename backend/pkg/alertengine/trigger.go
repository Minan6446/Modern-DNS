package alertengine

import "sync"

var (
	defaultEngineMu sync.RWMutex
	defaultEngine   *Engine
)

// SetDefaultEngine registers the process-global engine instance so external
// producers (like dnsengine query-log writer) can request a hot evaluation.
func SetDefaultEngine(e *Engine) {
	defaultEngineMu.Lock()
	defaultEngine = e
	defaultEngineMu.Unlock()
}

// NotifyQueryLogWritten signals the alert engine that fresh query logs are
// available and a hot evaluation can run immediately.
func NotifyQueryLogWritten() {
	defaultEngineMu.RLock()
	e := defaultEngine
	defaultEngineMu.RUnlock()
	if e != nil {
		e.TriggerHotEval()
	}
}
