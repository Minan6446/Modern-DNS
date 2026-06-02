package alertengine

import (
	"log"
	"sync"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/db"
)

const (
	historyQueueSize  = 4096
	historyBatchSize  = 100
	historyFlushEvery = 1 * time.Second
)

type historyWriter struct {
	ch     chan model.MonitorRuleHistory
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func newHistoryWriter() *historyWriter {
	return &historyWriter{
		ch:     make(chan model.MonitorRuleHistory, historyQueueSize),
		stopCh: make(chan struct{}),
	}
}

func (w *historyWriter) Start() {
	w.wg.Add(1)
	go w.loop()
}

func (w *historyWriter) Stop() {
	close(w.stopCh)
	w.wg.Wait()
}

func (w *historyWriter) Enqueue(entry model.MonitorRuleHistory) bool {
	select {
	case w.ch <- entry:
		return true
	default:
		return false
	}
}

func (w *historyWriter) loop() {
	defer w.wg.Done()
	ticker := time.NewTicker(historyFlushEvery)
	defer ticker.Stop()

	batch := make([]model.MonitorRuleHistory, 0, historyBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := db.DB.Create(&batch).Error; err != nil {
			log.Printf("[alert-engine] history batch flush failed: %v", err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-w.stopCh:
			flush()
			return
		case item := <-w.ch:
			batch = append(batch, item)
			if len(batch) >= historyBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
