package notify

import (
	"fmt"
	"log"
	"sync"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/alertmetrics"
	"modern-dns/pkg/db"
)

const (
	notifyQueueSize       = 256
	notifyWorkerPerChan   = 2
	notifyMaxAttempts     = 4
	notifySendTimeout     = 5 * time.Second
	notifyRetryBase       = 1 * time.Second
	notifyCircuitTripFail = 5
	notifyCircuitOpenFor  = 1 * time.Minute
)

type dispatchJob struct {
	channel  Channel
	cfg      map[string]any
	ev       Event
	isTest   bool
	resultCh chan error
}

type channelDispatcher struct {
	channel Channel
	queue   chan dispatchJob

	mu              sync.Mutex
	failureStreak   int
	circuitOpenTill time.Time
}

var (
	dispatcherOnce sync.Once
	dispatchers    map[Channel]*channelDispatcher
)

func initDispatchers() {
	dispatchers = make(map[Channel]*channelDispatcher, len(allChannels))
	for _, ch := range allChannels {
		d := &channelDispatcher{
			channel: ch,
			queue:   make(chan dispatchJob, notifyQueueSize),
		}
		dispatchers[ch] = d
		for i := 0; i < notifyWorkerPerChan; i++ {
			go d.runWorker()
		}
	}
}

func getDispatcher(ch Channel) *channelDispatcher {
	dispatcherOnce.Do(initDispatchers)
	return dispatchers[ch]
}

func dispatchThroughWorkers(ev Event) {
	cfgs := loadConfigs()
	if len(cfgs) == 0 {
		return
	}
	for _, ch := range allChannels {
		raw := cfgs[string(ch)]
		if raw == nil || raw["enabled"] != true {
			continue
		}
		job := dispatchJob{
			channel: ch,
			cfg:     cloneMap(raw),
			ev:      ev,
		}
		d := getDispatcher(ch)
		select {
		case d.queue <- job:
		default:
			err := fmt.Errorf("queue full")
			log.Printf("[notify] %s queue full, dropping event", ch)
			persistDeadLetter(job, notifyMaxAttempts, err)
		}
	}
}

func dispatchTestThroughWorkers(ch Channel, raw map[string]any, ev Event) error {
	job := dispatchJob{
		channel:  ch,
		cfg:      cloneMap(raw),
		ev:       ev,
		isTest:   true,
		resultCh: make(chan error, 1),
	}
	d := getDispatcher(ch)
	select {
	case d.queue <- job:
	case <-time.After(2 * time.Second):
		return fmt.Errorf("%s 测试队列繁忙，请稍后重试", ch)
	}
	return <-job.resultCh
}

func (d *channelDispatcher) runWorker() {
	for job := range d.queue {
		err, attempts := d.handle(job)
		if job.resultCh != nil {
			job.resultCh <- err
		}
		if err != nil {
			persistDeadLetter(job, attempts, err)
		}
	}
}

func (d *channelDispatcher) handle(job dispatchJob) (error, int) {
	if err := d.circuitGuard(); err != nil {
		d.markFailure()
		return err, 0
	}
	attempts := 0
	var err error
	backoff := notifyRetryBase
	for i := 0; i < notifyMaxAttempts; i++ {
		attempts = i + 1
		err = sendOneWithTimeout(job.channel, job.cfg, job.ev, notifySendTimeout)
		if err == nil {
			d.markSuccess()
			if !job.ev.TriggeredAt.IsZero() {
				alertmetrics.ObserveNotifyLatency(time.Since(job.ev.TriggeredAt).Seconds())
			}
			return nil, attempts
		}
		alertmetrics.IncNotifyError(string(job.channel))
		if i < notifyMaxAttempts-1 {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
	d.markFailure()
	return err, attempts
}

func (d *channelDispatcher) circuitGuard() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if time.Now().Before(d.circuitOpenTill) {
		return fmt.Errorf("channel circuit open until %s", d.circuitOpenTill.Format("15:04:05"))
	}
	return nil
}

func (d *channelDispatcher) markSuccess() {
	d.mu.Lock()
	d.failureStreak = 0
	d.circuitOpenTill = time.Time{}
	d.mu.Unlock()
}

func (d *channelDispatcher) markFailure() {
	d.mu.Lock()
	d.failureStreak++
	if d.failureStreak >= notifyCircuitTripFail {
		d.circuitOpenTill = time.Now().Add(notifyCircuitOpenFor)
		log.Printf("[notify] %s circuit open for %s (failures=%d)", d.channel, notifyCircuitOpenFor, d.failureStreak)
		d.failureStreak = 0
	}
	d.mu.Unlock()
}

func sendOneWithTimeout(ch Channel, cfg map[string]any, ev Event, timeout time.Duration) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- sendOne(ch, cfg, ev)
	}()
	select {
	case err := <-errCh:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("%s send timeout after %s", ch, timeout)
	}
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func persistDeadLetter(job dispatchJob, attempts int, err error) {
	if job.isTest || err == nil || db.DB == nil {
		return
	}
	_ = db.DB.Create(&model.AlertNotifyDeadLetter{
		Channel:   string(job.channel),
		Level:     job.ev.Level,
		AlertType: job.ev.Type,
		Domain:    job.ev.Domain,
		Title:     job.ev.Title,
		Message:   job.ev.Message,
		Error:     err.Error(),
		Attempts:  attempts,
		IsTest:    job.isTest,
	}).Error
}
