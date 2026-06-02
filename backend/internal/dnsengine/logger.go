package dnsengine

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"modern-dns/internal/model"
	"modern-dns/pkg/alertengine"
	"modern-dns/pkg/db"

	"github.com/miekg/dns"
	"gorm.io/gorm"
)

// writeQueryLog persists a query log entry to the database asynchronously.
func (e *Engine) writeQueryLog(q dns.Question, remoteAddr string, rcode int, status string, elapsed time.Duration, req, resp *dns.Msg, rpzHitRuleID uint) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	domain := strings.TrimSuffix(q.Name, ".")
	qType := dns.TypeToString[q.Qtype]
	if qType == "" {
		qType = fmt.Sprintf("TYPE%d", q.Qtype)
	}

	rcodeStr := dns.RcodeToString[rcode]
	if rcodeStr == "" {
		rcodeStr = fmt.Sprintf("%d", rcode)
	}

	queryID := fmt.Sprintf("Q-%d", time.Now().UnixNano()%1e12)

	// Serialise the request / response with miekg's dig-style text
	// format so the 实时查询 详情 dialog's "复制请求内容 / 响应内容"
	// buttons actually have something to hand back to the operator.
	// Fallback to a minimal synthetic line if the raw message is
	// missing (shouldn't happen in practice, but logger must never
	// panic on a nil pointer in the async goroutine).
	requestPayload := ""
	if req != nil {
		requestPayload = req.String()
	} else {
		requestPayload = fmt.Sprintf(";; question: %s\t%s", q.Name, qType)
	}
	responsePayload := ""
	if resp != nil {
		responsePayload = resp.String()
	}

	// Transaction ID is useful for correlating with pcap / tcpdump
	// captures. We already carry it in the model, just never wrote it.
	var txnID string
	if req != nil {
		txnID = fmt.Sprintf("0x%04X", req.Id)
	}

	entry := model.QueryLog{
		QueryID:         queryID,
		Domain:          domain,
		RecordType:      qType,
		SourceIP:        host,
		ResponseStatus:  status,
		ResponseTime:    int(elapsed.Milliseconds()),
		RCode:           rcodeStr,
		TransactionID:   txnID,
		RequestPayload:  requestPayload,
		ResponsePayload: responsePayload,
	}

	if err := db.DB.Create(&entry).Error; err != nil {
		log.Printf("[dns-engine] failed to write query log: %v", err)
	} else {
		alertengine.NotifyQueryLogWritten()
	}

	if rpzHitRuleID > 0 {
		e.queueRPZHit(rpzHitRuleID)
	}

	// Update last_used_at for matching local records
	if rcode == dns.RcodeSuccess && resp != nil && len(resp.Answer) > 0 {
		go e.touchLocalRecords(domain, qType)
	}
}

func (e *Engine) queueRPZHit(ruleID uint) {
	if ruleID == 0 {
		return
	}
	e.rpzHitMu.Lock()
	e.rpzHitDeltas[ruleID]++
	e.rpzHitMu.Unlock()
}

func (e *Engine) rpzHitFlushLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.flushRPZHitDeltas()
		case <-e.stopCh:
			return
		}
	}
}

func (e *Engine) flushRPZHitDeltas() {
	e.rpzHitMu.Lock()
	if len(e.rpzHitDeltas) == 0 {
		e.rpzHitMu.Unlock()
		return
	}
	deltas := e.rpzHitDeltas
	e.rpzHitDeltas = make(map[uint]int64)
	e.rpzHitMu.Unlock()

	err := db.DB.Transaction(func(tx *gorm.DB) error {
		for id, delta := range deltas {
			if delta <= 0 {
				continue
			}
			if err := tx.Model(&model.RpzRule{}).
				Where("id = ?", id).
				UpdateColumn("hit_count", gorm.Expr("hit_count + ?", delta)).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("[dns-engine] failed to flush RPZ hit_count deltas: %v", err)
		// Merge deltas back so transient DB errors don't permanently drop counts.
		e.rpzHitMu.Lock()
		for id, delta := range deltas {
			e.rpzHitDeltas[id] += delta
		}
		e.rpzHitMu.Unlock()
	}
}

// touchLocalRecords updates last_used_at for local zone records that matched.
func (e *Engine) touchLocalRecords(domain, qType string) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, zd := range e.zones {
		zoneDomain := strings.ToLower(zd.Zone.Domain)
		domainLower := strings.ToLower(domain)

		if !strings.HasSuffix(domainLower, zoneDomain) && domainLower != zoneDomain {
			continue
		}

		var hostLabel string
		if domainLower == zoneDomain {
			hostLabel = "@"
		} else {
			hostLabel = strings.TrimSuffix(domainLower, "."+zoneDomain)
		}

		for _, rec := range zd.Records {
			if strings.ToLower(rec.Host) == hostLabel && strings.EqualFold(rec.Type, qType) {
				now := time.Now()
				db.DB.Model(&model.DNSRecord{}).Where("id = ?", rec.ID).Update("last_used_at", now)
			}
		}
	}
}
