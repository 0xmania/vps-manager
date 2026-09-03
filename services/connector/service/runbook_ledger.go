package service

import (
	"sync"
	"time"

	connectorprotocol "vpsmanager/services/connector-protocol"
)

type runbookLedgerState uint8

const (
	runbookInProgress runbookLedgerState = iota + 1
	runbookCompleted
)

type runbookLedgerEntry struct {
	scope     string
	state     runbookLedgerState
	startedAt time.Time
	response  connectorprotocol.RunbookExecuteResponse
}

type runbookLedger struct {
	mu      sync.Mutex
	entries map[string]*runbookLedgerEntry
	max     int
}

type runbookClaim uint8

const (
	claimNew runbookClaim = iota + 1
	claimReplay
	claimConflict
	claimInProgress
	claimFull
)

func newRunbookLedger(maxEntries int) *runbookLedger {
	if maxEntries <= 0 {
		maxEntries = 10_000
	}
	return &runbookLedger{entries: make(map[string]*runbookLedgerEntry), max: maxEntries}
}

func (l *runbookLedger) claim(jobID, scope string, now time.Time) (runbookClaim, connectorprotocol.RunbookExecuteResponse) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if entry, ok := l.entries[jobID]; ok {
		if entry.scope != scope {
			return claimConflict, connectorprotocol.RunbookExecuteResponse{}
		}
		if entry.state == runbookInProgress {
			return claimInProgress, connectorprotocol.RunbookExecuteResponse{}
		}
		return claimReplay, cloneRunbookResponse(entry.response)
	}
	if len(l.entries) >= l.max {
		var oldestJob string
		var oldest time.Time
		for candidateJob, entry := range l.entries {
			if entry.state == runbookCompleted && (oldestJob == "" || entry.startedAt.Before(oldest)) {
				oldestJob, oldest = candidateJob, entry.startedAt
			}
		}
		if oldestJob == "" {
			return claimFull, connectorprotocol.RunbookExecuteResponse{}
		}
		delete(l.entries, oldestJob)
	}
	l.entries[jobID] = &runbookLedgerEntry{scope: scope, state: runbookInProgress, startedAt: now}
	return claimNew, connectorprotocol.RunbookExecuteResponse{}
}

func (l *runbookLedger) complete(jobID, scope string, response connectorprotocol.RunbookExecuteResponse) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.entries[jobID]
	if !ok || entry.scope != scope || entry.state != runbookInProgress {
		return
	}
	entry.state = runbookCompleted
	entry.response = cloneRunbookResponse(response)
}

func cloneRunbookResponse(value connectorprotocol.RunbookExecuteResponse) connectorprotocol.RunbookExecuteResponse {
	value.Steps = append([]connectorprotocol.RunbookStepResult(nil), value.Steps...)
	for index := range value.Steps {
		value.Steps[index].Stdout = append([]byte(nil), value.Steps[index].Stdout...)
		value.Steps[index].Stderr = append([]byte(nil), value.Steps[index].Stderr...)
	}
	return value
}
