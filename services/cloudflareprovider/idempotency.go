package cloudflareprovider

import (
	"context"
	"time"
)

type idempotencyEntry struct {
	fingerprint string
	done        chan struct{}
	value       any
	err         error
	createdAt   time.Time
}

func (c *Client) runIdempotent(ctx context.Context, operation, scope, key, fingerprint string, execute func() (any, error)) (any, error) {
	cacheKey := operation + "\x00" + scope + "\x00" + key
	c.idemMu.Lock()
	if existing, ok := c.idem[cacheKey]; ok {
		if existing.fingerprint != fingerprint {
			c.idemMu.Unlock()
			return nil, &Error{Kind: ErrorConflict, Operation: operation}
		}
		done := existing.done
		c.idemMu.Unlock()
		select {
		case <-done:
			return existing.value, existing.err
		case <-ctx.Done():
			if ctx.Err() == context.Canceled {
				return nil, &Error{Kind: ErrorCancelled, Operation: operation}
			}
			return nil, &Error{Kind: ErrorTimeout, Operation: operation, Retryable: true}
		}
	}
	if len(c.idem) >= c.maxIdemEntries && !c.evictOldestCompletedLocked() {
		c.idemMu.Unlock()
		return nil, &Error{Kind: ErrorConflict, Operation: operation, Retryable: true}
	}
	entry := &idempotencyEntry{fingerprint: fingerprint, done: make(chan struct{}), createdAt: time.Now()}
	c.idem[cacheKey] = entry
	c.idemMu.Unlock()

	value, err := execute()
	c.idemMu.Lock()
	entry.value = value
	entry.err = err
	if err != nil {
		delete(c.idem, cacheKey)
	}
	close(entry.done)
	c.idemMu.Unlock()
	return value, err
}

func (c *Client) evictOldestCompletedLocked() bool {
	var oldestKey string
	var oldest *idempotencyEntry
	for key, entry := range c.idem {
		select {
		case <-entry.done:
			if oldest == nil || entry.createdAt.Before(oldest.createdAt) {
				oldestKey = key
				oldest = entry
			}
		default:
		}
	}
	if oldest == nil {
		return false
	}
	delete(c.idem, oldestKey)
	return true
}
