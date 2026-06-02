package transport

import (
	"sync"
	"time"
)

// nonceCache rejects replayed handshake nonces. Each entry expires once it is
// older than the clock-skew window — past that point the timestamp check
// rejects a replay on its own, so we no longer need the nonce record.
type nonceCache struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newNonceCache() *nonceCache {
	return &nonceCache{m: make(map[string]time.Time)}
}

func (c *nonceCache) add(nonce string, t time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := t.Add(-2 * maxClockSkew)
	for k, v := range c.m {
		if v.Before(cutoff) {
			delete(c.m, k)
		}
	}
	if _, ok := c.m[nonce]; ok {
		return false
	}
	c.m[nonce] = t
	return true
}
