package meter

import (
	"errors"
	"strconv"
	"time"

	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
)

// Remote grants remain durable quota reservations. Tickets divide a grant
// locally; only its actual, cumulative usage is ever sent to the controller.
type credit struct {
	grant     wire.Grant
	available int64
	pending   int
	retired   bool
	closed    bool
	prefetch  bool
}

type creditTicket struct {
	credit *credit
	bytes  int64
}

func (f *flow) collectCreditsLocked() error {
	kept := f.credits[:0]
	var failure error
	for _, c := range f.credits {
		if !c.closed && c.pending == 0 && (c.retired || c.available == 0) {
			if err := f.tracker.store.Accumulate(c.grant.ID, 0, 0, true); err != nil {
				failure = err
				f.tracker.failed.Store(true)
			} else {
				c.closed = true
			}
		}
		if !c.closed {
			kept = append(kept, c)
		}
	}
	f.credits = kept
	return failure
}

func (f *flow) retireCredits() {
	f.creditMu.Lock()
	defer f.creditMu.Unlock()
	for _, c := range f.credits {
		c.retired = true
	}
	f.collectCreditsLocked()
}

// At most one refill is in flight and one unused successor grant is kept.
// The central rate bucket is charged on allocation, across all servers/flows.
func (f *flow) startFetchLocked() {
	if f.fetching || f.ctx.Err() != nil || f.fetchErr != nil {
		return
	}
	usable := 0
	for _, c := range f.credits {
		if !c.retired && c.available > 0 {
			usable++
		}
	}
	if usable >= 2 || !f.tracker.begin() {
		return
	}
	f.fetching = true
	f.fetchDone = make(chan struct{})
	n := f.creditSize
	go func() {
		defer f.tracker.work.Done()
		g, err := f.fetchGrant(int(n))
		f.creditMu.Lock()
		defer f.creditMu.Unlock()
		if err == nil {
			c := &credit{grant: g, available: g.Bytes, prefetch: g.Bytes == n}
			f.credits = append(f.credits, c)
			if f.ctx.Err() != nil {
				c.retired = true
				f.collectCreditsLocked()
			} else {
				f.creditSize = min(f.creditMax, n*8)
				// Retire idle credits even if no further socket I/O occurs.
				if f.tracker.begin() {
					go f.expireCredit(c)
				} else {
					c.retired = true
					f.collectCreditsLocked()
				}
			}
		} else {
			f.fetchErr = err
		}
		f.fetching = false
		close(f.fetchDone)
	}()
}

func (f *flow) expireCredit(c *credit) {
	defer f.tracker.work.Done()
	timer := time.NewTimer(max(time.Duration(0), time.Until(c.grant.ExpiresAt.Add(-200*time.Millisecond))))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-f.ctx.Done():
	}
	f.creditMu.Lock()
	c.retired = true
	f.collectCreditsLocked()
	f.creditMu.Unlock()
}

func (f *flow) permit(n int) (wire.Grant, error) {
	if n < 1 || n > 65536 {
		return wire.Grant{}, errors.New("invalid byte count")
	}
	for {
		if f.ctx.Err() != nil || !f.tracker.active(f.lease.InboundID, f.lease.UserID, f.lease.Epoch) || time.Now().UnixNano() >= f.until.Load() {
			return wire.Grant{}, errors.New("lease inactive")
		}
		f.creditMu.Lock()
		now := time.Now().Add(200 * time.Millisecond)
		for _, c := range f.credits {
			if !c.grant.ExpiresAt.After(now) {
				c.retired = true
			}
		}
		if err := f.collectCreditsLocked(); err != nil {
			f.creditMu.Unlock()
			return wire.Grant{}, err
		}
		var available int64
		var selected *credit
		for _, c := range f.credits {
			if !c.retired {
				available += c.available
				if selected == nil && c.available > 0 {
					selected = c
				}
			}
		}
		if selected != nil {
			bytes := min(int64(n), selected.available)
			selected.available -= bytes
			selected.pending++
			f.ticketSequence++
			id := selected.grant.ID + ":" + strconv.FormatUint(f.ticketSequence, 10)
			f.tickets[id] = creditTicket{credit: selected, bytes: bytes}
			// A partial quota grant is consumed before asking for another one.
			if selected.prefetch && available-bytes < selected.grant.Bytes/2 {
				f.startFetchLocked()
			}
			g := wire.Grant{ID: id, Bytes: bytes, ExpiresAt: selected.grant.ExpiresAt}
			f.creditMu.Unlock()
			return g, nil
		}
		if f.fetchErr != nil {
			err := f.fetchErr
			f.creditMu.Unlock()
			return wire.Grant{}, err
		}
		f.creditSize = max(f.creditSize, int64(n))
		f.startFetchLocked()
		if !f.fetching {
			f.creditMu.Unlock()
			return wire.Grant{}, errors.New("credit refill stopped")
		}
		done := f.fetchDone
		f.creditMu.Unlock()
		select {
		case <-done:
		case <-f.ctx.Done():
			return wire.Grant{}, f.ctx.Err()
		}
	}
}

func (f *flow) settle(g wire.Grant, up, down int64) error {
	f.creditMu.Lock()
	ticket, ok := f.tickets[g.ID]
	if !ok || up < 0 || down < 0 || up+down > ticket.bytes || g.Bytes != ticket.bytes {
		f.creditMu.Unlock()
		return errors.New("invalid credit ticket settlement")
	}
	delete(f.tickets, g.ID)
	c := ticket.credit
	c.pending--
	// Unsent ticket bytes are released at close, not reused after an ambiguous
	// or partial write. The reservation covers every byte that could be sent.
	err := f.tracker.store.Accumulate(c.grant.ID, up, down, false)
	if err == nil {
		err = f.collectCreditsLocked()
	}
	f.creditMu.Unlock()
	if err != nil {
		f.tracker.failed.Store(true)
		f.close()
	}
	return err
}
