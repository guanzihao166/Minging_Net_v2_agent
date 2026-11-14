package engine

import (
	"bytes"
	"context"
	"fmt"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/meter"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/xcore"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	sj "github.com/sagernet/sing/common/json"
	"sync"
)

// coreRuntime is a started-or-stoppable protocol core serving one inbound.
type coreRuntime interface {
	Start() error
	Close() error
}
type instance struct {
	box  coreRuntime
	core string
	raw  []byte
}
type Engine struct {
	mu           sync.Mutex
	ctx          context.Context
	tlsDirectory string
	tracker      adapter.ConnectionTracker
	instances    map[int64]instance
	snapshot     wire.Snapshot
	save         func(wire.Snapshot) error
	update       func(wire.Snapshot)
	closeInbound func(int64)
}

func New(ctx context.Context, tlsDirectory string, tracker adapter.ConnectionTracker, save func(wire.Snapshot) error, update func(wire.Snapshot), closeInbound func(int64)) *Engine {
	return &Engine{ctx: ctx, tlsDirectory: tlsDirectory, tracker: tracker, instances: map[int64]instance{}, save: save, update: update, closeInbound: closeInbound}
}
func (e *Engine) make(raw []byte) (*box.Box, error) {
	ctx := coreContext(e.ctx)
	options, err := sj.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("protocol configuration rejected: %w", err)
	}
	b, err := box.New(box.Options{Options: options, Context: ctx})
	if err != nil {
		return nil, err
	}
	if e.tracker != nil {
		b.Router().AppendTracker(e.tracker)
	}
	return b, nil
}
func (e *Engine) start(core string, raw []byte) (coreRuntime, error) {
	if core == coreXray {
		// Without the metering tracker no Xray connection can be admitted.
		tracker, _ := e.tracker.(*meter.Tracker)
		allowPrivate, _ := e.ctx.Value(egressTestKey{}).(bool)
		return xcore.New(e.ctx, raw, tracker, allowPrivate)
	}
	return e.make(raw)
}
func (e *Engine) Apply(s wire.Snapshot) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s.IssuedAt.Before(e.snapshot.IssuedAt) {
		return nil
	}
	candidate := map[int64]instance{}
	committed := false
	defer func() {
		if !committed {
			for id, c := range candidate {
				if old, ok := e.instances[id]; !ok || old.box != c.box {
					c.box.Close()
				}
			}
		}
	}()
	for _, in := range s.Inbounds {
		if len(in.Users) == 0 {
			continue
		}
		core, raw, err := Plan(in, e.tlsDirectory)
		if err != nil {
			return fmt.Errorf("inbound %d rejected: %w", in.ID, err)
		}
		if old, ok := e.instances[in.ID]; ok && old.core == core && bytes.Equal(old.raw, raw) {
			candidate[in.ID] = old
			continue
		}
		b, err := e.start(core, raw)
		if err != nil {
			return fmt.Errorf("inbound %d validation failed: %w", in.ID, err)
		}
		candidate[in.ID] = instance{b, core, raw}
	}
	changed := map[int64]instance{}
	for id, old := range e.instances {
		next, ok := candidate[id]
		if !ok || old.box != next.box {
			e.closeInbound(id)
			old.box.Close()
			changed[id] = old
		}
	}
	var failure error
	for id, next := range candidate {
		old, ok := e.instances[id]
		if ok && old.box == next.box {
			continue
		}
		if err := next.box.Start(); err != nil {
			failure = fmt.Errorf("inbound %d failed to start", id)
			break
		}
	}
	if failure == nil && e.save != nil {
		failure = e.save(s)
	}
	if failure != nil {
		for id, next := range candidate {
			old, ok := e.instances[id]
			if !ok || old.box != next.box {
				next.box.Close()
			}
		}
		candidate = map[int64]instance{} // already closed above; avoid double close during rollback
		for id, old := range changed {
			restored, err := e.start(old.core, old.raw)
			if err != nil {
				return fmt.Errorf("configuration failed; previous inbound %d restore failed", id)
			}
			if err = restored.Start(); err != nil {
				restored.Close()
				return fmt.Errorf("configuration failed; previous inbound %d restart failed", id)
			}
			e.instances[id] = instance{restored, old.core, old.raw}
		}
		return failure
	}
	e.instances = candidate
	committed = true
	e.snapshot = s
	e.update(s)
	return nil
}
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, x := range e.instances {
		e.closeInbound(id)
		x.box.Close()
	}
	e.instances = map[int64]instance{}
}
func (e *Engine) Snapshot() wire.Snapshot { e.mu.Lock(); defer e.mu.Unlock(); return e.snapshot }
