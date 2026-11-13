package journal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	bolt "github.com/sagernet/bbolt"
	"os"
	"path/filepath"
	"time"
)

type Entry struct {
	Request   wire.GrantRequest `json:"request"`
	Grant     wire.Grant        `json:"grant"`
	State     string            `json:"state"`
	Report    wire.GrantReport  `json:"report"`
	UpdatedAt time.Time         `json:"updated_at"`
}
type Store struct {
	db     *bolt.DB
	secret []byte
}

func Open(dir, token string) (*Store, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	db, e := bolt.Open(filepath.Join(dir, "usage.db"), 0600, &bolt.Options{Timeout: time.Second})
	if e != nil {
		return nil, e
	}
	key := sha256.Sum256([]byte("minging-agent-state-v1:" + token))
	s := &Store{db: db, secret: key[:]}
	e = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"grants", "state", "nonces"} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		return setJournalCount(tx, uint64(tx.Bucket([]byte("grants")).Stats().KeyN))
	})
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) UseNonce(nonce string) (bool, error) {
	fresh := false
	e := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nonces"))
		cursor := b.Cursor()
		now := time.Now().Unix()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			if len(v) != 8 || now-int64(binary.BigEndian.Uint64(v)) > 60 {
				if err := cursor.Delete(); err != nil {
					return err
				}
			}
		}
		if b.Get([]byte(nonce)) != nil {
			return nil
		}
		stamp := make([]byte, 8)
		binary.BigEndian.PutUint64(stamp, uint64(now))
		if err := b.Put([]byte(nonce), stamp); err != nil {
			return err
		}
		fresh = true
		return nil
	})
	return fresh, e
}
func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Put(e Entry) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("grants"))
		if b.Get([]byte(e.Request.ID)) == nil && journalCount(tx) >= 100000 {
			return errors.New("usage journal capacity reached")
		}
		e.UpdatedAt = time.Now().UTC()
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if b.Get([]byte(e.Request.ID)) == nil {
			if err = setJournalCount(tx, journalCount(tx)+1); err != nil {
				return err
			}
		}
		return b.Put([]byte(e.Request.ID), raw)
	})
}
func (s *Store) Settle(id string, up, down int64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("grants"))
		var e Entry
		if err := json.Unmarshal(b.Get([]byte(id)), &e); err != nil {
			return err
		}
		if e.State == "settled" {
			return errors.New("grant already settled")
		}
		if up < 0 || down < 0 || up+down > e.Grant.Bytes {
			return errors.New("invalid usage settlement")
		}
		e.State = "settled"
		e.Report = wire.GrantReport{ID: id, Upload: up, Download: down, Closed: true}
		raw, _ := json.Marshal(e)
		if err := b.Put([]byte(id), raw); err != nil {
			return err
		}
		state := tx.Bucket([]byte("state"))
		for key, delta := range map[string]int64{"total_upload": up, "total_download": down} {
			old := state.Get([]byte(key))
			var n uint64
			if len(old) == 8 {
				n = binary.BigEndian.Uint64(old)
			}
			value := make([]byte, 8)
			binary.BigEndian.PutUint64(value, n+uint64(delta))
			if err := state.Put([]byte(key), value); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Store) Entries() ([]Entry, error) {
	items := []Entry{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("grants")).ForEach(func(k, v []byte) error {
			var e Entry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			items = append(items, e)
			return nil
		})
	})
	return items, err
}
func journalCount(tx *bolt.Tx) uint64 {
	value := tx.Bucket([]byte("state")).Get([]byte("journal_count"))
	if len(value) == 8 {
		return binary.BigEndian.Uint64(value)
	}
	return 0
}
func setJournalCount(tx *bolt.Tx, n uint64) error {
	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, n)
	return tx.Bucket([]byte("state")).Put([]byte("journal_count"), value)
}
func dropGrant(tx *bolt.Tx, id string) error {
	b := tx.Bucket([]byte("grants"))
	if b.Get([]byte(id)) == nil {
		return nil
	}
	if err := b.Delete([]byte(id)); err != nil {
		return err
	}
	n := journalCount(tx)
	if n > 0 {
		n--
	}
	return setJournalCount(tx, n)
}
func (s *Store) Drop(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return dropGrant(tx, id) })
}
func (s *Store) Abandon(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("grants"))
		raw := b.Get([]byte(id))
		if raw == nil {
			return nil
		}
		var entry Entry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return err
		}
		if entry.State != "requested" {
			return nil
		}
		entry.State = "abandoned"
		entry.UpdatedAt = time.Now().UTC()
		raw, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(id), raw)
	})
}
func (s *Store) Totals() (int64, int64) {
	var up, down int64
	s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("state"))
		if v := b.Get([]byte("total_upload")); len(v) == 8 {
			up = int64(binary.BigEndian.Uint64(v))
		}
		if v := b.Get([]byte("total_download")); len(v) == 8 {
			down = int64(binary.BigEndian.Uint64(v))
		}
		return nil
	})
	return up, down
}
func (s *Store) SaveSnapshot(v wire.Snapshot) error {
	raw, e := json.Marshal(v)
	if e != nil {
		return e
	}
	block, e := aes.NewCipher(s.secret)
	if e != nil {
		return e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	sealed := g.Seal(nonce, nonce, raw, []byte("snapshot"))
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("state")).Put([]byte("snapshot"), sealed) })
}
func (s *Store) LoadSnapshot() (wire.Snapshot, error) {
	var snapshot wire.Snapshot
	var sealed []byte
	e := s.db.View(func(tx *bolt.Tx) error {
		sealed = append([]byte(nil), tx.Bucket([]byte("state")).Get([]byte("snapshot"))...)
		return nil
	})
	if e != nil {
		return snapshot, e
	}
	block, e := aes.NewCipher(s.secret)
	if e != nil {
		return snapshot, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return snapshot, e
	}
	if len(sealed) < g.NonceSize() {
		return snapshot, os.ErrNotExist
	}
	raw, e := g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], []byte("snapshot"))
	if e != nil {
		return snapshot, e
	}
	e = json.Unmarshal(raw, &snapshot)
	return snapshot, e
}
func (s *Store) QueueReport(report wire.Report) ([]byte, error) {
	var out []byte
	e := s.db.Update(func(tx *bolt.Tx) error {
		state := tx.Bucket([]byte("state"))
		if raw := state.Get([]byte("outbox")); len(raw) > 0 {
			out = append([]byte(nil), raw...)
			return nil
		}
		report.Grants = []wire.GrantReport{}
		e := tx.Bucket([]byte("grants")).ForEach(func(k, v []byte) error {
			if len(report.Grants) >= 1000 {
				return nil
			}
			var entry Entry
			if err := json.Unmarshal(v, &entry); err != nil {
				return err
			}
			if entry.State == "settled" {
				report.Grants = append(report.Grants, entry.Report)
			}
			return nil
		})
		if e != nil {
			return e
		}
		out, e = json.Marshal(report)
		if e != nil {
			return e
		}
		return state.Put([]byte("outbox"), out)
	})
	return out, e
}
func (s *Store) AckReport(raw []byte) error {
	var report wire.Report
	if e := json.Unmarshal(raw, &report); e != nil {
		return e
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		state := tx.Bucket([]byte("state"))
		var old wire.Report
		if e := json.Unmarshal(state.Get([]byte("outbox")), &old); e != nil {
			return e
		}
		if old.ID != report.ID {
			return errors.New("outbox acknowledgement mismatch")
		}
		for _, g := range report.Grants {
			if e := dropGrant(tx, g.ID); e != nil {
				return e
			}
		}
		return state.Delete([]byte("outbox"))
	})
}
