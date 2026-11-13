package daemon

import (
	"encoding/json"
	"errors"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/control"
	"os"
	"path/filepath"
	"time"
)

type localStatus struct {
	At      time.Time `json:"at"`
	Healthy bool      `json:"healthy"`
	Version string    `json:"version"`
}

func (d *Daemon) writeStatus(healthy bool) error {
	raw, _ := json.Marshal(localStatus{time.Now().UTC(), healthy, d.version})
	path := filepath.Join(d.config.StateDirectory, "health.json")
	if err := os.WriteFile(path+".next", raw, 0600); err != nil {
		return err
	}
	return os.Rename(path+".next", path)
}
func CheckStatus(c control.Config) error {
	raw, err := os.ReadFile(filepath.Join(c.StateDirectory, "health.json"))
	if err != nil {
		return err
	}
	var status localStatus
	if json.Unmarshal(raw, &status) != nil || !status.Healthy || time.Since(status.At) > 12*time.Second || status.At.After(time.Now().Add(time.Second)) {
		return errors.New("fresh healthy acknowledgement not available")
	}
	return nil
}
