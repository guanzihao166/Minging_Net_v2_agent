package daemon

import (
	"bufio"
	"github.com/guanzihao166/Minging_Net_v2_agent/internal/wire"
	"os"
	"strconv"
	"strings"
	"time"
)

type metricsState struct {
	total, idle uint64
	last        time.Time
	up, down    int64
}

func (m *metricsState) sample(up, down int64, connections int) wire.Metrics {
	out := wire.Metrics{Connections: connections, TotalUpload: up, TotalDownload: down}
	now := time.Now()
	if !m.last.IsZero() {
		elapsed := now.Sub(m.last).Seconds()
		out.UploadBPS = int64(float64(max(int64(0), up-m.up)) * 8 / elapsed)
		out.DownloadBPS = int64(float64(max(int64(0), down-m.down)) * 8 / elapsed)
	}
	m.last, m.up, m.down = now, up, down
	if raw, e := os.ReadFile("/proc/stat"); e == nil {
		line := strings.SplitN(string(raw), "\n", 2)[0]
		fields := strings.Fields(line)
		var total, idle uint64
		for i, s := range fields[1:] {
			if i >= 8 {
				break
			}
			n, _ := strconv.ParseUint(s, 10, 64)
			total += n
			if i == 3 || i == 4 {
				idle += n
			}
		}
		if total > m.total && m.total > 0 {
			delta := total - m.total
			idleDelta := min(delta, idle-m.idle)
			out.CPU = float64(delta-idleDelta) * 100 / float64(delta)
		}
		m.total, m.idle = total, idle
	}
	if f, e := os.Open("/proc/meminfo"); e == nil {
		scanner := bufio.NewScanner(f)
		var available int64
		for scanner.Scan() {
			v := strings.Fields(scanner.Text())
			if len(v) < 2 {
				continue
			}
			n, _ := strconv.ParseInt(v[1], 10, 64)
			switch v[0] {
			case "MemTotal:":
				out.MemoryTotal = n * 1024
			case "MemAvailable:":
				available = n * 1024
			}
		}
		f.Close()
		out.Memory = max(int64(0), out.MemoryTotal-available)
	}
	if raw, e := os.ReadFile("/proc/uptime"); e == nil {
		v := strings.Fields(string(raw))
		if len(v) > 0 {
			n, _ := strconv.ParseFloat(v[0], 64)
			out.Uptime = int64(n)
		}
	}
	return out
}
