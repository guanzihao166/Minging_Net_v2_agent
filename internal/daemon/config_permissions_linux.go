package daemon

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

func managedConfigMode(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm() != 0640 {
		return false
	}
	if os.Geteuid() != 0 {
		return stat.Gid == uint32(os.Getegid())
	}
	group, err := user.LookupGroup("minging-agent")
	return err == nil && group.Gid == strconv.FormatUint(uint64(stat.Gid), 10)
}
