package ollamasupervisor

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// parseCPUQuota accepts cpu.max contents or the two v1 values joined by space.
// Zero means an unlimited quota; limited quotas round up without overflowing.
func parseCPUQuota(contents string) (int, error) {
	fields := strings.Fields(contents)
	if len(fields) != 2 {
		return 0, fmt.Errorf("CPU quota must contain quota and period")
	}
	period, err := strconv.Atoi(fields[1])
	if err != nil || period <= 0 {
		return 0, fmt.Errorf("CPU period must be a positive integer")
	}
	if fields[0] == "max" || fields[0] == "-1" {
		return 0, nil
	}
	quota, err := strconv.Atoi(fields[0])
	if err != nil || quota <= 0 {
		return 0, fmt.Errorf("CPU quota must be positive or unlimited")
	}
	threads := quota / period
	if quota%period != 0 {
		threads++
	}
	return threads, nil
}

func cpuThreads(readFile func(string) ([]byte, error)) int {
	fallback := runtime.NumCPU()
	if contents, err := readFile("/sys/fs/cgroup/cpu.max"); err == nil {
		if threads, err := parseCPUQuota(string(contents)); err == nil {
			if threads == 0 {
				return fallback
			}
			return threads
		}
	}
	for _, directory := range []string{"/sys/fs/cgroup/cpu", "/sys/fs/cgroup/cpu,cpuacct", "/sys/fs/cgroup"} {
		quota, quotaErr := readFile(directory + "/cpu.cfs_quota_us")
		period, periodErr := readFile(directory + "/cpu.cfs_period_us")
		if quotaErr != nil || periodErr != nil {
			continue
		}
		if threads, err := parseCPUQuota(string(quota) + " " + string(period)); err == nil {
			if threads == 0 {
				return fallback
			}
			return threads
		}
	}
	return fallback
}
