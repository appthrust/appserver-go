package ollamasupervisor

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCPUQuota(t *testing.T) {
	for _, test := range []struct {
		contents string
		threads  int
	}{
		{"max 100000", 0},
		{"400000 100000", 4},
		{"150000 100000", 2},
		{"50000 100000", 1},
		{"-1\n 100000\n", 0},
	} {
		t.Run(test.contents, func(t *testing.T) {
			threads, err := parseCPUQuota(test.contents)
			require.NoError(t, err)
			require.Equal(t, test.threads, threads)
		})
	}
	for _, contents := range []string{"", "max", "max 0", "100 0", "0 100", "-2 100", "bad 100", "100 bad", "100 100 extra"} {
		_, err := parseCPUQuota(contents)
		require.Error(t, err, contents)
	}
}

func TestCPUThreadsCgroupFallback(t *testing.T) {
	for _, test := range []struct {
		name    string
		files   map[string]string
		threads int
	}{
		{"v2", map[string]string{"/sys/fs/cgroup/cpu.max": "400000 100000\n"}, 4},
		{"fractional", map[string]string{"/sys/fs/cgroup/cpu.max": "150000 100000"}, 2},
		{"unlimited", map[string]string{"/sys/fs/cgroup/cpu.max": "max 100000"}, runtime.NumCPU()},
		{"v1", map[string]string{
			"/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "150000\n", "/sys/fs/cgroup/cpu/cpu.cfs_period_us": "100000\n",
		}, 2},
		{"v1 unlimited", map[string]string{
			"/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "-1", "/sys/fs/cgroup/cpu/cpu.cfs_period_us": "100000",
		}, runtime.NumCPU()},
		{"combined v1 controller", map[string]string{
			"/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_quota_us": "400000", "/sys/fs/cgroup/cpu,cpuacct/cpu.cfs_period_us": "100000",
		}, 4},
		{"root v1 controller", map[string]string{
			"/sys/fs/cgroup/cpu.cfs_quota_us": "400000", "/sys/fs/cgroup/cpu.cfs_period_us": "100000",
		}, 4},
		{"malformed v2 falls back to v1", map[string]string{
			"/sys/fs/cgroup/cpu.max": "invalid", "/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "200000", "/sys/fs/cgroup/cpu/cpu.cfs_period_us": "100000",
		}, 2},
		{"missing", nil, runtime.NumCPU()},
		{"malformed", map[string]string{"/sys/fs/cgroup/cpu.max": "invalid"}, runtime.NumCPU()},
	} {
		t.Run(test.name, func(t *testing.T) {
			readFile := func(path string) ([]byte, error) {
				if contents, ok := test.files[path]; ok {
					return []byte(contents), nil
				}
				return nil, os.ErrNotExist
			}
			require.Equal(t, test.threads, cpuThreads(readFile))
		})
	}
}
