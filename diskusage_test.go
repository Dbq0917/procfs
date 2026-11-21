// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package procfs

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// unionMountInfo models a container host: an overlay mount whose merged view
// and lower/upper layers live on the same backing device (8:1), a bind mount
// of the same device, plus two genuinely independent devices (a tmpfs and a
// distinct block device).
const unionMountInfo = `21 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw,data=ordered
100 21 8:1 /var/lib/docker/overlay2/abc/merged /var/lib/docker/overlay2/abc/merged rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w
101 21 8:1 /var/lib/docker/overlay2/abc/upper /var/lib/docker/overlay2/abc/upper rw,relatime - ext4 /dev/sda1 rw,data=ordered
102 21 8:1 /etc /opt/etc-bind rw,relatime - ext4 /dev/sda1 rw,data=ordered
200 21 0:50 / /run rw,nosuid,noexec - tmpfs tmpfs rw,mode=755
300 21 8:2 / /data rw,relatime - xfs /dev/sdb1 rw
`

// fakeStatfs returns fixed blocks per backing device so the expected totals
// are independent of the host kernel. The bsize of 4096 keeps the arithmetic
// trivial.
func fakeStatfs(t *testing.T, calls *[]string) func(string, *syscall.Statfs_t) error {
	t.Helper()
	blocks := map[string]struct{ blocks, bfree, bavail uint64 }{
		"/":                                   {1000, 400, 300},
		"/var/lib/docker/overlay2/abc/merged": {1000, 400, 300},
		"/var/lib/docker/overlay2/abc/upper":  {1000, 400, 300},
		"/opt/etc-bind":                       {1000, 400, 300},
		"/run":                                {100, 90, 90},
		"/data":                               {500, 100, 80},
	}
	return func(path string, stat *syscall.Statfs_t) error {
		*calls = append(*calls, path)
		values, ok := blocks[path]
		if !ok {
			t.Fatalf("unexpected statfs call for %q", path)
		}
		stat.Bsize = 4096
		stat.Blocks = values.blocks
		stat.Bfree = values.bfree
		stat.Bavail = values.bavail
		return nil
	}
}

func newDiskUsageFS(t *testing.T, mountInfo string) FS {
	t.Helper()
	procRoot := t.TempDir()
	selfDir := filepath.Join(procRoot, "self")
	if err := os.MkdirAll(selfDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(selfDir, "mountinfo"), []byte(mountInfo), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, err := NewFS(procRoot)
	if err != nil {
		t.Fatalf("NewFS: %v", err)
	}
	return fs
}

func TestDiskUsageDeduplicatesUnionAndBindMounts(t *testing.T) {
	fs := newDiskUsageFS(t, unionMountInfo)

	var calls []string
	oldStatfs := statfs
	statfs = fakeStatfs(t, &calls)
	t.Cleanup(func() { statfs = oldStatfs })

	usage, err := fs.DiskUsage()
	if err != nil {
		t.Fatalf("DiskUsage: %v", err)
	}

	// Six mount points but only three unique devices: the overlay merged/upper
	// views and the bind mount must not be counted on top of the root mount.
	want := []FilesystemUsage{
		{
			Device:         "8:1",
			MountPoint:     "/",
			FSType:         "ext4",
			Source:         "/dev/sda1",
			TotalBytes:     1000 * 4096,
			FreeBytes:      400 * 4096,
			AvailableBytes: 300 * 4096,
			UsedBytes:      600 * 4096,
		},
		{
			Device:         "0:50",
			MountPoint:     "/run",
			FSType:         "tmpfs",
			Source:         "tmpfs",
			TotalBytes:     100 * 4096,
			FreeBytes:      90 * 4096,
			AvailableBytes: 90 * 4096,
			UsedBytes:      10 * 4096,
		},
		{
			Device:         "8:2",
			MountPoint:     "/data",
			FSType:         "xfs",
			Source:         "/dev/sdb1",
			TotalBytes:     500 * 4096,
			FreeBytes:      100 * 4096,
			AvailableBytes: 80 * 4096,
			UsedBytes:      400 * 4096,
		},
	}
	if len(usage) != len(want) {
		t.Fatalf("got %d unique devices (%+v), want %d", len(usage), usage, len(want))
	}
	for i := range want {
		if usage[i] != want[i] {
			t.Fatalf("device %d:\n  got  %+v\n  want %+v", i, usage[i], want[i])
		}
	}

	// One statfs per unique device: dedup must not increase collection cost.
	if len(calls) != len(want) {
		t.Fatalf("statfs called %d times (%v), want exactly %d (once per unique device)", len(calls), calls, len(want))
	}

	// The naive per-mount sum would count the 8:1 device four times. The
	// deduplicated total must equal the actual physical footprint instead.
	var naiveSum, dedupedTotal uint64
	for range 4 {
		naiveSum += 1000 * 4096
	}
	naiveSum += 100*4096 + 500*4096
	for _, u := range usage {
		dedupedTotal += u.TotalBytes
	}
	if dedupedTotal != (1000+100+500)*4096 {
		t.Fatalf("deduplicated total = %d, want %d", dedupedTotal, (1000+100+500)*4096)
	}
	if naiveSum <= dedupedTotal {
		t.Fatalf("naive sum %d should exceed the deduplicated total %d", naiveSum, dedupedTotal)
	}
}

func TestDiskUsagePropagatesStatfsError(t *testing.T) {
	fs := newDiskUsageFS(t, unionMountInfo)

	oldStatfs := statfs
	statfs = func(_ string, _ *syscall.Statfs_t) error {
		return os.ErrNotExist
	}
	t.Cleanup(func() { statfs = oldStatfs })

	if _, err := fs.DiskUsage(); err == nil {
		t.Fatal("expected DiskUsage to return the statfs error")
	}
}

// TestDiskUsageAgainstRealMounts runs against the host's own mountinfo. It is
// skipped unless PROCFS_DISKUSAGE_LIVE=1 so the normal test suite stays
// hermetic. It verifies that every reported device number is unique and that
// the per-device numbers match a direct syscall.Statfs on the mount point.
func TestDiskUsageAgainstRealMounts(t *testing.T) {
	if os.Getenv("PROCFS_DISKUSAGE_LIVE") == "" {
		t.Skip("set PROCFS_DISKUSAGE_LIVE=1 to run against the real mountinfo")
	}

	fs, err := NewDefaultFS()
	if err != nil {
		t.Skipf("real procfs unavailable: %v", err)
	}
	usage, err := fs.DiskUsage()
	if err != nil {
		t.Fatalf("DiskUsage: %v", err)
	}

	mounts, err := fs.GetMounts()
	if err != nil {
		t.Fatalf("GetMounts: %v", err)
	}
	if len(usage) > len(mounts) || len(usage) == 0 {
		t.Fatalf("got %d device records for %d mount points", len(usage), len(mounts))
	}

	seen := map[string]bool{}
	for _, u := range usage {
		if seen[u.Device] {
			t.Fatalf("device %s reported more than once", u.Device)
		}
		seen[u.Device] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(u.MountPoint, &stat); err != nil {
			t.Fatalf("statfs %s: %v", u.MountPoint, err)
		}
		total := stat.Blocks * uint64(stat.Bsize)
		if u.TotalBytes != total {
			t.Fatalf("%s total = %d, direct statfs says %d", u.MountPoint, u.TotalBytes, total)
		}
		if u.UsedBytes != total-stat.Bfree*uint64(stat.Bsize) {
			t.Fatalf("%s used bytes do not match direct statfs", u.MountPoint)
		}
	}

	t.Logf("%d mount points -> %d unique devices (%.1f%% redundant views)",
		len(mounts), len(usage), 100*float64(len(mounts)-len(usage))/float64(len(mounts)))
}
