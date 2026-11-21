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

import "syscall"

// FilesystemUsage reports the block usage of one unique backing device,
// identified by the st_dev major:minor number reported in mountinfo.
//
// Bind mounts and union mounts (overlayfs, etc.) expose the same backing
// device through several mount points. Each mount point that shares a device
// number is counted once, so the same data is never counted twice while
// genuinely independent devices are never skipped.
type FilesystemUsage struct {
	// Device is the st_dev major:minor number as it appears in mountinfo.
	Device string
	// MountPoint is the first mount point seen for this device.
	MountPoint string
	// FSType is the filesystem type of the first mount point seen.
	FSType string
	// Source is the mount source of the first mount point seen.
	Source string
	// TotalBytes is the total size of the backing device in bytes.
	TotalBytes uint64
	// FreeBytes is the free space, including space reserved for the
	// privileged user, in bytes.
	FreeBytes uint64
	// AvailableBytes is the free space available to unprivileged users
	// in bytes.
	AvailableBytes uint64
	// UsedBytes is the space actually used in bytes.
	UsedBytes uint64
}

// statfs is a package level indirection so tests can avoid touching the
// real filesystem.
var statfs = syscall.Statfs

// DiskUsage reports disk usage for every unique backing device visible in
// /proc/self/mountinfo. Mount points that share an st_dev number (typically
// bind mounts and the layers of an overlay/union mount) are counted only
// once, so duplicate views of the same data cannot inflate the result while
// independent mounts are still reported separately.
//
// Statfs is invoked at most once per unique device, so deduplicating does
// not add collection overhead; it usually makes the collection cheaper than
// calling statfs on every mount point.
func DiskUsage() ([]FilesystemUsage, error) {
	fs, err := NewDefaultFS()
	if err != nil {
		return nil, err
	}
	return fs.DiskUsage()
}

// DiskUsage reports disk usage for every unique backing device visible in the
// proc FS mountinfo. See the package level DiskUsage for the deduplication
// and cost guarantees.
func (fs FS) DiskUsage() ([]FilesystemUsage, error) {
	mounts, err := fs.GetMounts()
	if err != nil {
		return nil, err
	}

	usage := make([]FilesystemUsage, 0, len(mounts))
	seen := make(map[string]int, len(mounts))
	for _, mount := range mounts {
		// The major:minor version is the st_dev of the files on the mount.
		// Multiple mount points pointing at the same device (bind mounts,
		// overlay lower/upper layers, etc.) share this number, so the first
		// occurrence stands in for every other view of the same data.
		if _, ok := seen[mount.MajorMinorVer]; ok {
			continue
		}

		var stat syscall.Statfs_t
		if err := statfs(mount.MountPoint, &stat); err != nil {
			return nil, err
		}

		seen[mount.MajorMinorVer] = len(usage)
		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bfree * uint64(stat.Bsize)
		available := stat.Bavail * uint64(stat.Bsize)
		usage = append(usage, FilesystemUsage{
			Device:         mount.MajorMinorVer,
			MountPoint:     mount.MountPoint,
			FSType:         mount.FSType,
			Source:         mount.Source,
			TotalBytes:     total,
			FreeBytes:      free,
			AvailableBytes: available,
			UsedBytes:      total - free,
		})
	}

	return usage, nil
}
