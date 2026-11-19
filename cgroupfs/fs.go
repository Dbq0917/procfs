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

// Package cgroupfs provides read-only access to the control group filesystem
// (cgroupfs), normally mounted at /sys/fs/cgroup.
//
// The kernel exposes two incompatible on-disk layouts:
//
//   - cgroup v1 mounts one hierarchy per controller, for example
//     cpuacct.usage and memory.stat live in different directories.
//   - cgroup v2 uses a single unified hierarchy with files such as cpu.stat
//     and memory.current.
//
// The difference between the two layouts is isolated in this package: callers
// work with one [FS] and one set of metric structs regardless of the running
// kernel. The layout is detected once in [NewFS], and every metric collector
// is shared between both versions through the [Cgroup] adapter, so adding a
// new metric means extending one collector rather than maintaining two copies
// of the collection logic.
//
// [FS.Snapshot] returns the cgroups that exist during one collection pass.
// The package keeps no cache between passes, so a container or scope removed
// by a rolling replacement is absent from the next snapshot. Parent-child
// relationships are derived from the relative cgroup path, not from directory
// iteration order. [Snapshot.AttributedUsage] removes descendant counters from
// hierarchical cgroup readings so callers cannot double count a parent and its
// children.
package cgroupfs

import (
	"errors"
	"fmt"
	"os"

	"github.com/prometheus/procfs/internal/fs"
)

// DefaultMountPoint is the common mount point of the cgroup filesystem.
const DefaultMountPoint = "/sys/fs/cgroup"

var (
	// ErrFileRead is returned when a cgroup file cannot be read.
	ErrFileRead = errors.New("error reading cgroup file")
	// ErrFileParse is returned when a cgroup file cannot be parsed.
	ErrFileParse = errors.New("error parsing cgroup file")
	// ErrUnsupportedVersion is returned when the cgroup layout cannot be
	// identified as either v1 or v2.
	ErrUnsupportedVersion = errors.New("unsupported cgroup version")
)

// Mode identifies the on-disk layout of the mounted cgroup filesystem.
type Mode int

const (
	// ModeUnknown is returned when neither the v1 nor the v2 layout is detected.
	ModeUnknown Mode = iota
	// ModeV1 is the legacy per-controller hierarchy layout.
	ModeV1
	// ModeV2 is the unified hierarchy layout.
	ModeV2
)

// String returns the canonical name of the cgroup layout.
func (m Mode) String() string {
	switch m {
	case ModeV1:
		return "v1"
	case ModeV2:
		return "v2"
	default:
		return "unknown"
	}
}

// FS represents the pseudo-filesystem cgroupfs, which provides an interface
// to kernel resource accounting for control groups.
type FS struct {
	mode Mode
	root fs.FS
}

// NewDefaultFS returns a new FS mounted under [DefaultMountPoint]. It returns
// an error if the mount point cannot be read or its cgroup layout cannot be
// determined.
func NewDefaultFS() (FS, error) {
	return NewFS(DefaultMountPoint)
}

// NewFS returns a new FS mounted under the given mountPoint. The cgroup layout
// is detected once here; all later metric reads go through version-independent
// collectors.
func NewFS(mountPoint string) (FS, error) {
	root, err := fs.NewFS(mountPoint)
	if err != nil {
		return FS{}, err
	}

	mode, err := detectMode(root)
	if err != nil {
		return FS{}, err
	}

	return FS{mode: mode, root: root}, nil
}

// Mode reports the detected cgroup layout.
func (fs FS) Mode() Mode {
	return fs.mode
}

// Cgroup returns a handle for the control group located at cgroupPath,
// relative to the cgroupfs mount point. Pass an empty string or "/" for the
// root cgroup. The returned [Cgroup] keeps collection logic identical across
// cgroup versions and only differs in how logical metric names map to files.
func (fs FS) Cgroup(cgroupPath string) Cgroup {
	return Cgroup{mode: fs.mode, root: fs.root, path: cleanCgroupPath(cgroupPath)}
}

// detectMode identifies the layout by probing layout-specific marker files.
//
// cgroup.controllers at the mount root only exists on a cgroup v2 hierarchy.
// On hybrid systems the v2 tree is mounted under a subdirectory (typically
// "unified"), so the marker is absent at the root and the v1 per-controller
// directories (cpu, cpuacct, memory, pids, blkio) identify the layout as v1.
func detectMode(root fs.FS) (Mode, error) {
	v2Marker := root.Path("cgroup.controllers")
	if _, err := os.Stat(v2Marker); err == nil {
		return ModeV2, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ModeUnknown, fmt.Errorf("%w: cannot stat %q: %w", ErrFileRead, v2Marker, err)
	}

	for _, controller := range []string{"cpu", "cpuacct", "memory", "pids", "blkio"} {
		if info, err := os.Stat(root.Path(controller)); err == nil && info.IsDir() {
			return ModeV1, nil
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return ModeUnknown, fmt.Errorf("%w: cannot stat cgroup controller %q: %w", ErrFileRead, controller, err)
		}
	}

	return ModeUnknown, fmt.Errorf("%w: no cgroup v1 controller directory or v2 marker file found under %q", ErrUnsupportedVersion, string(root))
}

// cleanCgroupPath normalizes a cgroup-relative path so the root cgroup is
// represented by "." and every other path is relative without a leading slash.
func cleanCgroupPath(cgroupPath string) string {
	if cgroupPath == "" || cgroupPath == "/" {
		return "."
	}
	normalized, err := normalizeCgroupPath(cgroupPath)
	if err != nil {
		// Cgroup does not return an error, so an escaping path is clamped to
		// the root rather than allowed to address files outside the mount.
		return "."
	}
	return normalized
}
