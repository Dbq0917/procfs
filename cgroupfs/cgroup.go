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

package cgroupfs

import (
	"errors"

	"github.com/prometheus/procfs/internal/fs"
)

// Cgroup is a version-independent handle to one control group. It is created
// with [FS.Cgroup] and dispatches every read to the layout-specific adapter
// for the detected cgroup version.
//
// Collection code must not branch on the cgroup version here: the only
// version-specific knowledge is the file layout implemented by the
// layout adapters in cgroup_v1.go and cgroup_v2.go.
type Cgroup struct {
	mode Mode
	root fs.FS
	// path is the cgroup location relative to the cgroupfs mount point. The
	// root cgroup is represented by ".".
	path string
}

// Stats collects all metrics available for the cgroup in one pass.
//
// A missing controller file (for example because a v2 cgroup does not enable
// the memory controller) is reported as an error wrapped with
// [errors.Is](err, os.ErrNotExist) instead of silently returning a zero
// value, so a broken mount or path can never look like a healthy empty
// cgroup again.
func (c Cgroup) Stats() (CgroupStats, error) {
	var stats CgroupStats
	var errs []error

	if cpu, err := c.CPUStats(); err != nil {
		errs = append(errs, err)
	} else {
		stats.CPU = cpu
	}

	if memory, err := c.MemoryStats(); err != nil {
		errs = append(errs, err)
	} else {
		stats.Memory = memory
	}

	if pids, err := c.PidsStats(); err != nil {
		errs = append(errs, err)
	} else {
		stats.Pids = pids
	}

	if io, err := c.IOStats(); err != nil {
		errs = append(errs, err)
	} else {
		stats.IO = io
	}

	// Pressure is a v2-only feature. On v1 the controller files do not exist
	// and the absence is expected rather than an error.
	if c.mode == ModeV2 {
		if pressure, err := c.PressureStats(); err != nil {
			errs = append(errs, err)
		} else {
			stats.Pressure = pressure
		}
	}

	return stats, errors.Join(errs...)
}

// CPUStats collects CPU accounting of the cgroup.
func (c Cgroup) CPUStats() (CgroupCPUStats, error) {
	return c.layout().readCPUStats()
}

// MemoryStats collects memory accounting of the cgroup.
func (c Cgroup) MemoryStats() (CgroupMemoryStats, error) {
	return c.layout().readMemoryStats()
}

// PidsStats collects task number accounting of the cgroup.
func (c Cgroup) PidsStats() (CgroupPidsStats, error) {
	return c.layout().readPidsStats()
}

// IOStats collects block IO accounting of the cgroup.
func (c Cgroup) IOStats() ([]CgroupIOStats, error) {
	return c.layout().readIOStats()
}

// PressureStats collects pressure stall information of the cgroup. It is only
// available on cgroup v2.
func (c Cgroup) PressureStats() (CgroupPressureStats, error) {
	return c.layout().readPressureStats()
}

// layout returns the file-layout adapter for the detected cgroup version.
// This is the single place where collection code picks between v1 and v2.
func (c Cgroup) layout() cgroupLayout {
	if c.mode == ModeV2 {
		return cgroupV2{c}
	}
	return cgroupV1{c}
}

// cgroupLayout maps the version-independent metric model onto the concrete
// files of one cgroup layout. Each implementation only describes where a
// logical metric lives; parsing and aggregation are shared.
type cgroupLayout interface {
	readCPUStats() (CgroupCPUStats, error)
	readMemoryStats() (CgroupMemoryStats, error)
	readPidsStats() (CgroupPidsStats, error)
	readIOStats() ([]CgroupIOStats, error)
	readPressureStats() (CgroupPressureStats, error)
}
