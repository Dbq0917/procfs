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

// CgroupStats bundles all metrics exposed by a single control group. Fields
// stay zero when the corresponding controller is not enabled on the cgroup.
type CgroupStats struct {
	CPU      CgroupCPUStats
	Memory   CgroupMemoryStats
	Pids     CgroupPidsStats
	IO       []CgroupIOStats
	Pressure CgroupPressureStats
}

// CgroupCPUStats contains CPU accounting of a cgroup. Time fields are in
// seconds.
type CgroupCPUStats struct {
	// UsageSeconds is the total CPU time consumed by the cgroup.
	UsageSeconds float64
	// UserSeconds is the CPU time spent in user mode.
	UserSeconds float64
	// SystemSeconds is the CPU time spent in kernel mode.
	SystemSeconds float64
	// NrPeriods is the number of observed CFS scheduling periods.
	NrPeriods uint64
	// NrThrottled is the number of periods in which the cgroup was throttled.
	NrThrottled uint64
	// ThrottledSeconds is the total time the cgroup spent throttled.
	ThrottledSeconds float64
}

// CgroupMemoryStats contains memory accounting of a cgroup. All sizes are in
// bytes.
type CgroupMemoryStats struct {
	// Usage is the total memory currently charged to the cgroup.
	Usage uint64
	// Peak is the highest recorded memory usage of the cgroup.
	Peak uint64
	// Limit is the configured memory limit. A value of math.MaxUint64 means
	// the limit is unset ("max").
	Limit uint64
	// Cache is the page-cache memory charged to the cgroup.
	Cache uint64
	// Rss is the anonymous resident memory charged to the cgroup.
	Rss uint64
	// Swap is the swap memory currently charged to the cgroup.
	Swap uint64
	// OomEvents counts the number of times the cgroup hit its OOM threshold.
	OomEvents uint64
	// OomKills counts the number of tasks the OOM killer terminated in the
	// cgroup.
	OomKills uint64
}

// CgroupPidsStats contains process number accounting of a cgroup.
type CgroupPidsStats struct {
	// Current is the number of tasks in the cgroup.
	Current uint64
	// Limit is the configured task limit. A value of math.MaxUint64 means the
	// limit is unset ("max").
	Limit uint64
}

// CgroupIOStats contains block IO accounting of a cgroup for one device,
// identified by its "major:minor" number.
type CgroupIOStats struct {
	Device string
	// Rbytes is the number of bytes read from the device.
	Rbytes uint64
	// Wbytes is the number of bytes written to the device.
	Wbytes uint64
	// Rios is the number of read IO operations.
	Rios uint64
	// Wios is the number of write IO operations.
	Wios uint64
}

// PressureLine is one pressure stall record. Avg fields are stall percentages
// averaged over 10, 60 and 300 seconds, and Total is the cumulative stall
// time in microseconds.
type PressureLine struct {
	Avg10  float64
	Avg60  float64
	Avg300 float64
	Total  uint64
}

// PressureStats is the pressure stall information of one resource.
type PressureStats struct {
	// Some covers time in which at least one task of the cgroup was stalled.
	Some *PressureLine
	// Full covers time in which all tasks of the cgroup were stalled. It is
	// nil for the CPU resource.
	Full *PressureLine
}

// CgroupPressureStats groups pressure stall information of all resources that
// expose it. Pressure only exists on cgroup v2.
type CgroupPressureStats struct {
	CPU    PressureStats
	IO     PressureStats
	Memory PressureStats
}
