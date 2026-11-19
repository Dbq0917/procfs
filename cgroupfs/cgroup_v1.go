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
	"fmt"
	"math"
	"strconv"
	"strings"
)

// cgroupV1 implements [cgroupLayout] for the legacy per-controller hierarchy.
// Every method only describes which v1 file holds which logical field; the
// parsing itself is shared with [cgroupV2] through the helpers in parse.go.
type cgroupV1 struct {
	Cgroup
}

// nanosecondsPerSecond converts cgroup time units to seconds.
const nanosecondsPerSecond = 1e9

// v1UnlimitedMemory is the documented sentinel value written by v1 memory
// controllers when no limit is configured. It is normalized onto the same
// "unlimited" representation used by v2 ([math.MaxUint64]).
const v1UnlimitedMemory = uint64(9223372036854771712)

// readV1Limit reads a v1 scalar limit and maps the kernel sentinel for an
// unset limit onto [math.MaxUint64] so both layouts share one representation.
func (c cgroupV1) readV1Limit(relativePath ...string) (uint64, error) {
	limit, err := c.readUint(relativePath...)
	if err != nil {
		return 0, err
	}
	if limit == v1UnlimitedMemory {
		return math.MaxUint64, nil
	}
	return limit, nil
}

func (c cgroupV1) readCPUStats() (CgroupCPUStats, error) {
	var stats CgroupCPUStats

	usage, err := c.readUint("cpuacct", "cpuacct.usage")
	if err != nil {
		return CgroupCPUStats{}, err
	}
	stats.UsageSeconds = float64(usage) / nanosecondsPerSecond

	// User/system split requires cpuacct.usage_all style data, which is not
	// available on every kernel. Keep the aggregate usage when it is absent.
	usageData, err := c.readFile("cpuacct", "cpuacct.usage_all")
	switch {
	case err == nil:
		if user, system, ok := parseCpuacctUsageAll(usageData); ok {
			stats.UserSeconds = user
			stats.SystemSeconds = system
		}
	case isNotExist(err):
		// Optional metric: leave UserSeconds and SystemSeconds at zero.
	default:
		return CgroupCPUStats{}, err
	}

	statData, err := c.readFile("cpu", "cpu.stat")
	if err != nil {
		return CgroupCPUStats{}, err
	}
	lines, err := parseKeyedLines(statData, []keyedLine{
		{key: "nr_periods", fields: map[string]int{"value": 1}},
		{key: "nr_throttled", fields: map[string]int{"value": 1}},
		{key: "throttled_time", fields: map[string]int{"value": 1}},
	})
	if err != nil {
		return CgroupCPUStats{}, err
	}
	if value, ok := firstUint(lines, "nr_periods", "value"); ok {
		stats.NrPeriods = value
	}
	if value, ok := firstUint(lines, "nr_throttled", "value"); ok {
		stats.NrThrottled = value
	}
	if value, ok := firstUint(lines, "throttled_time", "value"); ok {
		stats.ThrottledSeconds = float64(value) / nanosecondsPerSecond
	}

	return stats, nil
}

// parseCpuacctUsageAll derives user and system CPU time from
// cpuacct.usage_all, whose columns are "cpu user system" per CPU. Kernels
// without the accounting option only ship cpuacct.usage, so a missing or
// unparsable file makes the caller fall back to the aggregate usage.
func parseCpuacctUsageAll(data []byte) (userSeconds, systemSeconds float64, ok bool) {
	var userNanos, systemNanos uint64

	scanner := newLineScanner(data)
	for scanner.Scan() {
		columns := strings.Fields(scanner.Text())
		if len(columns) != 3 {
			return 0, 0, false
		}
		user, err := strconv.ParseUint(columns[1], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		system, err := strconv.ParseUint(columns[2], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		userNanos += user
		systemNanos += system
	}

	return float64(userNanos) / nanosecondsPerSecond, float64(systemNanos) / nanosecondsPerSecond, true
}

func (c cgroupV1) readMemoryStats() (CgroupMemoryStats, error) {
	var stats CgroupMemoryStats

	limit, err := c.readV1Limit("memory", "memory.limit_in_bytes")
	if err != nil {
		return CgroupMemoryStats{}, err
	}
	stats.Limit = limit

	statData, err := c.readFile("memory", "memory.stat")
	if err != nil {
		return CgroupMemoryStats{}, err
	}
	lines, err := parseKeyedLines(statData, []keyedLine{
		{key: "cache", fields: map[string]int{"value": 1}},
		{key: "rss", fields: map[string]int{"value": 1}},
		{key: "swap", fields: map[string]int{"value": 1}},
		{key: "oom", fields: map[string]int{"value": 1}},
		{key: "oom_kill", fields: map[string]int{"value": 1}},
	})
	if err != nil {
		return CgroupMemoryStats{}, err
	}
	stats.Cache, _ = firstUint(lines, "cache", "value")
	stats.Rss, _ = firstUint(lines, "rss", "value")
	stats.Swap, _ = firstUint(lines, "swap", "value")
	stats.OomEvents, _ = firstUint(lines, "oom", "value")
	stats.OomKills, _ = firstUint(lines, "oom_kill", "value")

	if stats.Usage, err = c.readUint("memory", "memory.usage_in_bytes"); err != nil {
		return CgroupMemoryStats{}, err
	}

	if stats.Peak, err = c.readUint("memory", "memory.max_usage_in_bytes"); err != nil {
		return CgroupMemoryStats{}, err
	}

	return stats, nil
}

func (c cgroupV1) readPidsStats() (CgroupPidsStats, error) {
	current, err := c.readUint("pids", "pids.current")
	if err != nil {
		return CgroupPidsStats{}, err
	}
	limit, err := c.readLimit("pids", "pids.max")
	if err != nil {
		return CgroupPidsStats{}, err
	}
	return CgroupPidsStats{Current: current, Limit: limit}, nil
}

func (c cgroupV1) readIOStats() ([]CgroupIOStats, error) {
	data, err := c.readFile("blkio", "blkio.throttle.io_service_bytes")
	if err != nil {
		return nil, err
	}
	byteStats, err := parseBlkioThrottle(data)
	if err != nil {
		return nil, err
	}

	data, err = c.readFile("blkio", "blkio.throttle.io_serviced")
	if err != nil {
		return nil, err
	}
	ioStats, err := parseBlkioThrottle(data)
	if err != nil {
		return nil, err
	}

	return mergeIOStats(byteStats, ioStats), nil
}

// blkioCounters holds one operation counter per device while parsing a single
// blkio.throttle file.
type blkioCounters struct {
	read  uint64
	write uint64
}

// parseBlkioThrottle parses blkio.throttle.io_* files. Each line has the
// shape "major:minor operation value".
func parseBlkioThrottle(data []byte) (map[string]blkioCounters, error) {
	result := map[string]blkioCounters{}

	scanner := newLineScanner(data)
	for scanner.Scan() {
		columns := strings.Fields(scanner.Text())
		if len(columns) != 3 {
			return nil, fmt.Errorf("%w: malformed blkio line %q", ErrFileParse, scanner.Text())
		}

		device := columns[0]
		value, err := strconv.ParseUint(columns[2], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFileParse, err)
		}

		stats := result[device]
		switch columns[1] {
		case "Read":
			stats.read = value
		case "Write":
			stats.write = value
		}
		result[device] = stats
	}

	return result, scanner.Err()
}

// mergeIOStats combines the byte and operation views of one device into the
// shared [CgroupIOStats] model.
func mergeIOStats(byteStats, ioStats map[string]blkioCounters) []CgroupIOStats {
	devices := make(map[string]struct{}, len(byteStats)+len(ioStats))
	for device := range byteStats {
		devices[device] = struct{}{}
	}
	for device := range ioStats {
		devices[device] = struct{}{}
	}

	merged := make([]CgroupIOStats, 0, len(devices))
	for device := range devices {
		entry := CgroupIOStats{Device: device}
		if stats, ok := byteStats[device]; ok {
			entry.Rbytes = stats.read
			entry.Wbytes = stats.write
		}
		if stats, ok := ioStats[device]; ok {
			entry.Rios = stats.read
			entry.Wios = stats.write
		}
		merged = append(merged, entry)
	}

	return merged
}

func (c cgroupV1) readPressureStats() (CgroupPressureStats, error) {
	return CgroupPressureStats{}, fmt.Errorf("%w: pressure stall information is only available on cgroup v2", ErrUnsupportedVersion)
}
