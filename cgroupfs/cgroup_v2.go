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
	"strconv"
	"strings"
)

// cgroupV2 implements [cgroupLayout] for the unified hierarchy. Like
// [cgroupV1] it only describes where each logical metric lives; the actual
// parsing is shared code in parse.go.
type cgroupV2 struct {
	Cgroup
}

// microsecondsPerSecond converts the v2 time units to seconds.
const microsecondsPerSecond = 1e6

func (c cgroupV2) readCPUStats() (CgroupCPUStats, error) {
	statData, err := c.readFile("cpu.stat")
	if err != nil {
		return CgroupCPUStats{}, err
	}
	lines, err := parseKeyedLines(statData, []keyedLine{
		{key: "usage_usec", fields: map[string]int{"value": 1}},
		{key: "user_usec", fields: map[string]int{"value": 1}},
		{key: "system_usec", fields: map[string]int{"value": 1}},
		{key: "nr_periods", fields: map[string]int{"value": 1}},
		{key: "nr_throttled", fields: map[string]int{"value": 1}},
		{key: "throttled_usec", fields: map[string]int{"value": 1}},
	})
	if err != nil {
		return CgroupCPUStats{}, err
	}

	stats := CgroupCPUStats{}
	if value, ok := firstUint(lines, "usage_usec", "value"); ok {
		stats.UsageSeconds = float64(value) / microsecondsPerSecond
	}
	if value, ok := firstUint(lines, "user_usec", "value"); ok {
		stats.UserSeconds = float64(value) / microsecondsPerSecond
	}
	if value, ok := firstUint(lines, "system_usec", "value"); ok {
		stats.SystemSeconds = float64(value) / microsecondsPerSecond
	}
	stats.NrPeriods, _ = firstUint(lines, "nr_periods", "value")
	stats.NrThrottled, _ = firstUint(lines, "nr_throttled", "value")
	if value, ok := firstUint(lines, "throttled_usec", "value"); ok {
		stats.ThrottledSeconds = float64(value) / microsecondsPerSecond
	}

	return stats, nil
}

func (c cgroupV2) readMemoryStats() (CgroupMemoryStats, error) {
	var stats CgroupMemoryStats

	limit, err := c.readLimit("memory.max")
	if err != nil {
		return CgroupMemoryStats{}, err
	}
	stats.Limit = limit

	statData, err := c.readFile("memory.stat")
	if err != nil {
		return CgroupMemoryStats{}, err
	}
	lines, err := parseKeyedLines(statData, []keyedLine{
		{key: "file", fields: map[string]int{"value": 1}},
		{key: "anon", fields: map[string]int{"value": 1}},
		{key: "swap", fields: map[string]int{"value": 1}},
		{key: "oom", fields: map[string]int{"value": 1}},
		{key: "oom_kill", fields: map[string]int{"value": 1}},
	})
	if err != nil {
		return CgroupMemoryStats{}, err
	}
	stats.Cache, _ = firstUint(lines, "file", "value")
	stats.Rss, _ = firstUint(lines, "anon", "value")
	stats.Swap, _ = firstUint(lines, "swap", "value")
	stats.OomEvents, _ = firstUint(lines, "oom", "value")
	stats.OomKills, _ = firstUint(lines, "oom_kill", "value")

	if stats.Usage, err = c.readUint("memory.current"); err != nil {
		return CgroupMemoryStats{}, err
	}

	// memory.peak only exists on kernels >= 5.19. Treat its absence as an
	// optional metric instead of failing the whole memory collection.
	if peak, err := c.readUint("memory.peak"); err == nil {
		stats.Peak = peak
	} else if !isNotExist(err) {
		return CgroupMemoryStats{}, err
	}

	return stats, nil
}

func (c cgroupV2) readPidsStats() (CgroupPidsStats, error) {
	current, err := c.readUint("pids.current")
	if err != nil {
		return CgroupPidsStats{}, err
	}
	limit, err := c.readLimit("pids.max")
	if err != nil {
		return CgroupPidsStats{}, err
	}
	return CgroupPidsStats{Current: current, Limit: limit}, nil
}

func (c cgroupV2) readIOStats() ([]CgroupIOStats, error) {
	data, err := c.readFile("io.stat")
	if err != nil {
		return nil, err
	}
	return parseIOStat(data)
}

// parseIOStat parses the v2 io.stat file. Each line starts with the device
// identifier "major:minor" followed by "key=value" counters:
//
//	8:0 rbytes=1024 wbytes=2048 rios=8 wios=16 dbytes=0 dios=0
func parseIOStat(data []byte) ([]CgroupIOStats, error) {
	var stats []CgroupIOStats

	scanner := newLineScanner(data)
	for scanner.Scan() {
		columns := strings.Fields(scanner.Text())
		if len(columns) < 2 {
			return nil, fmt.Errorf("%w: malformed io.stat line %q", ErrFileParse, scanner.Text())
		}

		entry := CgroupIOStats{Device: columns[0]}
		for _, token := range columns[1:] {
			name, rawValue, ok := strings.Cut(token, "=")
			if !ok {
				return nil, fmt.Errorf("%w: malformed io.stat token %q", ErrFileParse, token)
			}
			value, err := strconv.ParseUint(rawValue, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrFileParse, err)
			}

			switch name {
			case "rbytes":
				entry.Rbytes = value
			case "wbytes":
				entry.Wbytes = value
			case "rios":
				entry.Rios = value
			case "wios":
				entry.Wios = value
			}
		}
		stats = append(stats, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFileParse, err)
	}

	return stats, nil
}

func (c cgroupV2) readPressureStats() (CgroupPressureStats, error) {
	var stats CgroupPressureStats

	cpu, err := c.readPressure("cpu.pressure")
	if err != nil {
		return CgroupPressureStats{}, err
	}
	stats.CPU = cpu

	io, err := c.readPressure("io.pressure")
	if err != nil {
		return CgroupPressureStats{}, err
	}
	stats.IO = io

	memory, err := c.readPressure("memory.pressure")
	if err != nil {
		return CgroupPressureStats{}, err
	}
	stats.Memory = memory

	return stats, nil
}

// readPressure reads one PSI resource file through the shared parser.
func (c cgroupV2) readPressure(relativePath ...string) (PressureStats, error) {
	data, err := c.readFile(relativePath...)
	if err != nil {
		return PressureStats{}, err
	}
	return parsePressureFile(data)
}
