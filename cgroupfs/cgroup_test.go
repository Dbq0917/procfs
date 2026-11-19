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
	"math"
	"os"
	"reflect"
	"testing"
)

// wantStats is asserted against both layout fixtures. The fixtures carry the
// same logical values expressed in their respective kernel formats, which
// proves the two adapters normalize onto one metric model.
func wantStats() CgroupStats {
	return CgroupStats{
		CPU: CgroupCPUStats{
			UsageSeconds:     105,
			UserSeconds:      50,
			SystemSeconds:    55,
			NrPeriods:        100,
			NrThrottled:      5,
			ThrottledSeconds: 2,
		},
		Memory: CgroupMemoryStats{
			Usage:     16384,
			Peak:      32768,
			Limit:     math.MaxUint64,
			Cache:     4096,
			Rss:       8192,
			Swap:      2048,
			OomEvents: 3,
			OomKills:  2,
		},
		Pids: CgroupPidsStats{
			Current: 7,
			Limit:   math.MaxUint64,
		},
		IO: []CgroupIOStats{
			{Device: "8:0", Rbytes: 4096, Wbytes: 8192, Rios: 4, Wios: 2},
			{Device: "8:16", Rbytes: 1024, Wbytes: 0, Rios: 1, Wios: 0},
		},
	}
}

func TestStatsAcrossLayouts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mountPath   string
		wantMode    Mode
		hasPressure bool
	}{
		{name: "v1", mountPath: cgroupTestFixtures + "/v1", wantMode: ModeV1},
		{name: "v2", mountPath: cgroupTestFixtures + "/v2", wantMode: ModeV2, hasPressure: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fs, err := NewFS(test.mountPath)
			if err != nil {
				t.Fatalf("NewFS returned error: %v", err)
			}
			if fs.Mode() != test.wantMode {
				t.Fatalf("detected mode %q, want %q", fs.Mode(), test.wantMode)
			}

			got, err := fs.Cgroup("example").Stats()
			if err != nil {
				t.Fatalf("Stats returned error: %v", err)
			}

			want := wantStats()
			if test.hasPressure {
				want.Pressure = CgroupPressureStats{
					CPU: PressureStats{
						Some: &PressureLine{Avg10: 1.10, Avg60: 2.20, Avg300: 3.30, Total: 400000},
					},
					IO: PressureStats{
						Some: &PressureLine{Avg10: 4.40, Avg60: 5.50, Avg300: 6.60, Total: 700000},
						Full: &PressureLine{Avg10: 0.40, Avg60: 0.50, Avg300: 0.60, Total: 80000},
					},
					Memory: PressureStats{
						Some: &PressureLine{Avg10: 7.70, Avg60: 8.80, Avg300: 9.90, Total: 1000000},
						Full: &PressureLine{Avg10: 0.70, Avg60: 0.80, Avg300: 0.90, Total: 90000},
					},
				}
			}

			normalizeIO := func(stats CgroupStats) CgroupStats {
				stats.IO = sortedIOStats(stats.IO)
				return stats
			}
			if !reflect.DeepEqual(normalizeIO(want), normalizeIO(got)) {
				t.Errorf("unexpected stats:\nwant: %+v\ngot:  %+v", normalizeIO(want), normalizeIO(got))
			}
		})
	}
}

// sortedIOStats returns IO stats ordered by device so they can be compared
// deterministically; neither cgroup layout guarantees device order.
func sortedIOStats(stats []CgroupIOStats) []CgroupIOStats {
	sorted := append([]CgroupIOStats(nil), stats...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Device < sorted[i].Device {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	return sorted
}

func TestStatsMissingControllerReturnsError(t *testing.T) {
	t.Parallel()

	fs, err := NewFS(cgroupTestFixtures + "/v2")
	if err != nil {
		t.Fatalf("NewFS returned error: %v", err)
	}

	// The root cgroup has no controller files, so collection must surface a
	// not-exist error instead of silently returning zero metrics.
	_, err = fs.Cgroup("/").MemoryStats()
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want os.ErrNotExist for a missing controller file, got %v", err)
	}
}

func TestStatsJoinsPerControllerErrors(t *testing.T) {
	t.Parallel()

	fs, err := NewFS(cgroupTestFixtures + "/v2")
	if err != nil {
		t.Fatalf("NewFS returned error: %v", err)
	}

	_, err = fs.Cgroup("/").Stats()
	if err == nil {
		t.Fatal("Stats must fail when no controller file exists")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want the joined error to match os.ErrNotExist, got %v", err)
	}
}

func TestV1PressureUnsupported(t *testing.T) {
	t.Parallel()

	fs, err := NewFS(cgroupTestFixtures + "/v1")
	if err != nil {
		t.Fatalf("NewFS returned error: %v", err)
	}

	if _, err := fs.Cgroup("example").PressureStats(); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion on v1, got %v", err)
	}
}

func TestV1CPUStatsWithoutUsageAll(t *testing.T) {
	t.Parallel()

	// Build a minimal v1 hierarchy that only exposes the aggregate
	// cpuacct.usage file plus the throttling stats.
	root := t.TempDir()
	for _, dir := range []string{"cpu", "cpuacct"} {
		if err := os.MkdirAll(root+"/"+dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture(t, root+"/cpuacct/cpuacct.usage", "105000000000\n")
	writeFixture(t, root+"/cpu/cpu.stat", "nr_periods 100\nnr_throttled 5\nthrottled_time 2000000000\n")

	fs, err := NewFS(root)
	if err != nil {
		t.Fatalf("NewFS returned error: %v", err)
	}

	stats, err := fs.Cgroup("/").CPUStats()
	if err != nil {
		t.Fatalf("CPUStats must tolerate a missing cpuacct.usage_all: %v", err)
	}
	if stats.UsageSeconds != 105 || stats.UserSeconds != 0 || stats.SystemSeconds != 0 {
		t.Errorf("unexpected CPU stats: %+v", stats)
	}
	if stats.NrPeriods != 100 || stats.NrThrottled != 5 || stats.ThrottledSeconds != 2 {
		t.Errorf("unexpected throttling stats: %+v", stats)
	}
}

// writeFixture writes a cgroup fixture file with the given contents.
func writeFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}
