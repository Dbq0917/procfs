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
	"reflect"
	"testing"
)

func TestParseKeyedLines(t *testing.T) {
	t.Parallel()

	data := []byte("cache 4096\nrss 8192\nunknown 1 2\n")
	got, err := parseKeyedLines(data, []keyedLine{
		{key: "cache", fields: map[string]int{"value": 1}},
		{key: "rss", fields: map[string]int{"value": 1}},
	})
	if err != nil {
		t.Fatalf("parseKeyedLines returned error: %v", err)
	}

	if got["cache"]["value"] != 4096 {
		t.Errorf("cache = %d, want 4096", got["cache"]["value"])
	}
	if got["rss"]["value"] != 8192 {
		t.Errorf("rss = %d, want 8192", got["rss"]["value"])
	}
	if _, ok := got["unknown"]; ok {
		t.Error("undeclared keys must be ignored")
	}
}

func TestParseKeyedLinesMalformed(t *testing.T) {
	t.Parallel()

	data := []byte("cache not-a-number\n")
	_, err := parseKeyedLines(data, []keyedLine{
		{key: "cache", fields: map[string]int{"value": 1}},
	})
	if !errors.Is(err, ErrFileParse) {
		t.Fatalf("want ErrFileParse for malformed input, got %v", err)
	}
}

func TestParseIOStat(t *testing.T) {
	t.Parallel()

	data := []byte("8:0 rbytes=4096 wbytes=8192 rios=4 wios=2 dbytes=0 dios=0\n8:16 rbytes=1024 rios=1\n")
	got, err := parseIOStat(data)
	if err != nil {
		t.Fatalf("parseIOStat returned error: %v", err)
	}

	want := []CgroupIOStats{
		{Device: "8:0", Rbytes: 4096, Wbytes: 8192, Rios: 4, Wios: 2},
		{Device: "8:16", Rbytes: 1024, Rios: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseIOStat = %+v, want %+v", got, want)
	}
}

func TestParsePressureFile(t *testing.T) {
	t.Parallel()

	data := []byte("some avg10=1.10 avg60=2.20 avg300=3.30 total=400000\nfull avg10=0.40 avg60=0.50 avg300=0.60 total=80000\n")
	got, err := parsePressureFile(data)
	if err != nil {
		t.Fatalf("parsePressureFile returned error: %v", err)
	}

	if got.Some == nil || got.Some.Total != 400000 || got.Some.Avg10 != 1.10 {
		t.Errorf("unexpected some line: %+v", got.Some)
	}
	if got.Full == nil || got.Full.Total != 80000 || got.Full.Avg60 != 0.50 {
		t.Errorf("unexpected full line: %+v", got.Full)
	}
}

func TestParsePressureFileMalformed(t *testing.T) {
	t.Parallel()

	if _, err := parsePressureFile([]byte("some avg10=oops\n")); !errors.Is(err, ErrFileParse) {
		t.Fatalf("want ErrFileParse for malformed pressure input, got %v", err)
	}
}

func TestParseBlkioThrottle(t *testing.T) {
	t.Parallel()

	data := []byte("8:0 Read 4096\n8:0 Write 8192\n8:16 Read 1024\n")
	got, err := parseBlkioThrottle(data)
	if err != nil {
		t.Fatalf("parseBlkioThrottle returned error: %v", err)
	}

	if got["8:0"].read != 4096 || got["8:0"].write != 8192 {
		t.Errorf("unexpected 8:0 counters: %+v", got["8:0"])
	}
	if got["8:16"].read != 1024 {
		t.Errorf("unexpected 8:16 counters: %+v", got["8:16"])
	}
}

func TestParseCpuacctUsageAll(t *testing.T) {
	t.Parallel()

	user, system, ok := parseCpuacctUsageAll([]byte("0 50000000000 55000000000\n1 10000000000 20000000000\n"))
	if !ok {
		t.Fatal("valid cpuacct.usage_all must parse")
	}
	if user != 60 || system != 75 {
		t.Errorf("user=%v system=%v, want 60 and 75 seconds", user, system)
	}

	if _, _, ok := parseCpuacctUsageAll([]byte("garbage\n")); ok {
		t.Error("malformed cpuacct.usage_all must report ok=false")
	}
}
