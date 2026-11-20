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

//go:build !windows

package procfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkProcSMapsRollup(b *testing.B) {
	fs, err := NewFS(procTestFixtures)
	if err != nil {
		b.Fatalf("Creating pseudo fs from getProcFixtures failed at fixtures/proc with error: %s", err)
	}

	p, err := fs.Proc(26231)
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		_, _ = p.ProcSMapsRollup()
	}
}

func TestProcSmapsRollup(t *testing.T) {
	p, err := getProcFixtures(t).Proc(26231)
	if err != nil {
		t.Fatal(err)
	}

	s1, err := p.ProcSMapsRollup()
	if err != nil {
		t.Fatal(err)
	}

	s2, err := p.procSMapsRollupManual()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		smaps ProcSMapsRollup
	}{
		{
			name:  "ProcSMapsRollup",
			smaps: s1,
		},
		{
			name:  "procSMapsRollupManual",
			smaps: s2,
		},
	}

	for _, c := range cases {
		for _, test := range []struct {
			name string
			want uint64
			have uint64
		}{
			{name: "Rss", want: 29948 * 1024, have: c.smaps.Rss},
			{name: "Pss", want: 29944 * 1024, have: c.smaps.Pss},
			{name: "SharedClean", want: 4 * 1024, have: c.smaps.SharedClean},
			{name: "SharedDirty", want: 0 * 1024, have: c.smaps.SharedDirty},
			{name: "PrivateClean", want: 15548 * 1024, have: c.smaps.PrivateClean},
			{name: "PrivateDirty", want: 14396 * 1024, have: c.smaps.PrivateDirty},
			{name: "Referenced", want: 24752 * 1024, have: c.smaps.Referenced},
			{name: "Anonymous", want: 20756 * 1024, have: c.smaps.Anonymous},
			{name: "Swap", want: 1940 * 1024, have: c.smaps.Swap},
			{name: "SwapPss", want: 1940 * 1024, have: c.smaps.SwapPss},
		} {
			if test.want != test.have {
				t.Errorf("want %s %s %d, have %d", c.name, test.name, test.want, test.have)
			}
		}
	}
}

// writeProcDir creates a fake /proc/[pid] directory containing the given
// files and returns a Proc backed by that directory.
func writeProcDir(t *testing.T, files map[string]string) Proc {
	t.Helper()

	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "1234")
	if err := os.Mkdir(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(pidDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	fs, err := NewFS(procRoot)
	if err != nil {
		t.Fatal(err)
	}
	p, err := fs.Proc(1234)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const fullSMapsRollup = `00400000-ffffffffff601000 ---p 00000000 00:00 0                          [rollup]
Rss:               29948 kB
Pss:               29944 kB
Shared_Clean:          4 kB
Shared_Dirty:          0 kB
Private_Clean:     15548 kB
Private_Dirty:     14396 kB
Referenced:        24752 kB
Anonymous:         20756 kB
Swap:               1940 kB
SwapPss:            1940 kB
Locked:                0 kB
`

const fullSMaps = `00400000-00cb1000 r-xp 00000000 fd:01 952273                             /bin/app
Size:               8900 kB
Rss:                2952 kB
Pss:                2952 kB
Swap:                  0 kB
Locked:                0 kB
VmFlags: rd ex mr mw me dw sd
00cb1000-016b0000 r--p 008b1000 fd:01 952273                             /bin/app
Size:              10236 kB
Rss:                   0 kB
Pss:                   0 kB
Swap:                  0 kB
Locked:                0 kB
VmFlags: rd mr mw me
`

// TestProcSMapsRollupIncompleteRead makes sure a smaps_rollup snapshot that
// ends before the kernel's trailer is rejected instead of being summed into
// near-zero metrics. This is what the read side sees when the process exits
// while the seq_file is being read in chunks.
func TestProcSMapsRollupIncompleteRead(t *testing.T) {
	complete := writeProcDir(t, map[string]string{"smaps_rollup": fullSMapsRollup})
	if _, err := complete.ProcSMapsRollup(); err != nil {
		t.Fatalf("complete smaps_rollup must parse: %v", err)
	}

	// Cut the snapshot at several points: empty file, header only, and a cut
	// in the middle of the metric lines.
	cutPoints := []int{0, len("00400000-ffffffffff601000 ---p [rollup]\n"), len(fullSMapsRollup) / 2}
	for _, cut := range cutPoints {
		p := writeProcDir(t, map[string]string{"smaps_rollup": fullSMapsRollup[:cut]})
		_, err := p.ProcSMapsRollup()
		if !errors.Is(err, ErrProcSMapsIncomplete) {
			t.Fatalf("cut=%d: want ErrProcSMapsIncomplete, got %v", cut, err)
		}
	}
}

// TestProcSMapsManualIncompleteRead covers the fallback path used when
// smaps_rollup does not exist. A smaps file ending in the middle of a VMA
// block (no VmFlags trailer) must be reported as an incomplete read, both
// when the kernel returns a clean EOF and when it surfaces a scanner error.
func TestProcSMapsManualIncompleteRead(t *testing.T) {
	complete := writeProcDir(t, map[string]string{"smaps": fullSMaps})
	if _, err := complete.procSMapsRollupManual(); err != nil {
		t.Fatalf("complete smaps must parse: %v", err)
	}

	// Truncate inside the second VMA block, after some metric lines but
	// before its VmFlags trailer.
	secondHeader := "00cb1000-016b0000 r--p"
	idx := strings.Index(fullSMaps, secondHeader)
	if idx < 0 {
		t.Fatalf("second VMA header not found in fixture")
	}
	truncated := writeProcDir(t, map[string]string{"smaps": fullSMaps[:idx+len(secondHeader)+20]})
	if _, err := truncated.procSMapsRollupManual(); !errors.Is(err, ErrProcSMapsIncomplete) {
		t.Fatalf("truncated smaps: want ErrProcSMapsIncomplete, got %v", err)
	}

	// Empty file: no block at all, nothing to validate against, stays valid
	// with zeroed metrics, matching the behaviour of an empty smaps.
	empty := writeProcDir(t, map[string]string{"smaps": ""})
	if _, err := empty.procSMapsRollupManual(); err != nil {
		t.Fatalf("empty smaps must not error: %v", err)
	}
}
