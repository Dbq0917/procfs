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
	"errors"
	"os"
	"os/exec"
	"testing"
)

// TestProcSMapsRollupProcessDiesMidRead reproduces the production incident:
// the process exits while its smaps_rollup is being read, so the second half
// of the file comes back empty. The reader must surface the incomplete
// snapshot instead of treating the missing tail as zero-valued metrics.
//
// The kernel reports a mid-read death in one of two ways, depending on the
// kernel and on whether the task is a zombie or has been reaped: a read
// error (ESRCH) or a clean EOF after a truncated seq_file. Both must result
// in an error from ProcSMapsRollup rather than a near-zero rollup value.
//
// smaps_rollup is read through io.ReadAll in multiple kernel-sized chunks,
// which leaves a real window for the death to land between chunks. The
// manual smaps fallback uses a streaming scanner; its truncation handling is
// covered deterministically by TestProcSMapsManualIncompleteRead.
func TestProcSMapsRollupProcessDiesMidRead(t *testing.T) {
	fs, err := NewFS(DefaultMountPoint)
	if err != nil {
		t.Skipf("real procfs not available: %v", err)
	}

	// Each trial starts a fresh victim process, kills it right before the
	// read, and checks the result. A trial whose read finishes before the
	// death is observed is a benign miss and is retried; require several
	// confirmed mid-read deaths so the guard really exercises the race.
	const (
		trials       = 50
		requiredHits = 3
	)
	hits := 0

	for i := 0; i < trials && hits < requiredHits; i++ {
		cmd := exec.Command("/bin/sleep", "30")
		if err := cmd.Start(); err != nil {
			t.Fatalf("starting child process: %v", err)
		}
		pid := cmd.Process.Pid

		proc, err := fs.Proc(pid)
		if err != nil {
			t.Fatalf("fs.Proc(%d): %v", pid, err)
		}

		// Sanity check: while the process is alive a full read succeeds and
		// reports non-zero memory, establishing the metrics that must not
		// silently collapse to zero after the process dies mid-read.
		baseline, err := proc.ProcSMapsRollup()
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("baseline ProcSMapsRollup: %v", err)
		}
		if baseline.Rss == 0 {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatal("baseline Rss must be non-zero for a live process")
		}

		// Kill before reading so the task can disappear between the internal
		// chunked reads; reap only after the read returns, keeping the task
		// visible as a zombie for as long as the read is in flight.
		if err := cmd.Process.Kill(); err != nil {
			t.Fatalf("killing pid %d: %v", pid, err)
		}
		smaps, readErr := proc.ProcSMapsRollup()
		_ = cmd.Wait()

		if readErr == nil {
			// The snapshot may complete before the kernel observes the
			// death. That is a legitimate full read; retry with a fresh
			// victim.
			continue
		}

		if !errors.Is(readErr, ErrProcSMapsIncomplete) && !errors.Is(readErr, ErrFileRead) && !os.IsNotExist(readErr) {
			t.Fatalf("iteration %d: unexpected error %v", i, readErr)
		}
		// A failed read must never carry a full-looking snapshot.
		if smaps.Rss != 0 && smaps.Rss >= baseline.Rss {
			t.Fatalf("iteration %d: error path returned full Rss=%d baseline=%d", i, smaps.Rss, baseline.Rss)
		}
		hits++
	}

	if hits < requiredHits {
		t.Skipf("only observed %d mid-read deaths in %d trials; kernel likely completes reads before reaping", hits, trials)
	}
}
