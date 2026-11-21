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

package procfs

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	fsi "github.com/prometheus/procfs/internal/fs"
)

// Provide access to /proc/PID/task/TID files, for thread specific values. Since
// such files have the same structure as /proc/PID/ ones, the data structures
// and the parsers for the latter may be reused.

// AllThreads returns a list of all currently available threads under /proc/PID.
func AllThreads(pid int) (Procs, error) {
	fs, err := NewFS(DefaultMountPoint)
	if err != nil {
		return Procs{}, err
	}
	return fs.AllThreads(pid)
}

// AllThreads returns a list of all currently available threads for PID.
func (fs FS) AllThreads(pid int) (Procs, error) {
	taskPath := fs.proc.Path(strconv.Itoa(pid), "task")
	d, err := os.Open(taskPath)
	if err != nil {
		return Procs{}, err
	}
	defer d.Close()

	names, err := d.Readdirnames(-1)
	if err != nil {
		return Procs{}, fmt.Errorf("%w: could not read %q: %w", ErrFileRead, d.Name(), err)
	}

	t := Procs{}
	for _, n := range names {
		tid, err := strconv.ParseInt(n, 10, 64)
		if err != nil {
			continue
		}

		t = append(t, Proc{PID: int(tid), fs: FS{fsi.FS(taskPath), fs.isReal}})
	}

	return t, nil
}

// ThreadCount returns the number of threads currently existing for PID,
// counted as the number of entries in /proc/PID/task.
func ThreadCount(pid int) (int, error) {
	fs, err := NewFS(DefaultMountPoint)
	if err != nil {
		return 0, err
	}
	return fs.ThreadCount(pid)
}

// ThreadCount returns the number of threads currently existing for PID.
//
// The count is the number of entries in the /proc/PID/task directory at call
// time, i.e. the threads that actually exist. It differs from
// ProcStat.NumThreads, which reports the num_threads field of /proc/PID/stat:
// the two are read from different kernel data and are not refreshed
// atomically, so they may briefly disagree while threads are created or
// destroyed.
func (fs FS) ThreadCount(pid int) (int, error) {
	taskPath := fs.proc.Path(strconv.Itoa(pid), "task")
	d, err := os.Open(taskPath)
	if err != nil {
		return 0, err
	}
	defer d.Close()

	names, err := d.Readdirnames(-1)
	if err != nil {
		return 0, fmt.Errorf("%w: could not read %q: %w", ErrFileRead, d.Name(), err)
	}

	count := 0
	for _, n := range names {
		if _, err := strconv.ParseInt(n, 10, 64); err == nil {
			count++
		}
	}

	return count, nil
}

// ThreadCounter caches per-process thread counts so that frequent
// collections don't have to scan /proc/PID/task every time.
//
// The reported count for a PID is the number of entries in its
// /proc/PID/task directory at the moment of the last refresh, i.e. the
// threads that actually existed at that moment. The directory is re-scanned
// at most once per refresh interval; between refreshes the last known value
// is returned, so a count may lag reality by up to one interval. Failed
// scans are not cached. An interval <= 0 disables caching and every call
// re-scans the directory.
type ThreadCounter struct {
	fs       FS
	interval time.Duration
	now      func() time.Time

	mu      sync.Mutex
	entries map[int]threadCountEntry
}

type threadCountEntry struct {
	count     int
	refreshed time.Time
}

// NewThreadCounter returns a ThreadCounter that refreshes the thread count
// of a process at most once per refreshInterval.
func NewThreadCounter(fs FS, refreshInterval time.Duration) *ThreadCounter {
	return &ThreadCounter{
		fs:       fs,
		interval: refreshInterval,
		now:      time.Now,
		entries:  map[int]threadCountEntry{},
	}
}

// Count returns the number of threads of the process pid, as defined by
// FS.ThreadCount, refreshing the cached value if the previous refresh is
// older than the configured interval.
func (c *ThreadCounter) Count(pid int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[pid]; ok && c.now().Sub(e.refreshed) < c.interval {
		return e.count, nil
	}

	count, err := c.fs.ThreadCount(pid)
	if err != nil {
		return 0, err
	}
	c.entries[pid] = threadCountEntry{count: count, refreshed: c.now()}

	return count, nil
}

// Thread returns a process for a given PID, TID.
func (fs FS) Thread(pid, tid int) (Proc, error) {
	taskPath := fs.proc.Path(strconv.Itoa(pid), "task")
	if _, err := os.Stat(taskPath); err != nil {
		return Proc{}, err
	}
	return Proc{PID: tid, fs: FS{fsi.FS(taskPath), fs.isReal}}, nil
}

// Thread returns a process for a given TID of Proc.
func (proc Proc) Thread(tid int) (Proc, error) {
	tfs := FS{fsi.FS(proc.path("task")), proc.fs.isReal}
	if _, err := os.Stat(tfs.proc.Path(strconv.Itoa(tid))); err != nil {
		return Proc{}, err
	}
	return Proc{PID: tid, fs: tfs}, nil
}
