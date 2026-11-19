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
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParentAndAncestorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path      string
		parent    string
		hasParent bool
		ancestors []string
	}{
		{path: ".", parent: ".", hasParent: false},
		{path: "/", parent: ".", hasParent: false},
		{path: "service", parent: ".", hasParent: true, ancestors: []string{"."}},
		{path: "/service/pod/container", parent: "service/pod", hasParent: true, ancestors: []string{"service/pod", "service", "."}},
		{path: "service/../service/pod", parent: "service", hasParent: true, ancestors: []string{"service", "."}},
	}

	for _, test := range tests {
		parent, ok := ParentPath(test.path)
		if parent != test.parent || ok != test.hasParent {
			t.Errorf("ParentPath(%q) = (%q, %v), want (%q, %v)", test.path, parent, ok, test.parent, test.hasParent)
		}
		if got := AncestorPaths(test.path); !reflect.DeepEqual(got, test.ancestors) {
			t.Errorf("AncestorPaths(%q) = %#v, want %#v", test.path, got, test.ancestors)
		}
	}

	if _, err := normalizeCgroupPath("../../etc"); err == nil {
		t.Fatal("normalizeCgroupPath must reject a path outside the mount")
	}
}

func TestSnapshotConvergesAfterContainerReplacement(t *testing.T) {
	t.Parallel()

	root := newV2Fixture(t)
	writeCgroup(t, root, "service/old-container", allV2ControllerFiles("900000", "9000", "900"))

	fs, err := NewFS(root)
	if err != nil {
		t.Fatalf("NewFS returned error: %v", err)
	}

	before, err := fs.Snapshot("cpu", "memory", "io")
	if err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}
	if _, ok := before.Node("service/old-container"); !ok {
		t.Fatalf("old container missing from first snapshot: %v", before.Paths())
	}

	if err := os.RemoveAll(filepath.Join(root, "service", "old-container")); err != nil {
		t.Fatalf("remove old container: %v", err)
	}
	writeCgroup(t, root, "service/new-container", allV2ControllerFiles("700000", "7000", "700"))

	after, err := fs.Snapshot("cpu", "memory", "io")
	if err != nil {
		t.Fatalf("second Snapshot returned error: %v", err)
	}
	if _, ok := after.Node("service/old-container"); ok {
		t.Fatalf("deleted container remained in snapshot: %v", after.Paths())
	}
	if _, ok := after.Node("service/new-container"); !ok {
		t.Fatalf("replacement container missing from snapshot: %v", after.Paths())
	}

	changes := after.Changes(before)
	if !reflect.DeepEqual(changes.Removed, []string{"service/old-container"}) {
		t.Errorf("removed paths = %#v, want old container", changes.Removed)
	}
	if !reflect.DeepEqual(changes.Added, []string{"service/new-container"}) {
		t.Errorf("added paths = %#v, want new container", changes.Added)
	}
}

func TestSnapshotHierarchyComesFromPaths(t *testing.T) {
	t.Parallel()

	root := newV2Fixture(t)
	writeCgroup(t, root, "service/pod/container", allV2ControllerFiles("1", "1", "1"))

	fs, err := NewFS(root)
	if err != nil {
		t.Fatalf("NewFS returned error: %v", err)
	}
	snapshot, err := fs.Snapshot("cpu")
	if err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}

	node, ok := snapshot.Node("/service/pod/container")
	if !ok {
		t.Fatalf("container missing from snapshot: %v", snapshot.Paths())
	}
	parent, ok := node.Cgroup.Parent()
	if !ok || parent.Path() != "service/pod" {
		t.Fatalf("parent = %q, %v, want service/pod", parent.Path(), ok)
	}
	if got := node.Cgroup.Ancestors(); len(got) != 3 || got[0].Path() != "service/pod" || got[2].Path() != "." {
		t.Fatalf("unexpected ancestors: %#v", got)
	}
}

func TestSnapshotDepthStopsBeforeContainers(t *testing.T) {
	t.Parallel()

	root := newV2Fixture(t)
	writeCgroup(t, root, "service/container", allV2ControllerFiles("500000", "5000", "500"))

	fs, err := NewFS(root)
	if err != nil {
		t.Fatalf("NewFS returned error: %v", err)
	}

	serviceLevel, err := fs.SnapshotDepth(1, "cpu")
	if err != nil {
		t.Fatalf("SnapshotDepth returned error: %v", err)
	}
	if got, want := serviceLevel.Paths(), []string{".", "service"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("service-level paths = %#v, want %#v", got, want)
	}

	full, err := fs.Snapshot("cpu")
	if err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}
	if _, ok := full.Node("service/container"); !ok {
		t.Fatalf("full snapshot missing container: %v", full.Paths())
	}
}

func TestAttributedUsageSubtractsChildren(t *testing.T) {
	t.Parallel()

	root := newV2Fixture(t)
	writeCgroup(t, root, ".", map[string]string{
		"cgroup.controllers":     "cpu io memory pids\n",
		"cgroup.subtree_control": "cpu io memory pids\n",
		"cpu.stat":               cpuStat("1000000"),
		"memory.current":         "10000\n",
		"memory.max":             "max\n",
		"memory.stat":            "file 1000\nanon 8000\nswap 0\noom 0\noom_kill 0\n",
		"io.stat":                "8:0 rbytes=1000 wbytes=2000 rios=10 wios=20\n",
	})
	writeCgroup(t, root, "apps", allV2ControllerFiles("900000", "9000", "900"))
	writeCgroup(t, root, "apps/a", allV2ControllerFiles("500000", "5000", "500"))
	writeCgroup(t, root, "apps/b", allV2ControllerFiles("300000", "3000", "300"))
	writeCgroup(t, root, "other", allV2ControllerFiles("100000", "1000", "100"))

	fs, err := NewFS(root)
	if err != nil {
		t.Fatalf("NewFS returned error: %v", err)
	}
	snapshot, err := fs.Snapshot("cpu", "memory", "io")
	if err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}

	rows := usageByPath(snapshot.AttributedUsage())
	assertUsage(t, rows, ".", 0, 0, 0)
	assertUsage(t, rows, "apps", 100000, 1000, 100)
	assertUsage(t, rows, "apps/a", 500000, 5000, 500)
	assertUsage(t, rows, "apps/b", 300000, 3000, 300)
	assertUsage(t, rows, "other", 100000, 1000, 100)

	assertUsageSum(t, rows, "cpu.stat usage_usec", 1000000)
	assertUsageSum(t, rows, "memory.current", 10000)
	assertUsageSum(t, rows, "io.stat rbytes", 1000)
}

func TestAttributedUsageSaturatesCounterRegression(t *testing.T) {
	t.Parallel()

	root := newV2Fixture(t)
	writeCgroup(t, root, ".", map[string]string{
		"cgroup.controllers":     "memory\n",
		"cgroup.subtree_control": "memory\n",
		"memory.current":         "10\n",
		"memory.max":             "max\n",
		"memory.stat":            "file 0\nanon 10\nswap 0\noom 0\noom_kill 0\n",
	})
	writeCgroup(t, root, "container", map[string]string{
		"cgroup.controllers": "memory\n",
		"memory.current":     "20\n",
		"memory.max":         "max\n",
		"memory.stat":        "file 0\nanon 20\nswap 0\noom 0\noom_kill 0\n",
	})

	fs, err := NewFS(root)
	if err != nil {
		t.Fatalf("NewFS returned error: %v", err)
	}
	snapshot, err := fs.Snapshot("memory")
	if err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}

	rows := usageByPath(snapshot.AttributedUsage())
	rootRow := rows["."]
	if rootRow.Memory.Usage != 0 {
		t.Errorf("root usage = %d, want saturated zero", rootRow.Memory.Usage)
	}
	if !rootRow.Inconsistent {
		t.Error("root row must be marked inconsistent after child counter regression")
	}
}

func TestSnapshotSkipsDisabledController(t *testing.T) {
	t.Parallel()

	root := newV2Fixture(t)
	writeCgroup(t, root, "container", map[string]string{
		"cgroup.controllers": "cpu\n",
		"cpu.stat":           cpuStat("250000"),
	})
	// The root only delegates cpu. The memory controller is visible in the
	// child's cgroup.controllers but has not been enabled by the parent.
	writeCgroup(t, root, ".", map[string]string{
		"cgroup.controllers":     "cpu memory\n",
		"cgroup.subtree_control": "cpu\n",
		"cpu.stat":               cpuStat("1000000"),
	})

	fs, err := NewFS(root)
	if err != nil {
		t.Fatalf("NewFS returned error: %v", err)
	}
	snapshot, err := fs.Snapshot("memory")
	if err != nil {
		t.Fatalf("Snapshot returned error: %v", err)
	}
	node, ok := snapshot.Node("container")
	if !ok {
		t.Fatal("container missing from snapshot")
	}
	if node.Enabled("memory") {
		t.Fatal("memory must not be enabled when the parent does not delegate it")
	}
}

func newV2Fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeCgroup(t, root, ".", map[string]string{
		"cgroup.controllers":     "cpu io memory pids\n",
		"cgroup.subtree_control": "cpu io memory pids\n",
	})
	writeCgroup(t, root, "service", map[string]string{
		"cgroup.controllers":     "cpu io memory pids\n",
		"cgroup.subtree_control": "cpu io memory pids\n",
	})
	return root
}

func allV2ControllerFiles(cpuUsage, memoryUsage, ioBytes string) map[string]string {
	return map[string]string{
		"cgroup.controllers":     "cpu io memory pids\n",
		"cgroup.subtree_control": "cpu io memory pids\n",
		"cpu.stat":               cpuStat(cpuUsage),
		"memory.current":         memoryUsage + "\n",
		"memory.max":             "max\n",
		"memory.stat":            "file 0\nanon " + memoryUsage + "\nswap 0\noom 0\noom_kill 0\n",
		"io.stat":                "8:0 rbytes=" + ioBytes + " wbytes=" + ioBytes + " rios=1 wios=1\n",
	}
}

func cpuStat(usageUsec string) string {
	return "usage_usec " + usageUsec + "\nuser_usec 0\nsystem_usec 0\nnr_periods 1\nnr_throttled 0\nthrottled_usec 0\n"
}

func writeCgroup(t *testing.T, root, relative string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(root, relative)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create %q: %v", dir, err)
	}
	for name, contents := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatalf("write %q: %v", path, err)
		}
	}
}

func usageByPath(rows []AttributedUsage) map[string]AttributedUsage {
	byPath := make(map[string]AttributedUsage, len(rows))
	for _, row := range rows {
		byPath[row.Path] = row
	}
	return byPath
}

func assertUsage(t *testing.T, rows map[string]AttributedUsage, path string, cpuUsec, memory, ioBytes uint64) {
	t.Helper()
	row, ok := rows[path]
	if !ok {
		t.Fatalf("%s missing from attributed usage", path)
	}
	if got := uint64(row.CPU.UsageSeconds * 1e6); got != cpuUsec {
		t.Errorf("%s cpu usage = %d usec, want %d", path, got, cpuUsec)
	}
	if row.Memory.Usage != memory {
		t.Errorf("%s memory usage = %d, want %d", path, row.Memory.Usage, memory)
	}
	if len(row.IO) != 1 || row.IO[0].Rbytes != ioBytes {
		t.Errorf("%s io usage = %#v, want rbytes %d", path, row.IO, ioBytes)
	}
}

func assertUsageSum(t *testing.T, rows map[string]AttributedUsage, label string, want uint64) {
	t.Helper()
	var got uint64
	for _, row := range rows {
		switch label {
		case "cpu.stat usage_usec":
			got += uint64(row.CPU.UsageSeconds * 1e6)
		case "memory.current":
			got += row.Memory.Usage
		case "io.stat rbytes":
			for _, stats := range row.IO {
				got += stats.Rbytes
			}
		}
	}
	if got != want {
		t.Errorf("%s sum = %d, want %d", label, got, want)
	}
}
