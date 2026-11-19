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
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
)

// ErrUnsupportedController is returned when a snapshot is requested for a
// controller this package cannot collect.
var ErrUnsupportedController = errors.New("unsupported cgroup controller")

// DefaultSnapshotControllers is the controller set collected when
// [FS.Snapshot] is called without an explicit controller list.
var DefaultSnapshotControllers = []string{"cpu", "memory", "io", "pids"}

// SnapshotNode is one cgroup that existed when the snapshot was taken.
type SnapshotNode struct {
	// Cgroup is a handle to the cgroup's current files.
	Cgroup Cgroup
	// Path is the cgroup path relative to the cgroupfs mount point. The root
	// cgroup is ".".
	Path string
	// Controllers contains the controllers enabled on this cgroup. On cgroup
	// v2 these are the entries from cgroup.controllers accepted by the
	// parent's cgroup.subtree_control.
	Controllers []string
	// SubtreeControllers contains the controllers enabled for children of
	// this cgroup. It is populated on cgroup v2.
	SubtreeControllers []string
	// Stats contains the direct kernel readings for the snapshot's requested
	// controllers. Hierarchical counters still include descendants here.
	Stats CgroupStats
	// Err records non-fatal errors while reading this cgroup. A cgroup that
	// disappeared during collection is omitted from the snapshot instead.
	Err error
}

// Enabled reports whether controller is enabled on the cgroup.
func (n *SnapshotNode) Enabled(controller string) bool {
	return containsString(n.Controllers, controller)
}

// Snapshot is an immutable view of the cgroups and counters that existed
// during one collection pass.
//
// A Snapshot never merges with an earlier Snapshot and the package keeps no
// process-wide cgroup cache. A deleted container therefore has no
// SnapshotNode on the next pass. Callers that emit one time series per node
// should replace their emitted set with the new Snapshot, or use
// [Snapshot.Changes] to delete removed paths explicitly.
type Snapshot struct {
	mode        Mode
	controllers []string
	nodes       []*SnapshotNode
	byPath      map[string]*SnapshotNode
}

// Mode reports the cgroup layout used for the snapshot.
func (s *Snapshot) Mode() Mode {
	return s.mode
}

// Len reports the number of cgroups in the snapshot.
func (s *Snapshot) Len() int {
	return len(s.nodes)
}

// Nodes returns the snapshot's cgroups ordered by path. The returned slice is
// a copy; the nodes themselves are immutable after Snapshot returns.
func (s *Snapshot) Nodes() []*SnapshotNode {
	return append([]*SnapshotNode(nil), s.nodes...)
}

// Paths returns the cgroup paths in the snapshot ordered by path.
func (s *Snapshot) Paths() []string {
	paths := make([]string, 0, len(s.nodes))
	for _, node := range s.nodes {
		paths = append(paths, node.Path)
	}
	return paths
}

// Node returns the cgroup at the given path. The path is normalized before
// lookup, so "", "/" and "." all address the root cgroup.
func (s *Snapshot) Node(cgroupPath string) (*SnapshotNode, bool) {
	normalized, err := normalizeCgroupPath(cgroupPath)
	if err != nil {
		return nil, false
	}
	node, ok := s.byPath[normalized]
	return node, ok
}

// Changes lists paths added and removed between two snapshots. It compares
// paths only; consumers read changed values from the new snapshot.
//
// Passing nil as previous reports every current path as added. Removed paths
// are the stale series a metrics consumer must delete.
func (s *Snapshot) Changes(previous *Snapshot) Changes {
	changes := Changes{}
	if previous == nil {
		changes.Added = s.Paths()
		return changes
	}

	for _, node := range s.nodes {
		if _, ok := previous.byPath[node.Path]; !ok {
			changes.Added = append(changes.Added, node.Path)
		}
	}
	for _, node := range previous.nodes {
		if _, ok := s.byPath[node.Path]; !ok {
			changes.Removed = append(changes.Removed, node.Path)
		}
	}
	return changes
}

// Changes describes cgroup paths that appeared or disappeared between two
// snapshots.
type Changes struct {
	// Added contains paths present only in the newer snapshot.
	Added []string
	// Removed contains paths present only in the older snapshot.
	Removed []string
}

// SnapshotOptions controls a cgroup snapshot.
type SnapshotOptions struct {
	// Controllers lists the controllers to collect. An empty list uses
	// [DefaultSnapshotControllers].
	Controllers []string
	// MaxDepth limits how many path components below the mount point are
	// visited. Zero means no limit. One collects the root and its immediate
	// children but does not descend into container subtrees.
	//
	// Setting MaxDepth is useful when metrics are reported at a stable service
	// level: the collector reads one directory entry per service instead of
	// walking every container below it.
	MaxDepth int
}

// Snapshot collects the currently visible cgroups and their direct kernel
// counters.
//
// With no arguments it collects [DefaultSnapshotControllers]. Requested
// controllers are read only where they are enabled. Each directory is listed
// exactly once and the parent of every cgroup is found by looking up its path
// prefix in a map, so hierarchy construction does not rescan the tree once
// per container.
//
// The returned Snapshot contains only cgroups that still existed when their
// counters were read. A cgroup deleted during collection is skipped, which
// makes rolling replacements converge on the next pass.
func (fs FS) Snapshot(controllers ...string) (*Snapshot, error) {
	return fs.SnapshotWithOptions(SnapshotOptions{Controllers: controllers})
}

// SnapshotDepth is [FS.SnapshotWithOptions] with only a depth limit and
// controller list. A maxDepth of zero means no limit.
func (fs FS) SnapshotDepth(maxDepth int, controllers ...string) (*Snapshot, error) {
	return fs.SnapshotWithOptions(SnapshotOptions{Controllers: controllers, MaxDepth: maxDepth})
}

// SnapshotWithOptions collects a snapshot with explicit depth and controller
// limits.
func (fs FS) SnapshotWithOptions(options SnapshotOptions) (*Snapshot, error) {
	if options.MaxDepth < 0 {
		return nil, fmt.Errorf("cgroup snapshot max depth must not be negative: %d", options.MaxDepth)
	}
	requested, err := normalizeControllers(options.Controllers)
	if err != nil {
		return nil, err
	}

	switch fs.mode {
	case ModeV2:
		return fs.snapshotV2(requested, options.MaxDepth)
	case ModeV1:
		return fs.snapshotV1(requested, options.MaxDepth)
	default:
		return nil, fmt.Errorf("%w: cannot take a cgroup snapshot in mode %q", ErrUnsupportedVersion, fs.mode)
	}
}

func (fs FS) snapshotV2(requested []string, maxDepth int) (*Snapshot, error) {
	requestedSet := stringSet(requested)
	var nodes []*SnapshotNode

	var walk func(string) error
	walk = func(relative string) error {
		cgroup := fs.Cgroup(relative)
		available, err := cgroup.readControllerList("cgroup.controllers")
		if err != nil && !isNotExist(err) {
			return err
		}
		subtree, err := cgroup.readControllerList("cgroup.subtree_control")
		if err != nil && !isNotExist(err) {
			return err
		}

		node := &SnapshotNode{
			Cgroup:             cgroup,
			Path:               cgroup.Path(),
			Controllers:        available,
			SubtreeControllers: subtree,
		}
		nodes = append(nodes, node)

		if maxDepth > 0 && pathDepth(cgroup.Path()) >= maxDepth {
			return nil
		}
		entries, err := os.ReadDir(cgroup.root.Path(cgroup.Path()))
		if err != nil {
			if isNotExist(err) {
				// The cgroup was removed after its metadata was read.
				nodes = nodes[:len(nodes)-1]
				return nil
			}
			return fmt.Errorf("%w: read cgroup directory %q: %w", ErrFileRead, cgroup.Path(), err)
		}
		for _, entry := range entries {
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			child := path.Join(relative, entry.Name())
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}

	if err := walk("."); err != nil {
		return nil, err
	}

	snapshot := newSnapshot(ModeV2, requested, nodes)
	for _, node := range snapshot.nodes {
		if node.Path == "." {
			continue
		}
		parent, ok := snapshot.byPath[parentPath(node.Path)]
		if !ok {
			// A path without a parent cannot be placed in the tree. This is
			// normally only possible for hand-built snapshots.
			node.Controllers = nil
			continue
		}
		node.Controllers = intersectStrings(node.Controllers, parent.SubtreeControllers)
	}

	collectSnapshotStats(snapshot, requestedSet)
	snapshot.removeVanished()
	return snapshot, nil
}

func (fs FS) snapshotV1(requested []string, maxDepth int) (*Snapshot, error) {
	requestedSet := stringSet(requested)
	var nodes []*SnapshotNode

	var walk func(string) error
	walk = func(relative string) error {
		cgroup := fs.Cgroup(relative)
		node := &SnapshotNode{
			Cgroup:      cgroup,
			Path:        cgroup.Path(),
			Controllers: append([]string(nil), requested...),
		}
		nodes = append(nodes, node)

		if maxDepth > 0 && pathDepth(cgroup.Path()) >= maxDepth {
			return nil
		}
		entries, err := os.ReadDir(cgroup.root.Path(cgroup.Path()))
		if err != nil {
			if isNotExist(err) {
				nodes = nodes[:len(nodes)-1]
				return nil
			}
			return fmt.Errorf("%w: read cgroup directory %q: %w", ErrFileRead, cgroup.Path(), err)
		}
		for _, entry := range entries {
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			if isV1ControllerDir(entry.Name()) {
				continue
			}
			child := path.Join(relative, entry.Name())
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}

	if err := walk("."); err != nil {
		return nil, err
	}

	snapshot := newSnapshot(ModeV1, requested, nodes)
	collectSnapshotStats(snapshot, requestedSet)
	snapshot.removeVanished()
	return snapshot, nil
}

func newSnapshot(mode Mode, controllers []string, nodes []*SnapshotNode) *Snapshot {
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].Path < nodes[j].Path
	})

	byPath := make(map[string]*SnapshotNode, len(nodes))
	for _, node := range nodes {
		byPath[node.Path] = node
	}
	return &Snapshot{
		mode:        mode,
		controllers: append([]string(nil), controllers...),
		nodes:       nodes,
		byPath:      byPath,
	}
}

func collectSnapshotStats(snapshot *Snapshot, requested map[string]struct{}) {
	for _, node := range snapshot.nodes {
		var errs []error
		if _, ok := requested["cpu"]; ok && node.Enabled("cpu") {
			if stats, err := node.Cgroup.CPUStats(); err == nil {
				node.Stats.CPU = stats
			} else if !isNotExist(err) {
				errs = append(errs, err)
			}
		}
		if _, ok := requested["memory"]; ok && node.Enabled("memory") {
			if stats, err := node.Cgroup.MemoryStats(); err == nil {
				node.Stats.Memory = stats
			} else if !isNotExist(err) {
				errs = append(errs, err)
			}
		}
		if _, ok := requested["pids"]; ok && node.Enabled("pids") {
			if stats, err := node.Cgroup.PidsStats(); err == nil {
				node.Stats.Pids = stats
			} else if !isNotExist(err) {
				errs = append(errs, err)
			}
		}
		if _, ok := requested["io"]; ok && node.Enabled("io") {
			if stats, err := node.Cgroup.IOStats(); err == nil {
				node.Stats.IO = stats
			} else if !isNotExist(err) {
				errs = append(errs, err)
			}
		}
		if _, ok := requested["pressure"]; ok && snapshot.mode == ModeV2 {
			if stats, err := node.Cgroup.PressureStats(); err == nil {
				node.Stats.Pressure = stats
			} else if !isNotExist(err) {
				errs = append(errs, err)
			}
		}
		node.Err = errors.Join(errs...)
	}
}

func (s *Snapshot) removeVanished() {
	kept := s.nodes[:0]
	for _, node := range s.nodes {
		if _, err := os.Stat(node.Cgroup.root.Path(node.Path)); err != nil && isNotExist(err) {
			delete(s.byPath, node.Path)
			continue
		}
		kept = append(kept, node)
	}
	s.nodes = kept
}

func (c Cgroup) readControllerList(name string) ([]string, error) {
	data, err := c.readFile(name)
	if err != nil {
		return nil, err
	}
	controllers := strings.Fields(string(data))
	sort.Strings(controllers)
	return uniqueStrings(controllers), nil
}

func normalizeControllers(controllers []string) ([]string, error) {
	if len(controllers) == 0 {
		return append([]string(nil), DefaultSnapshotControllers...), nil
	}

	normalized := make([]string, 0, len(controllers))
	for _, controller := range controllers {
		controller = strings.ToLower(strings.TrimSpace(controller))
		switch controller {
		case "cpu", "memory", "io", "pids", "pressure":
			normalized = append(normalized, controller)
		default:
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedController, controller)
		}
	}
	sort.Strings(normalized)
	return uniqueStrings(normalized), nil
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func uniqueStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func intersectStrings(left, right []string) []string {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}
	rightSet := stringSet(right)
	intersection := make([]string, 0, len(left))
	for _, value := range left {
		if _, ok := rightSet[value]; ok {
			intersection = append(intersection, value)
		}
	}
	sort.Strings(intersection)
	return uniqueStrings(intersection)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// parentPath is the path form used for map lookups. ParentPath accepts the
// same normalized input and reports false only for the root.
func parentPath(cgroupPath string) string {
	parent, _ := ParentPath(cgroupPath)
	return parent
}

func isV1ControllerDir(name string) bool {
	switch name {
	case "blkio", "cpu", "cpuacct", "cpuset", "devices", "freezer", "hugetlb",
		"memory", "misc", "net_cls", "net_prio", "perf_event", "pids", "rdma":
		return true
	default:
		return false
	}
}
