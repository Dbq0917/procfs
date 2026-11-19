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
	"math"
	"sort"
	"strings"
)

// AttributedUsage is one cgroup's exclusive usage. Hierarchical counters from
// the kernel have had the usage of the nearest enabled descendants removed,
// so summing Own usage over all rows does not double count a parent and its
// children.
type AttributedUsage struct {
	// Path is the cgroup path relative to the cgroupfs mount point.
	Path string
	// Controllers contains the controllers enabled on this cgroup that were
	// collected in the snapshot.
	Controllers []string
	// CPU is the cgroup's exclusive CPU usage.
	CPU CgroupCPUStats
	// Memory is the cgroup's exclusive memory usage. Limit and Peak remain
	// the direct kernel values because a limit is not additive and a subtree
	// peak cannot be reconstructed by subtraction.
	Memory CgroupMemoryStats
	// IO is the cgroup's exclusive block IO usage per device.
	IO []CgroupIOStats
	// Pids is the cgroup's exclusive process count. Limit remains the direct
	// kernel value.
	Pids CgroupPidsStats
	// Inconsistent is true when a child counter exceeded its parent while
	// subtracting. The subtraction saturates at zero instead of producing a
	// negative value, and the sample should be treated as a gap.
	Inconsistent bool
}

// AttributedUsage returns one exclusive usage row per cgroup that had at
// least one requested controller enabled.
//
// Cgroup v2 cpu.stat, memory.current and io.stat include all descendants.
// Subtracting each node's direct reading from its nearest enabled ancestor
// leaves the ancestor's own usage. The subtraction always uses the kernel's
// direct hierarchical reading, because a parent's reading includes the whole
// child subtree, not only the child's corrected own value.
//
// The work is one pass over the snapshot plus one ancestor lookup per
// enabled controller, not a descendant scan per cgroup.
func (s *Snapshot) AttributedUsage() []AttributedUsage {
	rows := make(map[string]*AttributedUsage, len(s.nodes))
	for _, node := range s.nodes {
		enabled := intersectStrings(node.Controllers, s.controllers)
		if len(enabled) == 0 {
			continue
		}
		rows[node.Path] = &AttributedUsage{
			Path:        node.Path,
			Controllers: enabled,
			CPU:         node.Stats.CPU,
			Memory:      node.Stats.Memory,
			IO:          append([]CgroupIOStats(nil), node.Stats.IO...),
			Pids:        node.Stats.Pids,
		}
	}

	ordered := make([]*SnapshotNode, 0, len(rows))
	for _, node := range s.nodes {
		if _, ok := rows[node.Path]; ok {
			ordered = append(ordered, node)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		left, right := pathDepth(ordered[i].Path), pathDepth(ordered[j].Path)
		if left != right {
			return left > right
		}
		return ordered[i].Path < ordered[j].Path
	})

	for _, node := range ordered {
		direct := AttributedUsage{
			CPU:    node.Stats.CPU,
			Memory: node.Stats.Memory,
			IO:     node.Stats.IO,
			Pids:   node.Stats.Pids,
		}
		for _, controller := range rows[node.Path].Controllers {
			ancestor := s.nearestEnabledAncestor(node.Path, controller)
			if ancestor == nil {
				continue
			}
			parentRow := rows[ancestor.Path]
			if parentRow == nil {
				continue
			}
			subtractUsage(parentRow, &direct, controller)
		}
	}

	result := make([]AttributedUsage, 0, len(rows))
	for _, node := range s.nodes {
		if row, ok := rows[node.Path]; ok {
			result = append(result, *row)
		}
	}
	return result
}

func (s *Snapshot) nearestEnabledAncestor(cgroupPath, controller string) *SnapshotNode {
	for _, ancestorPath := range AncestorPaths(cgroupPath) {
		ancestor, ok := s.byPath[ancestorPath]
		if ok && ancestor.Enabled(controller) {
			return ancestor
		}
	}
	return nil
}

func subtractUsage(parent, child *AttributedUsage, controller string) {
	switch controller {
	case "cpu":
		parent.CPU.UsageSeconds = subtractFloat(parent.CPU.UsageSeconds, child.CPU.UsageSeconds, parent)
		parent.CPU.UserSeconds = subtractFloat(parent.CPU.UserSeconds, child.CPU.UserSeconds, parent)
		parent.CPU.SystemSeconds = subtractFloat(parent.CPU.SystemSeconds, child.CPU.SystemSeconds, parent)
		parent.CPU.NrPeriods = subtractUint(parent.CPU.NrPeriods, child.CPU.NrPeriods, parent)
		parent.CPU.NrThrottled = subtractUint(parent.CPU.NrThrottled, child.CPU.NrThrottled, parent)
		parent.CPU.ThrottledSeconds = subtractFloat(parent.CPU.ThrottledSeconds, child.CPU.ThrottledSeconds, parent)
	case "memory":
		parent.Memory.Usage = subtractUint(parent.Memory.Usage, child.Memory.Usage, parent)
		parent.Memory.Cache = subtractUint(parent.Memory.Cache, child.Memory.Cache, parent)
		parent.Memory.Rss = subtractUint(parent.Memory.Rss, child.Memory.Rss, parent)
		parent.Memory.Swap = subtractUint(parent.Memory.Swap, child.Memory.Swap, parent)
		parent.Memory.OomEvents = subtractUint(parent.Memory.OomEvents, child.Memory.OomEvents, parent)
		parent.Memory.OomKills = subtractUint(parent.Memory.OomKills, child.Memory.OomKills, parent)
	case "pids":
		parent.Pids.Current = subtractUint(parent.Pids.Current, child.Pids.Current, parent)
	case "io":
		parent.IO = subtractIO(parent.IO, child.IO, parent)
	}
}

func subtractUint(parent, child uint64, row *AttributedUsage) uint64 {
	if child > parent {
		row.Inconsistent = true
		return 0
	}
	return parent - child
}

func subtractFloat(parent, child float64, row *AttributedUsage) float64 {
	if child > parent {
		row.Inconsistent = true
		return 0
	}
	value := parent - child
	if value < 0 || math.IsNaN(value) {
		row.Inconsistent = true
		return 0
	}
	return value
}

func subtractIO(parent, child []CgroupIOStats, row *AttributedUsage) []CgroupIOStats {
	if len(parent) == 0 {
		return nil
	}

	byDevice := make(map[string]CgroupIOStats, len(parent))
	for _, stats := range parent {
		byDevice[stats.Device] = stats
	}
	for _, stats := range child {
		parentStats, ok := byDevice[stats.Device]
		if !ok {
			row.Inconsistent = true
			continue
		}
		parentStats.Rbytes = subtractUint(parentStats.Rbytes, stats.Rbytes, row)
		parentStats.Wbytes = subtractUint(parentStats.Wbytes, stats.Wbytes, row)
		parentStats.Rios = subtractUint(parentStats.Rios, stats.Rios, row)
		parentStats.Wios = subtractUint(parentStats.Wios, stats.Wios, row)
		byDevice[stats.Device] = parentStats
	}

	result := make([]CgroupIOStats, 0, len(byDevice))
	for _, stats := range byDevice {
		result = append(result, stats)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Device < result[j].Device
	})
	return result
}

func pathDepth(cgroupPath string) int {
	if cgroupPath == "." || cgroupPath == "" {
		return 0
	}
	return strings.Count(cgroupPath, "/") + 1
}
