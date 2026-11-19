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
	"path"
	"strings"
)

// ErrInvalidCgroupPath is returned when a cgroup path would escape the
// cgroupfs mount point.
var ErrInvalidCgroupPath = errors.New("invalid cgroup path")

// Path returns the cgroup path relative to the cgroupfs mount point. The root
// cgroup is represented by ".".
func (c Cgroup) Path() string {
	return c.path
}

// Name returns the final path element of the cgroup. The root cgroup is
// represented by ".".
func (c Cgroup) Name() string {
	if c.path == "." {
		return "."
	}
	return path.Base(c.path)
}

// Parent returns the parent of the cgroup. The second return value is false
// for the root cgroup.
//
// Parentage is derived from the cgroup path alone. It does not depend on
// directory iteration order or on any state retained from an earlier scrape.
func (c Cgroup) Parent() (Cgroup, bool) {
	parent, ok := ParentPath(c.path)
	if !ok {
		return Cgroup{}, false
	}
	return Cgroup{mode: c.mode, root: c.root, path: parent}, true
}

// Ancestors returns the cgroup's ancestors ordered from nearest to root. The
// root cgroup is always the last element. The cgroup itself is not included.
func (c Cgroup) Ancestors() []Cgroup {
	paths := AncestorPaths(c.path)
	ancestors := make([]Cgroup, 0, len(paths))
	for _, ancestor := range paths {
		ancestors = append(ancestors, Cgroup{mode: c.mode, root: c.root, path: ancestor})
	}
	return ancestors
}

// ParentPath returns the parent of a normalized cgroup path. It reports false
// for the root cgroup.
//
// The hierarchy is encoded in the path string itself: cgroup v2 paths are
// directory paths relative to the mount point, so no extra filesystem lookup
// is needed to establish parent or child relationships.
func ParentPath(cgroupPath string) (string, bool) {
	normalized, err := normalizeCgroupPath(cgroupPath)
	if err != nil {
		return "", false
	}
	if normalized == "." {
		return ".", false
	}
	return path.Dir(normalized), true
}

// AncestorPaths returns the ancestors of a normalized cgroup path ordered
// from nearest to root. The root path "." is always the last element. The
// path itself is not included.
func AncestorPaths(cgroupPath string) []string {
	normalized, err := normalizeCgroupPath(cgroupPath)
	if err != nil || normalized == "." {
		return nil
	}

	var ancestors []string
	for current := normalized; current != "."; {
		current = path.Dir(current)
		ancestors = append(ancestors, current)
	}
	return ancestors
}

// normalizeCgroupPath turns any accepted spelling of a cgroup path into the
// canonical relative form used by [Cgroup]. The root cgroup is ".".
func normalizeCgroupPath(cgroupPath string) (string, error) {
	trimmed := strings.TrimSpace(cgroupPath)
	if trimmed == "" || trimmed == "/" || trimmed == "." {
		return ".", nil
	}

	trimmed = strings.TrimPrefix(trimmed, "/")
	cleaned := path.Clean(trimmed)
	if cleaned == "." {
		return ".", nil
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("%w: %q escapes the mount point", ErrInvalidCgroupPath, cgroupPath)
	}
	return cleaned, nil
}
