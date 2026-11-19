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
	"os"
	"path/filepath"
	"testing"
)

const cgroupTestFixtures = "testdata/fixtures/sys/fs/cgroup"

func TestNewFSDetectsMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mountPath string
		wantMode  Mode
	}{
		{name: "v1", mountPath: cgroupTestFixtures + "/v1", wantMode: ModeV1},
		{name: "v2", mountPath: cgroupTestFixtures + "/v2", wantMode: ModeV2},
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
		})
	}
}

func TestNewFSUnknownMode(t *testing.T) {
	t.Parallel()

	_, err := NewFS(t.TempDir())
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion for an empty mount point, got %v", err)
	}
}

func TestNewFSMissingMountPoint(t *testing.T) {
	t.Parallel()

	_, err := NewFS(t.TempDir() + "/does-not-exist")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want os.ErrNotExist for a missing mount point, got %v", err)
	}
}

func TestCleanCgroupPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{input: "", want: "."},
		{input: "/", want: "."},
		{input: "example", want: "example"},
		{input: "/example", want: "example"},
		{input: "/example/sub/", want: filepath.Join("example", "sub")},
	}

	for _, test := range tests {
		if got := cleanCgroupPath(test.input); got != test.want {
			t.Errorf("cleanCgroupPath(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}
