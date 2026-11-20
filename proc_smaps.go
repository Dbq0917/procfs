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
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/procfs/internal/parsers"
)

var (
	// ErrProcSMapsIncomplete is returned when an smaps or smaps_rollup file
	// could not be read in full, typically because the process exited while
	// the file was being read. The kernel may signal this with a read error
	// (e.g. ESRCH) or by ending the seq_file iteration early with a clean EOF.
	// In the latter case the file ends without the trailer the kernel always
	// emits for a complete snapshot, so the missing tail must not be parsed as
	// zero-valued metrics.
	ErrProcSMapsIncomplete = errors.New("incomplete smaps read, the process likely exited while the file was being read")

	// smapsRollupTrailer is the last metric line the kernel emits in
	// /proc/[pid]/smaps_rollup. A complete snapshot always ends with it.
	smapsRollupTrailer = "Locked"

	// smapsBlockTrailerPrefix is the first field of the last line of every
	// VMA block in /proc/[pid]/smaps. A complete block always ends with it.
	smapsBlockTrailerPrefix = "VmFlags"
)

// Match the header line before each mapped zone in `/proc/pid/smaps`.
var procSMapsHeaderLine = regexp.MustCompile(`^[a-f0-9].*$`)

type ProcSMapsRollup struct {
	// Amount of the mapping that is currently resident in RAM.
	Rss uint64
	// Process's proportional share of this mapping.
	Pss uint64
	// Size in bytes of clean shared pages.
	SharedClean uint64
	// Size in bytes of dirty shared pages.
	SharedDirty uint64
	// Size in bytes of clean private pages.
	PrivateClean uint64
	// Size in bytes of dirty private pages.
	PrivateDirty uint64
	// Amount of memory currently marked as referenced or accessed.
	Referenced uint64
	// Amount of memory that does not belong to any file.
	Anonymous uint64
	// Amount would-be-anonymous memory currently on swap.
	Swap uint64
	// Process's proportional memory on swap.
	SwapPss uint64
}

// ProcSMapsRollup reads from /proc/[pid]/smaps_rollup to get summed memory information of the
// process.
//
// If smaps_rollup does not exists (require kernel >= 4.15), the content of /proc/pid/smaps will
// we read and summed.
func (p Proc) ProcSMapsRollup() (ProcSMapsRollup, error) {
	data, err := parsers.ReadFileNoStat(p.path("smaps_rollup"))
	if err != nil && os.IsNotExist(err) {
		return p.procSMapsRollupManual()
	}
	if err != nil {
		return ProcSMapsRollup{}, fmt.Errorf("%w: %w", ErrFileRead, err)
	}

	if err := validateProcSMapsRollupData(data); err != nil {
		return ProcSMapsRollup{}, err
	}

	lines := strings.Split(string(data), "\n")
	smaps := ProcSMapsRollup{}

	// skip first line which don't contains information we need
	lines = lines[1:]
	for _, line := range lines {
		if line == "" {
			continue
		}

		if err := smaps.parseLine(line); err != nil {
			return ProcSMapsRollup{}, err
		}
	}

	return smaps, nil
}

// validateProcSMapsRollupData rejects snapshots that were cut short. The
// kernel emits a fixed trailer ("Locked:") as the last non-empty line of a
// complete smaps_rollup; when the process disappears mid-read the seq_file
// iteration can stop earlier with a clean EOF, leaving no trailer behind.
//
// This only inspects bytes already held in memory: it adds no I/O and does
// not read the file a second time, so the cost of the normal path is
// unchanged.
func validateProcSMapsRollupData(data []byte) error {
	trimmed := strings.TrimRight(string(data), "\n\t ")
	if trimmed == "" {
		return fmt.Errorf("%w: %s", ErrProcSMapsIncomplete, "smaps_rollup is empty")
	}
	lastLine := trimmed
	if idx := strings.LastIndexByte(trimmed, '\n'); idx >= 0 {
		lastLine = trimmed[idx+1:]
	}
	if field, _, ok := strings.Cut(lastLine, ":"); ok && field == smapsRollupTrailer {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrProcSMapsIncomplete, "smaps_rollup is missing its trailer")
}

// Read /proc/pid/smaps and do the roll-up in Go code.
func (p Proc) procSMapsRollupManual() (ProcSMapsRollup, error) {
	file, err := os.Open(p.path("smaps"))
	if err != nil {
		return ProcSMapsRollup{}, err
	}
	defer file.Close()

	smaps := ProcSMapsRollup{}
	scan := bufio.NewScanner(file)
	// Every VMA block in smaps ends with a VmFlags line. While scanning,
	// blockComplete says the last block seen so far has its trailer; a new
	// header starts a block that must end with VmFlags before EOF.
	blockComplete := true

	for scan.Scan() {
		line := scan.Text()
		if line == "" {
			continue
		}

		if procSMapsHeaderLine.MatchString(line) {
			if !blockComplete {
				return ProcSMapsRollup{}, fmt.Errorf("%w: %s", ErrProcSMapsIncomplete, "smaps VMA block is missing its VmFlags trailer")
			}
			blockComplete = false
			continue
		}

		if field, _, ok := strings.Cut(line, ":"); ok && field == smapsBlockTrailerPrefix {
			blockComplete = true
		}

		if err := smaps.parseLine(line); err != nil {
			return ProcSMapsRollup{}, err
		}
	}

	if err := scan.Err(); err != nil {
		return ProcSMapsRollup{}, fmt.Errorf("%w: %w", ErrFileRead, err)
	}
	if !blockComplete {
		return ProcSMapsRollup{}, fmt.Errorf("%w: %s", ErrProcSMapsIncomplete, "smaps ended in the middle of a VMA block")
	}

	return smaps, nil
}

func (s *ProcSMapsRollup) parseLine(line string) error {
	kv := strings.SplitN(line, ":", 2)
	if len(kv) != 2 {
		return errors.New("invalid net/dev line, missing colon")
	}

	k := kv[0]
	if k == "VmFlags" {
		return nil
	}

	v := strings.TrimSpace(kv[1])
	v = strings.TrimSuffix(v, " kB")

	vKBytes, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return err
	}
	vBytes := vKBytes * 1024

	s.addValue(k, vBytes)

	return nil
}

func (s *ProcSMapsRollup) addValue(k string, vUintBytes uint64) {
	switch k {
	case "Rss":
		s.Rss += vUintBytes
	case "Pss":
		s.Pss += vUintBytes
	case "Shared_Clean":
		s.SharedClean += vUintBytes
	case "Shared_Dirty":
		s.SharedDirty += vUintBytes
	case "Private_Clean":
		s.PrivateClean += vUintBytes
	case "Private_Dirty":
		s.PrivateDirty += vUintBytes
	case "Referenced":
		s.Referenced += vUintBytes
	case "Anonymous":
		s.Anonymous += vUintBytes
	case "Swap":
		s.Swap += vUintBytes
	case "SwapPss":
		s.SwapPss += vUintBytes
	}
}
