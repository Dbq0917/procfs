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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/procfs/internal/parsers"
)

// readFile reads a file located relative to the cgroup. Read errors are
// wrapped in [ErrFileRead] so callers can distinguish IO failures from parse
// failures while still matching the original os error with [errors.Is].
func (c Cgroup) readFile(relativePath ...string) ([]byte, error) {
	path := c.root.Path(append([]string{c.path}, relativePath...)...)
	data, err := parsers.ReadFileNoStat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrFileRead, path, err)
	}
	return data, nil
}

// readUint reads a single unsigned integer from a cgroup file.
func (c Cgroup) readUint(relativePath ...string) (uint64, error) {
	data, err := c.readFile(relativePath...)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %s: %w", ErrFileParse, c.root.Path(append([]string{c.path}, relativePath...)...), err)
	}
	return value, nil
}

// readLimit reads a single scalar limit. The string "max" means the limit is
// unset and is reported as [math.MaxUint64], matching both the v1 limitless
// convention and the v2 "max" keyword.
func (c Cgroup) readLimit(relativePath ...string) (uint64, error) {
	data, err := c.readFile(relativePath...)
	if err != nil {
		return 0, err
	}

	trimmed := strings.TrimSpace(string(data))
	if trimmed == "max" {
		return math.MaxUint64, nil
	}

	value, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %s: %w", ErrFileParse, c.root.Path(append([]string{c.path}, relativePath...)...), err)
	}
	return value, nil
}

// keyedLine maps a logical field name to its zero-based column index inside
// one line of a whitespace-separated cgroup file.
type keyedLine struct {
	key    string
	fields map[string]int
}

// newLineScanner returns a line scanner over raw cgroup file contents.
func newLineScanner(data []byte) *bufio.Scanner {
	return bufio.NewScanner(bytes.NewReader(data))
}

// isNotExist reports whether err represents a missing cgroup file. Read errors
// are wrapped with %w in readFile, so the original os error stays matchable.
func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

// parseKeyedLines parses files made of whitespace-separated columns whose
// first column is a key. keyedLines declares, for every line key of interest,
// which columns of that line map to which logical field names. Lines and
// fields that are not declared are ignored so extra kernel counters do not
// break parsing.
//
// The same parser handles both layouts; the difference between for example
// v1 memory.stat and v2 memory.stat is entirely expressed in keyedLines.
func parseKeyedLines(data []byte, keyedLines []keyedLine) (map[string]map[string]uint64, error) {
	specByKey := make(map[string]map[string]int, len(keyedLines))
	for _, spec := range keyedLines {
		specByKey[spec.key] = spec.fields
	}

	result := make(map[string]map[string]uint64, len(keyedLines))
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		columns := strings.Fields(line)
		fields, ok := specByKey[columns[0]]
		if !ok {
			continue
		}

		values := make(map[string]uint64, len(fields))
		for field, index := range fields {
			if index >= len(columns) {
				return nil, fmt.Errorf("%w: line %d: key %q has no column %d", ErrFileParse, lineNo, columns[0], index)
			}
			value, err := strconv.ParseUint(columns[index], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: line %d: %w", ErrFileParse, lineNo, err)
			}
			values[field] = value
		}
		result[columns[0]] = values
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFileParse, err)
	}

	return result, nil
}

// firstUint looks up the value of field under key in a keyed-line result and
// reports whether it was present.
func firstUint(lines map[string]map[string]uint64, key, field string) (uint64, bool) {
	if values, ok := lines[key]; ok {
		if value, ok := values[field]; ok {
			return value, true
		}
	}
	return 0, false
}

// parsePressureFile parses a PSI file such as cpu.pressure. The format is
// shared with /proc/pressure and is v2-only.
func parsePressureFile(data []byte) (PressureStats, error) {
	stats := PressureStats{}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		kind, rest, ok := strings.Cut(line, " ")
		if !ok {
			return PressureStats{}, fmt.Errorf("%w: malformed pressure line %q", ErrFileParse, line)
		}

		record := PressureLine{}
		for _, token := range strings.Fields(rest) {
			name, rawValue, ok := strings.Cut(token, "=")
			if !ok {
				return PressureStats{}, fmt.Errorf("%w: malformed pressure token %q", ErrFileParse, token)
			}

			switch name {
			case "avg10":
				value, err := strconv.ParseFloat(rawValue, 64)
				if err != nil {
					return PressureStats{}, fmt.Errorf("%w: %w", ErrFileParse, err)
				}
				record.Avg10 = value
			case "avg60":
				value, err := strconv.ParseFloat(rawValue, 64)
				if err != nil {
					return PressureStats{}, fmt.Errorf("%w: %w", ErrFileParse, err)
				}
				record.Avg60 = value
			case "avg300":
				value, err := strconv.ParseFloat(rawValue, 64)
				if err != nil {
					return PressureStats{}, fmt.Errorf("%w: %w", ErrFileParse, err)
				}
				record.Avg300 = value
			case "total":
				value, err := strconv.ParseUint(rawValue, 10, 64)
				if err != nil {
					return PressureStats{}, fmt.Errorf("%w: %w", ErrFileParse, err)
				}
				record.Total = value
			}
		}

		switch kind {
		case "some":
			stats.Some = &record
		case "full":
			stats.Full = &record
		}
	}
	if err := scanner.Err(); err != nil {
		return PressureStats{}, fmt.Errorf("%w: %w", ErrFileParse, err)
	}

	return stats, nil
}
