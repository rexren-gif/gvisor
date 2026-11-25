// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package control

import (
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/ktime"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

func init() {
	log.SetLevel(log.Debug)
}

func TestPercentCPU(t *testing.T) {
	testCases := []struct {
		stats     usage.CPUStats
		startTime ktime.Time
		now       ktime.Time
		expected  int32
	}{
		{
			// Verify that 100% use is capped at 99.
			stats:     usage.CPUStats{UserTime: 1e9, SysTime: 1e9},
			startTime: ktime.FromNanoseconds(7e9),
			now:       ktime.FromNanoseconds(9e9),
			expected:  99,
		},
		{
			// Verify that if usage > lifetime, we get at most 99%
			// usage.
			stats:     usage.CPUStats{UserTime: 2e9, SysTime: 2e9},
			startTime: ktime.FromNanoseconds(7e9),
			now:       ktime.FromNanoseconds(9e9),
			expected:  99,
		},
		{
			// Verify that 50% usage is reported correctly.
			stats:     usage.CPUStats{UserTime: 1e9, SysTime: 1e9},
			startTime: ktime.FromNanoseconds(12e9),
			now:       ktime.FromNanoseconds(16e9),
			expected:  50,
		},
		{
			// Verify that 0% usage is reported correctly.
			stats:     usage.CPUStats{UserTime: 0, SysTime: 0},
			startTime: ktime.FromNanoseconds(12e9),
			now:       ktime.FromNanoseconds(14e9),
			expected:  0,
		},
	}

	for _, tc := range testCases {
		if pcpu := percentCPU(tc.stats, tc.startTime, tc.now); pcpu != tc.expected {
			t.Errorf("percentCPU(%v, %v, %v): got %d, want %d", tc.stats, tc.startTime, tc.now, pcpu, tc.expected)
		}
	}
}

// allowFilter returns a seccomp filter of n instructions that allows every
// system call.
func allowFilter(n int) []byte {
	insns := make([]bpf.Instruction, n)
	for i := range insns {
		insns[i] = bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW))
	}
	return bpf.ToBytecode(insns)
}

func TestCompileSeccompFilters(t *testing.T) {
	for _, tc := range []struct {
		name        string
		programs    [][]byte
		errContains string
	}{
		{name: "None"},
		{name: "One", programs: [][]byte{allowFilter(1)}},
		{name: "MaxInstructions", programs: [][]byte{allowFilter(bpf.MaxInstructions), allowFilter(1)}},
		{
			// 7 programs of 4096 instructions, plus 4 for each program
			// beyond the first, fit in 32768 instructions.
			name:     "MaxCombinedLength",
			programs: [][]byte{allowFilter(4096), allowFilter(4096), allowFilter(4096), allowFilter(4096), allowFilter(4096), allowFilter(4096), allowFilter(4096)},
		},
		{
			// The optimizer folds each program to 1 instruction, but the
			// limit applies to the programs as given.
			name:        "CombinedLengthTooLarge",
			programs:    [][]byte{allowFilter(4096), allowFilter(4096), allowFilter(4096), allowFilter(4096), allowFilter(4096), allowFilter(4096), allowFilter(4096), allowFilter(4096)},
			errContains: "out of memory",
		},
		{name: "Empty", programs: [][]byte{allowFilter(1), {}}, errContains: "seccomp filter 1: size is 0 bytes"},
		{name: "NotMultipleOfInstructionSize", programs: [][]byte{{1, 2, 3}}, errContains: "seccomp filter 0: size is 3 bytes"},
		{name: "TooManyInstructions", programs: [][]byte{allowFilter(bpf.MaxInstructions + 1)}, errContains: "size is 32776 bytes"},
		{
			name:        "NoReturn",
			programs:    [][]byte{bpf.ToBytecode([]bpf.Instruction{bpf.Stmt(bpf.Ld|bpf.W|bpf.Abs, 0)})},
			errContains: "invalid BPF program",
		},
		{
			name:        "BadOpcode",
			programs:    [][]byte{bpf.ToBytecode([]bpf.Instruction{bpf.RawInstruction(0xffff, 0, 0, 0)})},
			errContains: "invalid BPF program",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filters, err := compileSeccompFilters(tc.programs)
			if tc.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("compileSeccompFilters() = %v, want error containing %q", err, tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("compileSeccompFilters() failed: %v", err)
			}
			if len(filters) != len(tc.programs) {
				t.Fatalf("compileSeccompFilters() returned %d filters, want %d", len(filters), len(tc.programs))
			}
			for i, f := range filters {
				if got, want := f.ProgramLength(), len(tc.programs[i])/8; got < 1 || got > want {
					t.Errorf("filter %d has %d instructions, want 1 to %d", i, got, want)
				}
			}
		})
	}
}
