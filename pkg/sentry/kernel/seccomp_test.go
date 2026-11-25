// Copyright 2026 The gVisor Authors.
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

package kernel

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

func TestCheckSyscallFiltersLength(t *testing.T) {
	for _, tc := range []struct {
		name    string
		lengths []int
		wantErr error
	}{
		{name: "None"},
		{name: "One", lengths: []int{maxSyscallFilterInstructions}},
		{name: "OneTooLong", lengths: []int{maxSyscallFilterInstructions + 1}, wantErr: linuxerr.ENOMEM},
		// Each filter beyond the first adds 4 instructions.
		{name: "Two", lengths: []int{maxSyscallFilterInstructions/2 - 2, maxSyscallFilterInstructions/2 - 2}},
		{name: "TwoTooLong", lengths: []int{maxSyscallFilterInstructions/2 - 1, maxSyscallFilterInstructions/2 - 2}, wantErr: linuxerr.ENOMEM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckSyscallFiltersLength(tc.lengths...); err != tc.wantErr {
				t.Errorf("CheckSyscallFiltersLength(%v) = %v, want %v", tc.lengths, err, tc.wantErr)
			}
		})
	}
}

// seccompTestTask returns a task that can hold system call filters.
func seccompTestTask() *Task {
	tg := &ThreadGroup{signalHandlers: &SignalHandlers{}}
	return &Task{tg: tg, image: TaskImage{st: &SyscallTable{AuditNumber: linux.AUDIT_ARCH_X86_64}}}
}

// denySyscallFilter returns a filter that fails system call sysno with errno
// and allows all others.
func denySyscallFilter(t *testing.T, sysno, errno uint32, length int) SyscallFilter {
	t.Helper()
	insns := []bpf.Instruction{
		bpf.Stmt(bpf.Ld|bpf.Abs|bpf.W, 0),
		bpf.Jump(bpf.Jmp|bpf.Jeq|bpf.K, sysno, 0, 1),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ERRNO)|errno),
	}
	for len(insns) < length {
		insns = append(insns, bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW)))
	}
	program, err := bpf.Compile(insns, false)
	if err != nil {
		t.Fatalf("bpf.Compile() failed: %v", err)
	}
	return NewSyscallFilter(program)
}

// TestAppendSyscallFilters checks that adding filters in one call gives the
// same result as adding them one at a time.
func TestAppendSyscallFilters(t *testing.T) {
	filters := []SyscallFilter{
		denySyscallFilter(t, 1, 1, 4),
		denySyscallFilter(t, 2, 2, 4),
		denySyscallFilter(t, 1, 3, 4),
	}
	batch := seccompTestTask()
	if err := batch.AppendSyscallFilter(filters[0], false); err != nil {
		t.Fatalf("AppendSyscallFilter() failed: %v", err)
	}
	if err := batch.AppendSyscallFilters(filters[1:], false); err != nil {
		t.Fatalf("AppendSyscallFilters() failed: %v", err)
	}
	single := seccompTestTask()
	for _, f := range filters {
		if err := single.AppendSyscallFilter(f, false); err != nil {
			t.Fatalf("AppendSyscallFilter() failed: %v", err)
		}
	}
	got, want := batch.seccomp.Load(), single.seccomp.Load()
	if len(got.filters) != len(filters) {
		t.Fatalf("got %d filters, want %d", len(got.filters), len(filters))
	}
	if got.cache != want.cache || got.cacheAuditNumber != want.cacheAuditNumber {
		t.Errorf("cache of AppendSyscallFilters differs from the cache of AppendSyscallFilter")
	}
	// The last filter added decides between equal actions.
	if got.cache[1] != linux.SECCOMP_RET_ERRNO|3 || got.cache[2] != linux.SECCOMP_RET_ERRNO|2 {
		t.Errorf("cache[1] = %#x, cache[2] = %#x, want %#x, %#x", got.cache[1], got.cache[2], linux.SECCOMP_RET_ERRNO|3, linux.SECCOMP_RET_ERRNO|2)
	}

	// Nothing changes if the filters do not fit.
	var tooLong []SyscallFilter
	for range maxSyscallFilterInstructions / bpf.MaxInstructions {
		tooLong = append(tooLong, denySyscallFilter(t, 1, 1, bpf.MaxInstructions))
	}
	if err := batch.AppendSyscallFilters(tooLong, false); err != linuxerr.ENOMEM {
		t.Errorf("AppendSyscallFilters() = %v, want %v", err, linuxerr.ENOMEM)
	}
	if batch.seccomp.Load() != got {
		t.Errorf("AppendSyscallFilters() changed the filters after an error")
	}
	if err := batch.AppendSyscallFilters(nil, false); err != nil || batch.seccomp.Load() != got {
		t.Errorf("AppendSyscallFilters(nil) = %v, or changed the filters", err)
	}
}
