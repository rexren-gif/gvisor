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

package bwrap

import (
	"bytes"
	"fmt"

	"golang.org/x/sys/unix"
)

// ptraceInjectMkdir makes the tracee pid, which must be in a ptrace stop
// inside a system call, run mkdirat(AT_FDCWD, path, 0755). It returns the
// result of the system call and restores the registers of the tracee.
func ptraceInjectMkdir(pid int, path string) (int64, error) {
	var orig unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &orig); err != nil {
		return 0, fmt.Errorf("getregs: %w", err)
	}
	// Find the syscall instruction that the tracee stopped in.
	syscallInsn := []byte{0x0f, 0x05}
	insn := make([]byte, 2)
	rip := orig.Rip
	if _, err := unix.PtracePeekText(pid, uintptr(rip-2), insn); err == nil && bytes.Equal(insn, syscallInsn) {
		rip -= 2
	} else if _, err := unix.PtracePeekText(pid, uintptr(rip), insn); err != nil || !bytes.Equal(insn, syscallInsn) {
		return 0, fmt.Errorf("no syscall instruction at %#x", orig.Rip)
	}
	// Put path below the red zone of the stack of the tracee.
	addr := (orig.Rsp - 4096) &^ 7
	data := append([]byte(path), 0)
	for len(data)%8 != 0 {
		data = append(data, 0)
	}
	if _, err := unix.PtracePokeData(pid, uintptr(addr), data); err != nil {
		return 0, fmt.Errorf("pokedata: %w", err)
	}
	regs := orig
	atFDCWD := int64(unix.AT_FDCWD)
	regs.Rip = rip
	regs.Rax = unix.SYS_MKDIRAT
	regs.Orig_rax = ^uint64(0)
	regs.Rdi = uint64(atFDCWD)
	regs.Rsi = addr
	regs.Rdx = 0755
	if err := unix.PtraceSetRegs(pid, &regs); err != nil {
		return 0, fmt.Errorf("setregs: %w", err)
	}
	// Run to the system call entry, and then to its exit.
	for i := 0; i < 2; i++ {
		if err := unix.PtraceSyscall(pid, 0); err != nil {
			return 0, fmt.Errorf("syscall: %w", err)
		}
		var ws unix.WaitStatus
		if _, err := unix.Wait4(pid, &ws, unix.WALL, nil); err != nil {
			return 0, fmt.Errorf("wait: %w", err)
		}
	}
	var after unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &after); err != nil {
		return 0, fmt.Errorf("getregs: %w", err)
	}
	if err := unix.PtraceSetRegs(pid, &orig); err != nil {
		return 0, fmt.Errorf("setregs: %w", err)
	}
	return int64(after.Rax), nil
}
