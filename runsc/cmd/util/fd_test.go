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

package util

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCheckInheritedFD(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	// dup(2) clears close-on-exec, like a descriptor that runsc inherits.
	inherited, err := unix.Dup(int(r.Fd()))
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	defer unix.Close(inherited)

	if err := CheckInheritedFD(inherited); err != nil {
		t.Errorf("CheckInheritedFD(inherited) = %v, want nil", err)
	}
	for _, tc := range []struct {
		name string
		fd   int
	}{
		{name: "Negative", fd: -1},
		{name: "CloseOnExec", fd: int(r.Fd())},
		// Without a 32-bit limit, the kernel would check the inherited
		// descriptor instead.
		{name: "TooLarge", fd: 1<<32 + inherited},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckInheritedFD(tc.fd); !errors.Is(err, unix.EBADF) {
				t.Errorf("CheckInheritedFD(%d) = %v, want %v", tc.fd, err, unix.EBADF)
			}
		})
	}
}
