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
	"fmt"
	"math"
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/flag"
)

// runscFDFlags are the global runsc flags that give runsc a descriptor of its
// own.
var runscFDFlags = []string{"log-fd", "debug-log-fd", "panic-log-fd", "coverage-fd"}

// CheckInheritedFD returns nil if fd is an open descriptor that runsc
// inherited and that no global runsc flag uses. runsc opens its own
// descriptors close-on-exec, and a descriptor that survived execve is not
// close-on-exec.
func CheckInheritedFD(fd int) error {
	// The kernel takes descriptors as 32-bit values.
	if fd < 0 || fd > math.MaxInt32 {
		return unix.EBADF
	}
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return err
	}
	if flags&unix.FD_CLOEXEC != 0 {
		return unix.EBADF
	}
	for _, name := range runscFDFlags {
		if f := flag.Lookup(name); f != nil && f.Value.String() == strconv.Itoa(fd) {
			return fmt.Errorf("runsc uses it for --%s", name)
		}
	}
	return nil
}
