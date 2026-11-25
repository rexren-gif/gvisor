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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

// ptraceAttackEnv makes the test binary run ptraceAttack instead of the tests.
const ptraceAttackEnv = "BWRAP_TEST_PTRACE_ATTACK"

func TestMain(m *testing.M) {
	if os.Getenv(ptraceAttackEnv) == "1" {
		os.Exit(ptraceAttack())
	}
	os.Exit(m.Run())
}

// ptraceAttack runs inside a sandbox under a filter that denies mkdir and
// allows ptrace. It tries to make PID 1 create /tmp/pwned, and reports each
// step on stdout.
func ptraceAttack() int {
	// ptrace requests must come from the thread that attached.
	runtime.LockOSThread()
	if err := unix.Mkdir("/tmp/direct", 0755); err != nil {
		fmt.Printf("direct mkdir: %v\n", err)
	} else {
		fmt.Println("direct mkdir: ok")
	}
	if f, err := os.OpenFile("/proc/1/mem", os.O_RDWR, 0); err != nil {
		fmt.Printf("mem open: %v\n", err)
	} else {
		f.Close()
		fmt.Println("mem open: ok")
	}
	// Address 0 is not mapped, so the write fails with EFAULT if the access
	// check passes.
	b := []byte{0}
	_, err := unix.ProcessVMWritev(1, []unix.Iovec{{Base: &b[0], Len: 1}}, []unix.RemoteIovec{{Base: 0, Len: 1}}, 0)
	fmt.Printf("process_vm_writev: %v\n", err)
	if pidfd, err := unix.PidfdOpen(1, 0); err != nil {
		fmt.Printf("pidfd_open: %v\n", err)
	} else if fd, err := unix.PidfdGetfd(pidfd, 0, 0); err != nil {
		fmt.Printf("pidfd_getfd: %v\n", err)
	} else {
		unix.Close(fd)
		fmt.Println("pidfd_getfd: ok")
	}
	if err := unix.PtraceAttach(1); err != nil {
		fmt.Printf("attach: %v\n", err)
		return 0
	}
	fmt.Println("attach: ok")
	var ws unix.WaitStatus
	if _, err := unix.Wait4(1, &ws, unix.WALL, nil); err != nil {
		fmt.Printf("wait: %v\n", err)
		return 1
	}
	ret, err := ptraceInjectMkdir(1, "/tmp/pwned")
	fmt.Printf("injected mkdir: %d, %v\n", ret, err)
	if err := unix.PtraceDetach(1); err != nil {
		fmt.Printf("detach: %v\n", err)
	}
	return 0
}

// newRunRootDir returns a runtime root directory, deleted at test cleanup.
func newRunRootDir(t *testing.T) string {
	t.Helper()
	runRootDir := t.TempDir()
	t.Cleanup(func() { specutils.UnmountNullNetNS(runRootDir) })
	return runRootDir
}

func TestEnvVars(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get cwd: %v", err)
	}

	hostEnvVar := "BWRAP_TEST_ENV_VAR"
	hostEnvVal := "BWRAP_TEST_ENV_VALUE"

	baseEnv := []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/root",
	}

	tests := []struct {
		name      string
		bwrapArgs []string
		wantEnv   []string
	}{
		{
			name: "SetEnv",
			bwrapArgs: []string{
				"--ro-bind", "/", "/",
				"--setenv", "FOO", "bar",
				"--",
				"/usr/bin/env",
			},
			wantEnv: append(baseEnv, hostEnvVar+"="+hostEnvVal, "FOO=bar"),
		},
		{
			name: "ResetEnv",
			bwrapArgs: []string{
				"--ro-bind", "/", "/",
				"--setenv", hostEnvVar, "bar",
				"--",
				"/usr/bin/env",
			},
			wantEnv: append(baseEnv, hostEnvVar+"=bar"),
		},
		{
			name: "ClearEnv",
			bwrapArgs: []string{
				"--ro-bind", "/", "/",
				"--clearenv",
				"--setenv", "FOO", "bar",
				"--",
				"/usr/bin/env",
			},
			wantEnv: []string{"PWD=" + cwd, "FOO=bar", "HOME=/root"},
		},
		{
			name: "UnsetEnv",
			bwrapArgs: []string{
				"--ro-bind", "/", "/",
				"--unsetenv", hostEnvVar,
				"--",
				"/usr/bin/env",
			},
			wantEnv: baseEnv,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)
			cmd.Env = append(baseEnv, hostEnvVar+"="+hostEnvVal)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			actualEnv := strings.Split(strings.TrimSpace(stdout.String()), "\n")

			// 2. Sort both slices alphabetically so order is 100% ignored!
			slices.Sort(tc.wantEnv)
			slices.Sort(actualEnv)

			if diff := cmp.Diff(tc.wantEnv, actualEnv); diff != "" {
				t.Errorf("runsc bwrap env mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestBind(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat("/mnt"); err != nil || !info.IsDir() {
		t.Fatalf("bind destination /mnt is not a directory: %v", err)
	}
	stop := testutil.StartReaper()
	defer stop()

	workDir := t.TempDir()
	const contents = "bind mount contents\n"
	if err := os.WriteFile(filepath.Join(workDir, "input"), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(specutils.ExePath,
		"--root", newRunRootDir(t), "bwrap",
		"--ro-bind", "/", "/", "--bind", workDir, "/mnt",
		"--", "/bin/sh", "-ec", "cat /mnt/input; cp /mnt/input /mnt/output")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
	}
	if got := stdout.String(); got != contents {
		t.Errorf("bind mount contents = %q, want %q", got, contents)
	}
	output, err := os.ReadFile(filepath.Join(workDir, "output"))
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != contents {
		t.Errorf("written bind mount contents = %q, want %q", output, contents)
	}
}

func TestUserAndGroup(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name      string
		bwrapArgs []string
		wantUID   string
		wantGID   string
	}{
		{
			name: "DefaultUser",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--",
				"/usr/bin/id", "-u",
			},
			wantUID: fmt.Sprintf("%d", os.Getuid()),
		},
		{
			name: "CustomUID",
			bwrapArgs: []string{
				"--unshare-user",
				"--uid", "12345",
				"--ro-bind", "/", "/",
				"--",
				"/usr/bin/id", "-u",
			},
			wantUID: "12345",
		},
		{
			name: "CustomGID",
			bwrapArgs: []string{
				"--unshare-user",
				"--gid", "54321",
				"--ro-bind", "/", "/",
				"--",
				"/usr/bin/id", "-g",
			},
			wantGID: "54321",
		},
		{
			name: "CustomUIDAndGID",
			bwrapArgs: []string{
				"--unshare-user",
				"--uid", "12345",
				"--gid", "54321",
				"--ro-bind", "/", "/",
				"--",
				"/usr/bin/id",
			},
			wantUID: "uid=12345",
			wantGID: "gid=54321",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantUID != "" && !strings.Contains(output, tc.wantUID) {
				t.Errorf("output = %q, want UID %q", output, tc.wantUID)
			}
			if tc.wantGID != "" && !strings.Contains(output, tc.wantGID) {
				t.Errorf("output = %q, want GID %q", output, tc.wantGID)
			}
		})
	}
}

// TODO: b/518882196 - Support joining existing user namespaces.
func TestUserns(t *testing.T) {
	t.Skip("Skipping userns joining due to runsc doesn't support joining existing user namespaces")
}

func TestHostname(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name       string
		bwrapArgs  []string
		wantOutput string
	}{
		{
			name: "Hostname",
			bwrapArgs: []string{
				"--hostname", "test-host",
				"--ro-bind", "/", "/",
				"--",
				"/bin/hostname",
			},
			wantOutput: "test-host",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output = %q, want it to contain %q", output, tc.wantOutput)
			}
		})
	}
}

func TestProc(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name       string
		bwrapArgs  []string
		wantOutput string
	}{
		{
			name: "Proc",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--proc", "/proc1",
				"--",
				"/bin/ls", "/proc1",
			},
			wantOutput: "cpuinfo",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output = %q, want it to contain %q", output, tc.wantOutput)
			}
		})
	}
}

func TestCapabilities(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name       string
		bwrapArgs  []string
		wantOutput string
	}{
		{
			name: "CapDropAll",
			bwrapArgs: []string{
				"--unshare-all",
				"--ro-bind", "/", "/",
				"--cap-drop", "ALL",
				"--",
				"/bin/cat", "/proc/self/status",
			},
			// All bits zeroed out after dropping ALL capabilities.
			wantOutput: "CapEff:\t0000000000000000",
		},
		{
			name: "CapDropAllAndAddNetAdmin",
			bwrapArgs: []string{
				"--unshare-all",
				"--ro-bind", "/", "/",
				"--cap-drop", "ALL",
				"--cap-add", "NET_ADMIN",
				"--",
				"/bin/cat", "/proc/self/status",
			},
			// CAP_NET_ADMIN is bit 12 (1 << 12 = 0x1000).
			wantOutput: "CapEff:\t0000000000001000",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output missing expected capability mask:\ngot:\n%s\nwant to contain: %q", output, tc.wantOutput)
			}
		})
	}
}

func TestArgv0(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name       string
		bwrapArgs  []string
		wantOutput string
	}{
		{
			name: "CustomArgv0",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--argv0", "my-custom-sh",
				"--",
				"/bin/sh", "-c", "echo $0",
			},
			wantOutput: "my-custom-sh",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output = %q, want it to contain %q", output, tc.wantOutput)
			}
		})
	}
}

func TestPerms(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name       string
		bwrapArgs  []string
		wantOutput string
	}{
		{
			name: "TmpfsPerms",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--perms", "0700", "--tmpfs", "/foo",
				"--",
				"/bin/sh", "-c", "stat -c %a /foo",
			},
			wantOutput: "700",
		},
		{
			// Without --perms the tmpfs keeps gVisor's default mode, which is
			// 0777 plus the sticky bit.
			name: "TmpfsDefaultPerms",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/foo",
				"--",
				"/bin/sh", "-c", "stat -c %a /foo",
			},
			wantOutput: "1777",
		},
		{
			// --perms is consumed by the mount that follows it, so /b falls back
			// to the tmpfs default instead of inheriting the 0700.
			name: "PermsDoNotApplyToNextTmpfs",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--perms", "0700", "--tmpfs", "/a",
				"--tmpfs", "/b",
				"--",
				"/bin/sh", "-c", "echo $(stat -c %a /a) $(stat -c %a /b)",
			},
			wantOutput: "700 1777",
		},
		{
			name: "PermsApplyIndependentlyPerTmpfs",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--perms", "0700", "--tmpfs", "/a",
				"--perms", "0500", "--tmpfs", "/b",
				"--",
				"/bin/sh", "-c", "echo $(stat -c %a /a) $(stat -c %a /b)",
			},
			wantOutput: "700 500",
		},
		{
			// --perms only ever affects what follows it, so the mount declared
			// before it keeps the default mode.
			name: "PermsDoNotApplyToEarlierTmpfs",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/a",
				"--perms", "0700", "--tmpfs", "/b",
				"--",
				"/bin/sh", "-c", "echo $(stat -c %a /a) $(stat -c %a /b)",
			},
			wantOutput: "1777 700",
		},
		// The --dir cases below sit under a tmpfs, where --dir is itself a tmpfs
		// mount and --perms sets its mode.
		{
			name: "DirPerms",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--perms", "0700", "--dir", "/mnt/foo",
				"--",
				"/bin/sh", "-c", "stat -c %a /mnt/foo",
			},
			wantOutput: "700",
		},
		{
			// Without --perms the directory keeps gVisor's tmpfs default mode,
			// which is 0777 plus the sticky bit.
			name: "DirDefaultPerms",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--dir", "/mnt/foo",
				"--",
				"/bin/sh", "-c", "stat -c %a /mnt/foo",
			},
			wantOutput: "1777",
		},
		{
			// --perms is consumed by the directory that follows it, so /mnt/b
			// falls back to the tmpfs default instead of inheriting the 0700.
			name: "PermsDoNotApplyToNextDir",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--perms", "0700", "--dir", "/mnt/a",
				"--dir", "/mnt/b",
				"--",
				"/bin/sh", "-c", "echo $(stat -c %a /mnt/a) $(stat -c %a /mnt/b)",
			},
			wantOutput: "700 1777",
		},
		{
			name: "PermsApplyIndependentlyPerDir",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--perms", "0700", "--dir", "/mnt/a",
				"--perms", "0500", "--dir", "/mnt/b",
				"--",
				"/bin/sh", "-c", "echo $(stat -c %a /mnt/a) $(stat -c %a /mnt/b)",
			},
			wantOutput: "700 500",
		},
		{
			// --perms only ever affects what follows it, so the directory
			// declared before it keeps the default mode.
			name: "PermsDoNotApplyToEarlierDir",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--dir", "/mnt/a",
				"--perms", "0700", "--dir", "/mnt/b",
				"--",
				"/bin/sh", "-c", "echo $(stat -c %a /mnt/a) $(stat -c %a /mnt/b)",
			},
			wantOutput: "1777 700",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output = %q, want it to contain %q", output, tc.wantOutput)
			}
		})
	}
}

func TestDir(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	// hostDir is bind mounted at /mnt in the cases that need a writable host
	// directory. Each case gets a fresh one.
	const hostDir = "HOST_DIR"
	tests := []struct {
		name string
		// setup prepares hostDir before the run.
		setup func(t *testing.T, hostDir string)
		// bwrapArgs are the arguments, with hostDir standing in for the host
		// directory.
		bwrapArgs  []string
		wantOutput string
		// wantErr, if set, is text the failed run's stderr must contain.
		wantErr string
		// wantHostMode is the mode of hostDir/new afterwards, 0 if it must not
		// exist.
		wantHostMode os.FileMode
		// wantHostFile is a path under hostDir that must exist afterwards.
		wantHostFile string
	}{
		// Without a bind mount behind DEST, --dir is a tmpfs stand-in.
		{
			name: "CreatesParents",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--dir", "/mnt/a/b/c",
				"--",
				"/bin/sh", "-c", "test -d /mnt/a/b/c && echo ok",
			},
			wantOutput: "ok",
		},
		{
			name: "Writable",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--dir", "/mnt/foo",
				"--",
				"/bin/sh", "-c", "touch /mnt/foo/file && echo ok",
			},
			wantOutput: "ok",
		},
		// Under a bind mount, --dir works on the host as bubblewrap's mkdir
		// does through the bind.
		{
			name: "MissingInWritableBind",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--bind", hostDir, "/mnt",
				"--dir", "/mnt/new",
				"--",
				"/bin/sh", "-c", "echo data > /mnt/new/file && echo ok",
			},
			wantOutput:   "ok",
			wantHostMode: 0755,
			wantHostFile: "new/file",
		},
		{
			name: "MissingInWritableBindWithPerms",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--bind", hostDir, "/mnt",
				"--perms", "0700", "--dir", "/mnt/new",
				"--",
				"/bin/sh", "-c", "stat -c %a /mnt/new",
			},
			wantOutput:   "700",
			wantHostMode: 0700,
		},
		{
			name: "MissingParentsInWritableBind",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--bind", hostDir, "/mnt",
				"--dir", "/mnt/new/a/b",
				"--",
				"/bin/sh", "-c", "touch /mnt/new/a/b/file && echo ok",
			},
			wantOutput:   "ok",
			wantHostMode: 0755,
			wantHostFile: "new/a/b/file",
		},
		{
			// An existing directory keeps its mode and contents rather than
			// being hidden behind an empty mount. 0751 differs from the 0755
			// a new directory would get, and still lets a sandbox user that
			// does not own it, as under sudo, reach the marker.
			name: "ExistingInWritableBind",
			setup: func(t *testing.T, hostDir string) {
				newDir := filepath.Join(hostDir, "new")
				if err := os.Mkdir(newDir, 0751); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(newDir, 0751); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(newDir, "marker"), nil, 0644); err != nil {
					t.Fatal(err)
				}
			},
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--bind", hostDir, "/mnt",
				"--dir", "/mnt/new",
				"--",
				"/bin/sh", "-c", "test -f /mnt/new/marker && echo ok",
			},
			wantOutput:   "ok",
			wantHostMode: 0751,
			wantHostFile: "new/marker",
		},
		{
			name: "ExistingInReadOnlyBind",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--dir", "/usr",
				"--",
				"/bin/sh", "-c", "test -d /usr/bin && echo ok",
			},
			wantOutput: "ok",
		},
		{
			// bubblewrap's mkdir fails with EROFS inside a read-only bind, and
			// so does runsc, without touching the host.
			name: "MissingInReadOnlyBind",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", hostDir, "/mnt",
				"--dir", "/mnt/new",
				"--",
				"/bin/sh", "-c", "echo unreachable",
			},
			wantErr: "Can't mkdir /mnt/new: read-only file system",
		},
		// A directory that an earlier mount provides already exists, so --dir
		// leaves the mount alone rather than hiding it.
		{
			name: "ExistingTmpfs",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--perms", "0700", "--tmpfs", "/mnt",
				"--dir", "/mnt",
				"--",
				"/bin/sh", "-c", "stat -c %a /mnt",
			},
			wantOutput: "700",
		},
		{
			name: "ExistingProc",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--proc", "/proc",
				"--dir", "/proc",
				"--",
				"/bin/sh", "-c", "test -e /proc/self/status && echo ok",
			},
			wantOutput: "ok",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)
			// Under sudo, the sandbox user that SUDO_UID maps to must be able
			// to enter the directory, whatever the umask of the test.
			dir := t.TempDir()
			if err := os.Chmod(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if tc.setup != nil {
				tc.setup(t, dir)
			}

			args := []string{"--root", runRootDir, "bwrap"}
			for _, arg := range tc.bwrapArgs {
				if arg == hostDir {
					arg = dir
				}
				args = append(args, arg)
			}
			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			// bubblewrap clears its umask while it sets up the sandbox, so a
			// restrictive one inherited by runsc must not change the host modes
			// below. Only runsc gets it: under sudo, a 0700 dir from t.TempDir()
			// would shut out the sandbox user that SUDO_UID maps to.
			oldMask := unix.Umask(077)
			err := testutil.RunCmd(cmd)
			unix.Umask(oldMask)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("runsc bwrap succeeded, want failure with %q\nStdout: %s", tc.wantErr, stdout.String())
				}
				if !strings.Contains(stderr.String(), tc.wantErr) {
					t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			output := strings.TrimSpace(stdout.String())
			if tc.wantOutput != "" && !strings.Contains(output, tc.wantOutput) {
				t.Errorf("output = %q, want it to contain %q", output, tc.wantOutput)
			}

			newDir := filepath.Join(dir, "new")
			info, err := os.Stat(newDir)
			if tc.wantHostMode == 0 {
				if !errors.Is(err, os.ErrNotExist) {
					t.Errorf("os.Stat(%q) = %v, want %v", newDir, err, os.ErrNotExist)
				}
			} else if err != nil {
				t.Errorf("os.Stat(%q) = %v, want a directory", newDir, err)
			} else if !info.IsDir() || info.Mode().Perm() != tc.wantHostMode {
				t.Errorf("%q is %v, want a directory with mode %v", newDir, info.Mode(), tc.wantHostMode)
			}
			if tc.wantHostFile != "" {
				if _, err := os.Stat(filepath.Join(dir, tc.wantHostFile)); err != nil {
					t.Errorf("host file missing after the run: %v", err)
				}
			}
		})
	}
}

func TestAsPID1(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name      string
		bwrapArgs []string
		wantPID1  bool
	}{
		{
			name: "AsPID1",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--as-pid-1",
				"--",
				"/bin/sh", "-c", "echo $$",
			},
			wantPID1: true,
		},
		{
			// Without --as-pid-1 the /bin/sleep placeholder is PID 1.
			name: "NotPID1ByDefault",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--",
				"/bin/sh", "-c", "echo $$",
			},
			wantPID1: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			pid := strings.TrimSpace(stdout.String())
			if gotPID1 := pid == "1"; gotPID1 != tc.wantPID1 {
				t.Errorf("COMMAND ran as PID %q, want PID 1: %t", pid, tc.wantPID1)
			}
		})
	}
}

// TestAsPID1ExitStatus checks that runsc bwrap exits with COMMAND's exit status
// when COMMAND runs as PID 1.
func TestAsPID1ExitStatus(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	cmd := exec.Command(specutils.ExePath, "--root", newRunRootDir(t), "bwrap",
		"--unshare-user",
		"--ro-bind", "/", "/",
		"--as-pid-1",
		"--",
		"/bin/sh", "-c", "exit 7",
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := testutil.RunCmd(cmd)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Errorf("runsc bwrap = %v, want exit status 7\nStderr: %s", err, stderr.String())
	}
}

// TestAsPID1Argv0 checks --as-pid-1 and --argv0 alone and together. --as-pid-1
// decides whether COMMAND is PID 1, and --argv0 decides its argv[0]. Neither
// flag changes what the other does.
func TestAsPID1Argv0(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	tests := []struct {
		name      string
		bwrapArgs []string
		wantArgv0 string
		wantPID1  bool
	}{
		{
			name: "Default",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--",
				"/bin/sh", "-c", "echo $0 $$",
			},
			wantArgv0: "/bin/sh",
			wantPID1:  false,
		},
		{
			name: "Argv0",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--argv0", "custom-sh",
				"--",
				"/bin/sh", "-c", "echo $0 $$",
			},
			wantArgv0: "custom-sh",
			wantPID1:  false,
		},
		{
			name: "AsPID1",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--as-pid-1",
				"--",
				"/bin/sh", "-c", "echo $0 $$",
			},
			wantArgv0: "/bin/sh",
			wantPID1:  true,
		},
		{
			name: "AsPID1AndArgv0",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--as-pid-1",
				"--argv0", "custom-sh",
				"--",
				"/bin/sh", "-c", "echo $0 $$",
			},
			wantArgv0: "custom-sh",
			wantPID1:  true,
		},
		{
			// COMMAND has no slash, so the Sentry looks it up in PATH by its
			// name, sh, not by argv[0].
			name: "AsPID1AndArgv0PathLookup",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--as-pid-1",
				"--argv0", "custom-sh",
				"--",
				"sh", "-c", "echo $0 $$",
			},
			wantArgv0: "custom-sh",
			wantPID1:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			argv0, pid, ok := strings.Cut(strings.TrimSpace(stdout.String()), " ")
			if !ok {
				t.Fatalf(`output = %q, want "<argv0> <pid>"`, stdout.String())
			}
			if argv0 != tc.wantArgv0 {
				t.Errorf("COMMAND ran with argv[0] %q, want %q", argv0, tc.wantArgv0)
			}
			if gotPID1 := pid == "1"; gotPID1 != tc.wantPID1 {
				t.Errorf("COMMAND ran as PID %q, want PID 1: %t", pid, tc.wantPID1)
			}
		})
	}
}

func TestDev(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	// check succeeds if DIR holds working device nodes, the standard symlinks
	// and a devpts at DIR/pts.
	check := func(dir string) string {
		return fmt.Sprintf("test -c %[1]s/null && echo x > %[1]s/null && "+
			"test -c %[1]s/urandom && test -L %[1]s/stdin && "+
			"test -c %[1]s/pts/ptmx && echo ok", dir)
	}

	tests := []struct {
		name      string
		bwrapArgs []string
	}{
		{
			name: "NewDest",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/mnt",
				"--dev", "/mnt/dev",
				"--",
				"/bin/sh", "-c", check("/mnt/dev"),
			},
		},
		{
			name: "ReplaceDev",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--dev", "/dev",
				"--",
				"/bin/sh", "-c", check("/dev"),
			},
		},
		{
			// runsc always serves /dev from its dev filesystem, so a tmpfs
			// at /dev still holds the device nodes.
			name: "TmpfsAtDev",
			bwrapArgs: []string{
				"--unshare-user",
				"--ro-bind", "/", "/",
				"--tmpfs", "/dev",
				"--",
				"/bin/sh", "-c", check("/dev"),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runRootDir := newRunRootDir(t)

			args := append([]string{
				"--root", runRootDir,
				"bwrap",
			}, tc.bwrapArgs...)

			cmd := exec.Command(specutils.ExePath, args...)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}

			if got := strings.TrimSpace(stdout.String()); got != "ok" {
				t.Errorf("output = %q, want %q", got, "ok")
			}
		})
	}
}

// seccompArch holds the audit architecture of the host and the numbers of the
// system calls that the seccomp filters in the tests below deny.
type seccompArch struct {
	audit uint32
	// mkdir holds every system call that mkdir(1) may use.
	mkdir []uint32
	// chdir holds the system call that the cd shell builtin uses.
	chdir []uint32
}

var seccompArches = map[string]seccompArch{
	// mkdir is 83 and mkdirat is 258. chdir is 80.
	"amd64": {audit: linux.AUDIT_ARCH_X86_64, mkdir: []uint32{83, 258}, chdir: []uint32{80}},
	// mkdirat is 34. chdir is 49.
	"arm64": {audit: linux.AUDIT_ARCH_AARCH64, mkdir: []uint32{34}, chdir: []uint32{49}},
}

// hostSeccompArch returns the seccompArch of the host.
func hostSeccompArch(t *testing.T) seccompArch {
	t.Helper()
	arch, ok := seccompArches[runtime.GOARCH]
	if !ok {
		t.Skipf("no seccomp test data for %s", runtime.GOARCH)
	}
	return arch
}

// denyFilter returns a seccomp filter that fails the system calls sysnos with
// errno and allows all other system calls of arch. It kills the process on a
// system call of another architecture.
func denyFilter(arch seccompArch, sysnos []uint32, errno unix.Errno) []byte {
	insns := []bpf.Instruction{
		bpf.Stmt(bpf.Ld|bpf.W|bpf.Abs, 4), // seccomp_data.arch
		bpf.Jump(bpf.Jmp|bpf.Jeq|bpf.K, arch.audit, 1, 0),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_KILL_PROCESS)),
		bpf.Stmt(bpf.Ld|bpf.W|bpf.Abs, 0), // seccomp_data.nr
	}
	for i, sysno := range sysnos {
		// On a match, skip the rest of the comparisons and the allow.
		insns = append(insns, bpf.Jump(bpf.Jmp|bpf.Jeq|bpf.K, sysno, uint8(len(sysnos)-i), 0))
	}
	insns = append(insns,
		bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW)),
		bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ERRNO.WithReturnCode(uint16(errno)))),
	)
	return bpf.ToBytecode(insns)
}

// allowAllFilter returns a seccomp filter of n instructions that allows every
// system call.
func allowAllFilter(n int) []byte {
	insns := make([]bpf.Instruction, n)
	for i := range insns {
		insns[i] = bpf.Stmt(bpf.Ret|bpf.K, uint32(linux.SECCOMP_RET_ALLOW))
	}
	return bpf.ToBytecode(insns)
}

// filterFile returns a file at offset 0 that holds data. It is removed at test
// cleanup.
func filterFile(t *testing.T, data []byte) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "filter-*.bpf")
	if err != nil {
		t.Fatalf("failed to create filter file: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	if _, err := f.Write(data); err != nil {
		t.Fatalf("failed to write filter file: %v", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("failed to rewind filter file: %v", err)
	}
	return f
}

// seccompScript runs mkdir(1) as a child of the shell, and then reports the
// seccomp state of another child.
const seccompScript = `mkdir /tmp/x; echo mkdir=$?; grep -E "^(NoNewPrivs|Seccomp):" /proc/self/status`

// TestSeccomp checks that --seccomp and --add-seccomp-fd install the filters
// read from the descriptors on COMMAND and its children.
func TestSeccomp(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	arch := hostSeccompArch(t)
	denyMkdir := denyFilter(arch, arch.mkdir, unix.EPERM)
	denyMkdirEACCES := denyFilter(arch, arch.mkdir, unix.EACCES)
	denyChdir := denyFilter(arch, arch.chdir, unix.EPERM)
	maxFilter := allowAllFilter(bpf.MaxInstructions)
	sh := []string{"--", "/bin/sh", "-c", seccompScript}

	tests := []struct {
		name string
		// filters are given to runsc as descriptors 3 and up.
		filters   [][]byte
		bwrapArgs []string
		// wantOut and wantErr are substrings of stdout and stderr.
		wantOut []string
		wantErr []string
		// notWantOut are not substrings of stdout.
		notWantOut []string
	}{
		{
			name:      "NoFilter",
			bwrapArgs: sh,
			wantOut:   []string{"mkdir=0", "NoNewPrivs:\t0", "Seccomp:\t0"},
		},
		{
			name:      "DenyMkdir",
			filters:   [][]byte{denyMkdir},
			bwrapArgs: append([]string{"--seccomp", "3"}, sh...),
			wantOut:   []string{"mkdir=1", "NoNewPrivs:\t1", "Seccomp:\t2"},
			wantErr:   []string{"Operation not permitted"},
		},
		{
			name:      "AllowAll",
			filters:   [][]byte{allowAllFilter(1)},
			bwrapArgs: append([]string{"--seccomp", "3"}, sh...),
			wantOut:   []string{"mkdir=0", "NoNewPrivs:\t1", "Seccomp:\t2"},
		},
		{
			name:      "MaxInstructions",
			filters:   [][]byte{allowAllFilter(bpf.MaxInstructions)},
			bwrapArgs: append([]string{"--seccomp", "3"}, sh...),
			wantOut:   []string{"mkdir=0", "Seccomp:\t2"},
		},
		{
			name:    "Grandchild",
			filters: [][]byte{denyMkdir},
			bwrapArgs: []string{
				"--seccomp", "3",
				"--", "/bin/sh", "-c", `/bin/sh -c "mkdir /tmp/x || exit 1"; echo mkdir=$?`,
			},
			wantOut: []string{"mkdir=1"},
		},
		{
			name: "NonRootUserNoFilter",
			bwrapArgs: append([]string{
				"--unshare-user", "--uid", "1000", "--gid", "1000",
			}, sh...),
			wantOut: []string{"mkdir=0", "NoNewPrivs:\t0", "Seccomp:\t0"},
		},
		{
			name:      "AsPID1",
			filters:   [][]byte{denyMkdir},
			bwrapArgs: append([]string{"--as-pid-1", "--seccomp", "3"}, sh...),
			wantOut:   []string{"mkdir=1", "NoNewPrivs:\t1", "Seccomp:\t2"},
		},
		{
			name:    "NonRootUser",
			filters: [][]byte{denyMkdir},
			bwrapArgs: append([]string{
				"--unshare-user", "--uid", "1000", "--gid", "1000",
				"--seccomp", "3",
			}, sh...),
			wantOut: []string{"mkdir=1", "NoNewPrivs:\t1", "Seccomp:\t2"},
		},
		{
			name:      "SeccompLastWinsAllow",
			filters:   [][]byte{denyMkdir, allowAllFilter(1)},
			bwrapArgs: append([]string{"--seccomp", "3", "--seccomp", "4"}, sh...),
			wantOut:   []string{"mkdir=0", "Seccomp:\t2"},
			wantErr:   []string{"only the last one applies"},
		},
		{
			name:      "SeccompLastWinsDeny",
			filters:   [][]byte{allowAllFilter(1), denyMkdir},
			bwrapArgs: append([]string{"--seccomp", "3", "--seccomp", "4"}, sh...),
			wantOut:   []string{"mkdir=1", "Seccomp:\t2"},
		},
		{
			name:      "SeccompSameFDRepeated",
			filters:   [][]byte{denyMkdir},
			bwrapArgs: append([]string{"--seccomp", "3", "--seccomp", "3"}, sh...),
			wantOut:   []string{"mkdir=1", "Seccomp:\t2"},
		},
		{
			// The first --seccomp is not read, so its invalid data is ignored.
			name:      "SeccompReplacedInvalid",
			filters:   [][]byte{{1, 2, 3}, denyMkdir},
			bwrapArgs: append([]string{"--seccomp", "3", "--seccomp", "4"}, sh...),
			wantOut:   []string{"mkdir=1"},
		},
		{
			name:      "AddSeccompFDOne",
			filters:   [][]byte{denyMkdir},
			bwrapArgs: append([]string{"--add-seccomp-fd", "3"}, sh...),
			wantOut:   []string{"mkdir=1", "NoNewPrivs:\t1", "Seccomp:\t2"},
		},
		{
			name:    "AddSeccompFDStacks",
			filters: [][]byte{denyMkdir, denyChdir},
			bwrapArgs: []string{
				"--add-seccomp-fd", "3",
				"--add-seccomp-fd", "4",
				"--", "/bin/sh", "-c", `mkdir /tmp/x; echo mkdir=$?; cd /tmp; echo cd=$?`,
			},
			wantOut:    []string{"mkdir=1", "cd="},
			notWantOut: []string{"cd=0"},
		},
		{
			name:    "AddSeccompFDStacksWithAllow",
			filters: [][]byte{denyMkdir, allowAllFilter(1)},
			bwrapArgs: append([]string{
				"--add-seccomp-fd", "3",
				"--add-seccomp-fd", "4",
			}, sh...),
			wantOut: []string{"mkdir=1"},
		},
		{
			// If filters return the same action, the last one installed
			// decides the errno.
			name:      "AddSeccompFDOrderEACCESLast",
			filters:   [][]byte{denyMkdir, denyMkdirEACCES},
			bwrapArgs: append([]string{"--add-seccomp-fd", "3", "--add-seccomp-fd", "4"}, sh...),
			wantOut:   []string{"mkdir=1"},
			wantErr:   []string{"Permission denied"},
		},
		{
			name:      "AddSeccompFDOrderEPERMLast",
			filters:   [][]byte{denyMkdirEACCES, denyMkdir},
			bwrapArgs: append([]string{"--add-seccomp-fd", "3", "--add-seccomp-fd", "4"}, sh...),
			wantOut:   []string{"mkdir=1"},
			wantErr:   []string{"Operation not permitted"},
		},
		{
			// 7 filters of 4096 instructions, plus 4 for each filter beyond
			// the first, fit in 32768 instructions.
			name:    "MaxCombinedLength",
			filters: [][]byte{maxFilter, maxFilter, maxFilter, maxFilter, maxFilter, maxFilter, maxFilter},
			bwrapArgs: append([]string{
				"--add-seccomp-fd", "3", "--add-seccomp-fd", "4", "--add-seccomp-fd", "5",
				"--add-seccomp-fd", "6", "--add-seccomp-fd", "7", "--add-seccomp-fd", "8",
				"--add-seccomp-fd", "9",
			}, sh...),
			wantOut: []string{"mkdir=0", "Seccomp:\t2"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// mkdir fails for other reasons too, so check that the filter
			// made it fail.
			if slices.Contains(tc.wantOut, "mkdir=1") && len(tc.wantErr) == 0 {
				tc.wantErr = []string{"Operation not permitted"}
			}
			stdout, stderr, err := runBwrapWithFilters(t, nil, tc.filters, tc.bwrapArgs...)
			if err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
			}
			for _, want := range tc.wantOut {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout = %q, want it to contain %q", stdout, want)
				}
			}
			for _, notWant := range tc.notWantOut {
				if strings.Contains(stdout, notWant) {
					t.Errorf("stdout = %q, want it not to contain %q", stdout, notWant)
				}
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr = %q, want it to contain %q", stderr, want)
				}
			}
		})
	}
}

// TestSeccompErrors checks that runsc bwrap fails before the command runs if
// it cannot use a filter.
func TestSeccompErrors(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	noReturn := bpf.ToBytecode([]bpf.Instruction{bpf.Stmt(bpf.Ld|bpf.W|bpf.Abs, 0)})
	badOpcode := bpf.ToBytecode([]bpf.Instruction{bpf.RawInstruction(0xffff, 0, 0, 0)})
	maxFilter := allowAllFilter(bpf.MaxInstructions)

	tests := []struct {
		name      string
		runscArgs []string
		filters   [][]byte
		bwrapArgs []string
		wantErr   string
	}{
		{
			// 8 filters of 4096 instructions, plus 4 for each filter beyond
			// the first, do not fit in 32768 instructions.
			name:    "CombinedLengthTooLarge",
			filters: [][]byte{maxFilter, maxFilter, maxFilter, maxFilter, maxFilter, maxFilter, maxFilter, maxFilter},
			bwrapArgs: []string{
				"--add-seccomp-fd", "3", "--add-seccomp-fd", "4", "--add-seccomp-fd", "5",
				"--add-seccomp-fd", "6", "--add-seccomp-fd", "7", "--add-seccomp-fd", "8",
				"--add-seccomp-fd", "9", "--add-seccomp-fd", "10",
			},
			wantErr: "in total",
		},
		{
			name:      "RunscLogFD",
			runscArgs: []string{"--log-fd=3"},
			filters:   [][]byte{allowAllFilter(1)},
			bwrapArgs: []string{"--seccomp", "3"},
			wantErr:   "runsc uses it for --log-fd",
		},
		{
			name:      "Empty",
			filters:   [][]byte{{}},
			bwrapArgs: []string{"--seccomp", "3"},
			wantErr:   "filter is empty",
		},
		{
			name:      "NotMultipleOfInstructionSize",
			filters:   [][]byte{{1, 2, 3}},
			bwrapArgs: []string{"--seccomp", "3"},
			wantErr:   "not a multiple",
		},
		{
			name:      "TooManyInstructions",
			filters:   [][]byte{allowAllFilter(bpf.MaxInstructions + 1)},
			bwrapArgs: []string{"--seccomp", "3"},
			wantErr:   "more than 4096 instructions",
		},
		{
			name:      "NoReturn",
			filters:   [][]byte{noReturn},
			bwrapArgs: []string{"--add-seccomp-fd", "3"},
			wantErr:   "not a valid BPF program",
		},
		{
			name:      "BadOpcode",
			filters:   [][]byte{allowAllFilter(1), badOpcode},
			bwrapArgs: []string{"--add-seccomp-fd", "3", "--add-seccomp-fd", "4"},
			wantErr:   "not a valid BPF program",
		},
		{
			name:      "ClosedFD",
			bwrapArgs: []string{"--seccomp", "3"},
			wantErr:   "bad file descriptor",
		},
		{
			name:      "SameFDTwice",
			filters:   [][]byte{allowAllFilter(1)},
			bwrapArgs: []string{"--add-seccomp-fd", "3", "--add-seccomp-fd", "3"},
			wantErr:   "bad file descriptor",
		},
		{
			name:      "SeccompAndAddSeccompFD",
			filters:   [][]byte{allowAllFilter(1), allowAllFilter(1)},
			bwrapArgs: []string{"--seccomp", "3", "--add-seccomp-fd", "4"},
			wantErr:   "mutually exclusive",
		},
		{
			name:      "PermsBeforeSeccomp",
			filters:   [][]byte{allowAllFilter(1)},
			bwrapArgs: []string{"--perms", "0700", "--seccomp", "3"},
			wantErr:   "--perms must be followed by",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := slices.Concat(tc.bwrapArgs, []string{"--ro-bind", "/", "/", "--", "/bin/echo", "ran"})
			stdout, stderr, err := runBwrapWithFilters(t, tc.runscArgs, tc.filters, args...)
			if err == nil {
				t.Fatalf("runsc bwrap succeeded, want error containing %q\nStdout: %s", tc.wantErr, stdout)
			}
			if strings.Contains(stdout, "ran") {
				t.Errorf("command ran, stdout: %q", stdout)
			}
			if !strings.Contains(stderr, tc.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr, tc.wantErr)
			}
		})
	}
}

// runBwrapWithFilters runs runsc with the global flags runscArgs and then bwrap
// with bwrapArgs, after --ro-bind / / if bwrapArgs do not mount a root.
// filters[i] is given to runsc as descriptor 3+i; a nil entry leaves that
// descriptor closed.
func runBwrapWithFilters(t *testing.T, runscArgs []string, filters [][]byte, bwrapArgs ...string) (string, string, error) {
	t.Helper()
	args := append([]string{"--root", newRunRootDir(t)}, runscArgs...)
	args = append(args, "bwrap")
	if !slices.Contains(bwrapArgs, "--ro-bind") {
		args = append(args, "--ro-bind", "/", "/")
	}
	cmd := exec.Command(specutils.ExePath, append(args, bwrapArgs...)...)
	for _, filter := range filters {
		var f *os.File
		if filter != nil {
			f = filterFile(t, filter)
		}
		cmd.ExtraFiles = append(cmd.ExtraFiles, f)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := testutil.RunCmd(cmd)
	return stdout.String(), stderr.String(), err
}

// TestSeccompPtraceInit checks that COMMAND cannot use ptrace on the sandbox
// init process, which has no filter, to run a system call that its own filter
// denies.
func TestSeccompPtraceInit(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to find the test binary: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	arch := hostSeccompArch(t)
	for _, tc := range []struct {
		name      string
		filters   [][]byte
		bwrapArgs []string
		wantOut   []string
	}{
		{
			// The filter denies mkdir, and allows ptrace.
			name:      "Filter",
			filters:   [][]byte{denyFilter(arch, arch.mkdir, unix.EPERM)},
			bwrapArgs: []string{"--seccomp", "3"},
			wantOut: []string{
				"direct mkdir: operation not permitted",
				"mem open: open /proc/1/mem: permission denied",
				"process_vm_writev: operation not permitted",
				"pidfd_getfd: operation not permitted",
				"attach: operation not permitted",
				"safe",
			},
		},
		{
			// Without a filter, the init process can be traced as before.
			name: "NoFilter",
			wantOut: []string{
				"direct mkdir: ok",
				"mem open: ok",
				"process_vm_writev: bad address",
				"pidfd_getfd: ok",
				"attach: ok",
				"injected mkdir: 0, <nil>",
				"PWNED",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "NoFilter" && runtime.GOARCH != "amd64" {
				t.Skipf("ptraceInjectMkdir is not implemented on %s", runtime.GOARCH)
			}
			args := slices.Concat([]string{
				"--ro-bind", "/", "/",
				"--ro-bind", filepath.Dir(exe), "/attacker",
				"--setenv", ptraceAttackEnv, "1",
			}, tc.bwrapArgs, []string{
				"--", "/bin/sh", "-c", "/attacker/" + filepath.Base(exe) + "; test -d /tmp/pwned && echo PWNED || echo safe",
			})
			stdout, stderr, err := runBwrapWithFilters(t, nil, tc.filters, args...)
			if err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
			}
			for _, want := range tc.wantOut {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout = %q, want it to contain %q", stdout, want)
				}
			}
		})
	}
}

// TestSeccompStdin checks that runsc bwrap reads a filter from its stdin, and
// that COMMAND then gets /dev/null there.
func TestSeccompStdin(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	arch := hostSeccompArch(t)
	cmd := exec.Command(specutils.ExePath, "--root", newRunRootDir(t), "bwrap",
		"--ro-bind", "/", "/",
		"--seccomp", "0",
		"--", "/bin/sh", "-c", seccompScript+`; cat; echo cat=$?`,
	)
	cmd.Stdin = filterFile(t, denyFilter(arch, arch.mkdir, unix.EPERM))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := testutil.RunCmd(cmd); err != nil {
		t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
	}
	if want := "mkdir=1\nNoNewPrivs:\t1\nSeccomp:\t2\ncat=0\n"; stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
}

// TestSeccompStdioErrors checks the errors of filters read from stdio
// descriptors.
func TestSeccompStdioErrors(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	arch := hostSeccompArch(t)
	for _, tc := range []struct {
		name      string
		bwrapArgs []string
		wantErr   string
	}{
		{
			// stderr is the write end of a pipe, so the read fails, and runsc
			// still reports the error there.
			name:      "ReadFailure",
			bwrapArgs: []string{"--seccomp", "2"},
			wantErr:   "Can't read seccomp filter from fd 2: bad file descriptor",
		},
		{
			name:      "RepeatedStdin",
			bwrapArgs: []string{"--add-seccomp-fd", "0", "--add-seccomp-fd", "0"},
			wantErr:   "Can't read seccomp filter from fd 0: bad file descriptor",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := slices.Concat([]string{"--root", newRunRootDir(t), "bwrap", "--ro-bind", "/", "/"}, tc.bwrapArgs, []string{"--", "/bin/echo", "ran"})
			cmd := exec.Command(specutils.ExePath, args...)
			cmd.Stdin = filterFile(t, denyFilter(arch, arch.mkdir, unix.EPERM))
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := testutil.RunCmd(cmd); err == nil {
				t.Fatalf("runsc bwrap succeeded, want error containing %q\nStdout: %s", tc.wantErr, stdout.String())
			}
			if strings.Contains(stdout.String(), "ran") {
				t.Errorf("command ran, stdout: %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tc.wantErr)
			}
		})
	}
}

// TestSeccompFDNotInherited checks that no host process that runs the sandbox
// keeps a seccomp filter descriptor open while COMMAND runs.
func TestSeccompFDNotInherited(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}

	stop := testutil.StartReaper()
	defer stop()

	for _, flag := range []string{"--seccomp", "--add-seccomp-fd"} {
		t.Run(strings.TrimPrefix(flag, "--"), func(t *testing.T) {
			filter := filterFile(t, allowAllFilter(1))
			filterInfo, err := filter.Stat()
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			runRootDir := newRunRootDir(t)
			cmd := exec.Command(specutils.ExePath, "--root", runRootDir, "bwrap",
				"--ro-bind", "/", "/",
				flag, "3",
				"--", "/bin/sh", "-c", "echo ready; read x; exit 0",
			)
			cmd.ExtraFiles = []*os.File{filter}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatalf("stdin pipe: %v", err)
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatalf("stdout pipe: %v", err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := testutil.StartCmd(cmd); err != nil {
				t.Fatalf("failed to start runsc bwrap: %v", err)
			}
			defer func() {
				stdin.Close()
				if err := testutil.WaitCmd(cmd); err != nil {
					t.Errorf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
				}
			}()
			if err := testutil.WaitUntilRead(stdout, "ready", 30*time.Second); err != nil {
				// The deferred function reports stderr after runsc exits.
				t.Fatalf("command did not start: %v", err)
			}

			// Every runsc process of this sandbox has runRootDir in its
			// command line.
			procs, leaks := openFiles(t, runRootDir, func(path, target string) bool {
				// The descriptor given to runsc bwrap, or a file that runsc
				// bwrap gives to runsc exec.
				info, err := os.Stat(path)
				return (err == nil && os.SameFile(info, filterInfo)) || strings.Contains(target, "/seccomp-")
			})
			// runsc bwrap, runsc exec and the sandbox process at least.
			if procs < 3 {
				t.Errorf("inspected %d runsc processes, want at least 3", procs)
			}
			t.Logf("inspected %d runsc processes", procs)
			for _, leak := range leaks {
				t.Errorf("filter file still open: %s", leak)
			}
		})
	}
}

// openFiles inspects the processes whose command line contains cmdline. It
// returns their number, and their descriptors for which match returns true.
func openFiles(t *testing.T, cmdline string, match func(path, target string) bool) (int, []string) {
	t.Helper()
	procs, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatalf("failed to read /proc: %v", err)
	}
	inspected := 0
	var found []string
	for _, p := range procs {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		args, err := os.ReadFile(filepath.Join("/proc", p.Name(), "cmdline"))
		if err != nil || !bytes.Contains(args, []byte(cmdline)) {
			continue
		}
		fdDir := filepath.Join("/proc", p.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			t.Errorf("failed to read %s: %v", fdDir, err)
			continue
		}
		inspected++
		for _, fd := range fds {
			path := filepath.Join(fdDir, fd.Name())
			target, err := os.Readlink(path)
			if err == nil && match(path, target) {
				found = append(found, fmt.Sprintf("%s -> %s", path, target))
			}
		}
	}
	return inspected, found
}
