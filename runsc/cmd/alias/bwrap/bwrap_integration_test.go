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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

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

// blockedOpts are the options of runBlocked.
type blockedOpts struct {
	// root is the runsc root directory.
	root string
	// fdFlags are the --info-fd and --block-fd flags.
	fdFlags []string
	// blockFirst gives the --block-fd pipe as fd 3 and the --info-fd pipe as
	// fd 4, instead of the reverse.
	blockFirst bool
	// wrapper is a command that runs `runsc bwrap`, e.g. nohup.
	wrapper []string
	// extra are more files for `runsc bwrap`, as fds 5 and up.
	extra []*os.File
}

// runBlocked starts `runsc bwrap` with o.fdFlags and bwrapArgs, and gives it
// an --info-fd pipe and a --block-fd pipe. It returns the command, its stderr,
// the --info-fd JSON object and the write end of the --block-fd pipe.
func runBlocked(t *testing.T, o blockedOpts, bwrapArgs ...string) (*exec.Cmd, *bytes.Buffer, map[string]int, *os.File) {
	t.Helper()
	infoReader, infoWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer infoReader.Close()
	blockReader, blockWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { blockWriter.Close() })

	args := append(append([]string{specutils.ExePath, "--root", o.root, "bwrap"}, o.fdFlags...), bwrapArgs...)
	args = append(o.wrapper, args...)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.ExtraFiles = []*os.File{infoWriter, blockReader}
	if o.blockFirst {
		cmd.ExtraFiles = []*os.File{blockReader, infoWriter}
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, o.extra...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := testutil.StartCmd(cmd); err != nil {
		t.Fatal(err)
	}
	infoWriter.Close()
	blockReader.Close()

	// The read ends at EOF only once no process, the sandbox's included,
	// holds the write end.
	if err := infoReader.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(infoReader)
	var info map[string]int
	if err == nil {
		err = json.Unmarshal(data, &info)
	}
	if err != nil {
		blockWriter.Close()
		testutil.WaitCmd(cmd)
		t.Fatalf("reading --info-fd: %v (data: %q)\nStderr: %s", err, data, stderr.String())
	}
	return cmd, &stderr, info, blockWriter
}

// waitCmd waits up to timeout for cmd, which runs `runsc bwrap`, to exit, and
// returns the result that done gets. If cmd does not exit in time, waitCmd
// returns false. Then it stops cmd with SIGTERM, which stops its sandbox, and
// as a last resort with SIGKILL.
func waitCmd(cmd *exec.Cmd, done <-chan error, timeout time.Duration) (bool, error) {
	select {
	case err := <-done:
		return true, err
	case <-time.After(timeout):
	}
	cmd.Process.Signal(unix.SIGTERM)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		<-done
	}
	return false, nil
}

// startWait returns a channel that gets the result of testutil.WaitCmd(cmd).
func startWait(cmd *exec.Cmd) <-chan error {
	done := make(chan error, 1)
	go func() { done <- testutil.WaitCmd(cmd) }()
	return done
}

// waitForSandbox waits until a sandbox runs in the runsc root directory root.
func waitForSandbox(t *testing.T, root string) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for {
		out, _ := exec.Command(specutils.ExePath, "--root", root, "list", "--quiet").Output()
		if len(bytes.TrimSpace(out)) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no sandbox runs in %s after a minute", root)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// checkSandboxProcess returns an error unless pid is a running sandbox
// process, which runs `runsc boot`.
func checkSandboxProcess(pid int) error {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return err
	}
	if args := strings.Split(string(data), "\x00"); !slices.Contains(args, "boot") {
		return fmt.Errorf("command line is %q, want a runsc boot command", args)
	}
	return nil
}

// pipeHolders returns the processes, other than this one and the processes
// in except, that have a descriptor for the pipe of f.
func pipeHolders(t *testing.T, f *os.File, except ...int) []int {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("pipe:[%d]", st.Ino)
	except = append(except, os.Getpid())
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || slices.Contains(except, pid) {
			continue
		}
		fds, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		for _, fd := range fds {
			if link, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())); link == want {
				pids = append(pids, pid)
				break
			}
		}
	}
	return pids
}

// TestInfoAndBlockFD checks that --info-fd reports the sandbox process once
// the sandbox runs, and that the command waits for --block-fd.
func TestInfoAndBlockFD(t *testing.T) {
	if err := testutil.ConfigureExePath(); err != nil {
		t.Fatalf("failed to configure exe path: %v", err)
	}
	stop := testutil.StartReaper()
	defer stop()

	defaultFlags := []string{"--info-fd", "3", "--block-fd", "4"}
	writeByte := func(w *os.File) error {
		_, err := w.Write([]byte("x"))
		return err
	}
	for _, tc := range []struct {
		name string
		// flags are the --info-fd and --block-fd flags, and blockFirst
		// gives the --block-fd pipe as fd 3, see runBlocked.
		flags      []string
		blockFirst bool
		// release releases --block-fd. The write end stays open unless
		// release closes it.
		release func(w *os.File) error
	}{
		{
			name:    "Data",
			flags:   defaultFlags,
			release: writeByte,
		},
		{
			name:    "EOF",
			flags:   defaultFlags,
			release: func(w *os.File) error { return w.Close() },
		},
		{
			// The --block-fd descriptor is one that --info-fd replaced.
			name:       "ReplacedInfoFD",
			flags:      []string{"--info-fd", "3", "--info-fd", "4", "--block-fd", "3"},
			blockFirst: true,
			release:    writeByte,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The command creates a file in hostDir, so its absence shows
			// that the command has not run.
			hostDir := t.TempDir()
			marker := filepath.Join(hostDir, "ran")
			cmd, stderr, info, blockWriter := runBlocked(t, blockedOpts{root: newRunRootDir(t), fdFlags: tc.flags, blockFirst: tc.blockFirst},
				"--ro-bind", "/", "/", "--bind", hostDir, "/mnt", "--", "/bin/touch", "/mnt/ran")

			pid := info["child-pid"]
			if pid <= 0 || pid == cmd.Process.Pid {
				t.Errorf("child-pid = %d, want the sandbox process, not runsc bwrap (%d)", pid, cmd.Process.Pid)
			} else if err := checkSandboxProcess(pid); err != nil {
				t.Errorf("child-pid %d is not the sandbox process: %v", pid, err)
			}

			// Give a command that does not wait time to run.
			time.Sleep(time.Second)
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("command ran before --block-fd was released: %v", err)
			}

			if err := tc.release(blockWriter); err != nil {
				t.Errorf("releasing --block-fd failed, so runsc bwrap did not wait for it: %v", err)
			}
			ok, err := waitCmd(cmd, startWait(cmd), time.Minute)
			if !ok {
				t.Fatalf("runsc bwrap still runs a minute after --block-fd was released\nStderr: %s", stderr.String())
			}
			if err != nil {
				t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
			}
			if _, err := os.Stat(marker); err != nil {
				t.Errorf("command did not run after --block-fd was released: %v", err)
			}
		})
	}

	// checkStopped checks that cmd, which runs `runsc bwrap` with root,
	// exits on its own with 128+sig, and leaves no sandbox behind.
	checkStopped := func(t *testing.T, cmd *exec.Cmd, root string, childPID int, sig unix.Signal) {
		t.Helper()
		if ok, _ := waitCmd(cmd, startWait(cmd), time.Minute); !ok {
			t.Fatalf("runsc bwrap still runs a minute after %v", sig)
		}
		if got, want := cmd.ProcessState.ExitCode(), 128+int(sig); got != want {
			t.Errorf("exit code after %v = %d, want %d", sig, got, want)
		}
		out, err := exec.Command(specutils.ExePath, "--root", root, "list", "--quiet").CombinedOutput()
		if err != nil {
			t.Fatalf("runsc list failed: %v: %s", err, out)
		}
		if got := strings.TrimSpace(string(out)); got != "" {
			t.Errorf("containers left after %v: %q", sig, got)
		}
		if childPID <= 0 {
			return
		}
		deadline := time.Now().Add(10 * time.Second)
		for unix.Kill(childPID, 0) == nil && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
		}
		if err := unix.Kill(childPID, 0); err == nil {
			t.Errorf("sandbox process %d still runs after %v", childPID, sig)
		}
	}

	// A signal while the command waits stops the sandbox.
	t.Run("Signal", func(t *testing.T) {
		for _, sig := range []unix.Signal{unix.SIGINT, unix.SIGTERM, unix.SIGHUP, unix.SIGQUIT} {
			t.Run(unix.SignalName(sig), func(t *testing.T) {
				root := newRunRootDir(t)
				cmd, _, info, _ := runBlocked(t, blockedOpts{root: root, fdFlags: defaultFlags}, "--ro-bind", "/", "/", "--", "/bin/true")
				if err := cmd.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
				checkStopped(t, cmd, root, info["child-pid"], sig)
			})
		}
	})

	// A SIGINT or SIGHUP that runsc started with ignored does not stop the
	// wait.
	t.Run("IgnoredSignal", func(t *testing.T) {
		for _, sig := range []unix.Signal{unix.SIGINT, unix.SIGHUP} {
			t.Run(unix.SignalName(sig), func(t *testing.T) {
				// The shell ignores sig, then runs `runsc bwrap` in its place.
				wrapper := []string{"/bin/sh", "-c", fmt.Sprintf(`trap '' %d; exec "$0" "$@"`, sig)}
				hostDir := t.TempDir()
				cmd, stderr, _, blockWriter := runBlocked(t, blockedOpts{root: newRunRootDir(t), fdFlags: defaultFlags, wrapper: wrapper},
					"--ro-bind", "/", "/", "--bind", hostDir, "/mnt", "--", "/bin/touch", "/mnt/ran")
				if err := cmd.Process.Signal(sig); err != nil {
					t.Fatal(err)
				}
				time.Sleep(time.Second)
				blockWriter.Close()
				if err := testutil.WaitCmd(cmd); err != nil {
					t.Fatalf("runsc bwrap failed after an ignored %v: %v\nStderr: %s", sig, err, stderr.String())
				}
				if _, err := os.Stat(filepath.Join(hostDir, "ran")); err != nil {
					t.Errorf("command did not run: %v", err)
				}
			})
		}
	})

	// --block-fd without --info-fd also holds the command back, and a signal
	// during the wait stops the sandbox.
	t.Run("BlockFDOnly", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			sig  unix.Signal
		}{
			{name: "Release"},
			{name: "Signal", sig: unix.SIGTERM},
		} {
			t.Run(tc.name, func(t *testing.T) {
				blockReader, blockWriter, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer blockWriter.Close()
				hostDir := t.TempDir()
				marker := filepath.Join(hostDir, "ran")
				root := newRunRootDir(t)
				cmd := exec.Command(specutils.ExePath, "--root", root, "bwrap", "--block-fd", "3",
					"--ro-bind", "/", "/", "--bind", hostDir, "/mnt", "--", "/bin/touch", "/mnt/ran")
				cmd.ExtraFiles = []*os.File{blockReader}
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				if err := testutil.StartCmd(cmd); err != nil {
					t.Fatal(err)
				}
				blockReader.Close()
				done := startWait(cmd)
				waitForSandbox(t, root)
				// Give a command that does not wait time to run.
				time.Sleep(time.Second)
				if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("command ran before --block-fd was released: %v", err)
				}
				if tc.sig != 0 {
					if err := cmd.Process.Signal(tc.sig); err != nil {
						t.Fatal(err)
					}
				} else {
					blockWriter.Close()
				}
				ok, err := waitCmd(cmd, done, time.Minute)
				if !ok {
					t.Fatalf("runsc bwrap still runs a minute later\nStderr: %s", stderr.String())
				}
				if tc.sig != 0 {
					if got, want := cmd.ProcessState.ExitCode(), 128+int(tc.sig); got != want {
						t.Errorf("exit code after %v = %d, want %d", tc.sig, got, want)
					}
					out, err := exec.Command(specutils.ExePath, "--root", root, "list", "--quiet").CombinedOutput()
					if err != nil || len(bytes.TrimSpace(out)) > 0 {
						t.Errorf("runsc list after %v = %q (err: %v), want no containers", tc.sig, out, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
				}
				if _, err := os.Stat(marker); err != nil {
					t.Errorf("command did not run after --block-fd was released: %v", err)
				}
			})
		}
	})

	// A signal while runsc waits to write --info-fd stops the sandbox.
	t.Run("SignalWhileInfoFDFull", func(t *testing.T) {
		var p [2]int
		if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
			t.Fatal(err)
		}
		defer unix.Close(p[0])
		buf := make([]byte, 4096)
		for {
			if _, err := unix.Write(p[1], buf); err == unix.EAGAIN {
				break
			} else if err != nil {
				t.Fatal(err)
			}
		}
		if err := unix.SetNonblock(p[1], false); err != nil {
			t.Fatal(err)
		}
		infoWriter := os.NewFile(uintptr(p[1]), "info")
		root := newRunRootDir(t)
		cmd := exec.Command(specutils.ExePath, "--root", root, "bwrap", "--info-fd", "3", "--ro-bind", "/", "/", "--", "/bin/true")
		cmd.ExtraFiles = []*os.File{infoWriter}
		if err := testutil.StartCmd(cmd); err != nil {
			t.Fatal(err)
		}
		infoWriter.Close()
		// Wait until the sandbox runs, then give runsc bwrap time to start
		// the write.
		waitForSandbox(t, root)
		time.Sleep(time.Second)
		if err := cmd.Process.Signal(unix.SIGTERM); err != nil {
			t.Fatal(err)
		}
		checkStopped(t, cmd, root, 0, unix.SIGTERM)
		// Nothing is written to --info-fd after the signal.
		for {
			n, err := unix.Read(p[0], buf)
			if err != nil || n == 0 {
				break
			}
			if bytes.Contains(buf[:n], []byte("child-pid")) {
				t.Fatalf("--info-fd got the info after SIGTERM")
			}
		}
	})

	// A replaced --info-fd descriptor does not reach the sandbox processes.
	t.Run("ReplacedFDNotInherited", func(t *testing.T) {
		replacedReader, replacedWriter, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer replacedReader.Close()
		infoReader, infoWriter, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer infoReader.Close()
		cmd := exec.Command(specutils.ExePath, "--root", newRunRootDir(t), "bwrap", "--info-fd", "4", "--info-fd", "3", "--ro-bind", "/", "/", "--", "/bin/sleep", "3")
		cmd.ExtraFiles = []*os.File{infoWriter, replacedWriter}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := testutil.StartCmd(cmd); err != nil {
			t.Fatal(err)
		}
		infoWriter.Close()
		replacedWriter.Close()
		// Once --info-fd is written, the sandbox processes run.
		if err := infoReader.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(infoReader); err != nil {
			t.Errorf("reading --info-fd: %v", err)
		}
		holders := pipeHolders(t, replacedReader, cmd.Process.Pid)
		if err := testutil.WaitCmd(cmd); err != nil {
			t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
		}
		if len(holders) > 0 {
			t.Errorf("processes %v have the replaced --info-fd descriptor, want none", holders)
		}
	})

	// The --block-fd descriptor, and one that a later --block-fd replaced,
	// do not reach the processes that run the command.
	t.Run("BlockFDNotInherited", func(t *testing.T) {
		replacedReader, replacedWriter, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer replacedWriter.Close()
		cmd, stderr, _, blockWriter := runBlocked(t, blockedOpts{
			root:    newRunRootDir(t),
			fdFlags: []string{"--info-fd", "3", "--block-fd", "5", "--block-fd", "4"},
			extra:   []*os.File{replacedReader},
		}, "--ro-bind", "/", "/", "--", "/bin/sleep", "3")
		replacedReader.Close()
		if _, err := blockWriter.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		// Give the command time to start.
		time.Sleep(time.Second)
		holders := pipeHolders(t, blockWriter, cmd.Process.Pid)
		replacedHolders := pipeHolders(t, replacedWriter, cmd.Process.Pid)
		if err := testutil.WaitCmd(cmd); err != nil {
			t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
		}
		if len(holders) > 0 {
			t.Errorf("processes %v have the --block-fd descriptor, want none", holders)
		}
		if len(replacedHolders) > 0 {
			t.Errorf("processes %v have the replaced --block-fd descriptor, want none", replacedHolders)
		}
	})

	// run runs `runsc bwrap` with bwrapArgs, extra files as fds 3 and up,
	// and stdin, and returns its output.
	run := func(t *testing.T, stdin string, extra []*os.File, bwrapArgs ...string) (string, string, error) {
		t.Helper()
		cmd := exec.Command(specutils.ExePath, append([]string{"--root", newRunRootDir(t), "bwrap"}, bwrapArgs...)...)
		cmd.ExtraFiles = extra
		cmd.Stdin = strings.NewReader(stdin)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := testutil.RunCmd(cmd)
		return stdout.String(), stderr.String(), err
	}

	// A --block-fd that cannot be read releases the command at once.
	t.Run("UnreadableBlockFD", func(t *testing.T) {
		writeOnly, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer writeOnly.Close()
		for _, fd := range []string{"3", "9"} {
			stdout, stderr, err := run(t, "", []*os.File{writeOnly}, "--block-fd", fd, "--ro-bind", "/", "/", "--", "/bin/echo", "ran")
			if err != nil || stdout != "ran\n" {
				t.Errorf("--block-fd %s: stdout = %q, err = %v, want \"ran\\n\" and no error\nStderr: %s", fd, stdout, err, stderr)
			}
		}
	})

	// One read-write descriptor can serve as both flags. Writing the info
	// closes it, which releases the command even though the peer never
	// writes.
	t.Run("SameFD", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		// runsc bwrap gets a blocking end. The test's end is non-blocking,
		// which read deadlines need.
		if err := unix.SetNonblock(fds[0], true); err != nil {
			t.Fatal(err)
		}
		peer := os.NewFile(uintptr(fds[0]), "peer")
		defer peer.Close()
		sock := os.NewFile(uintptr(fds[1]), "sock")
		cmd := exec.Command(specutils.ExePath, "--root", newRunRootDir(t), "bwrap", "--info-fd", "3", "--block-fd", "3", "--ro-bind", "/", "/", "--", "/bin/echo", "ran")
		cmd.ExtraFiles = []*os.File{sock}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := testutil.StartCmd(cmd); err != nil {
			t.Fatal(err)
		}
		sock.Close()
		ok, err := waitCmd(cmd, startWait(cmd), time.Minute)
		if !ok {
			t.Fatalf("runsc bwrap still runs after a minute\nStderr: %s", stderr.String())
		}
		if err != nil || stdout.String() != "ran\n" {
			t.Errorf("stdout = %q, err = %v, want \"ran\\n\" and no error\nStderr: %s", stdout.String(), err, stderr.String())
		}
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if data, err := io.ReadAll(peer); err != nil || !strings.Contains(string(data), "child-pid") {
			t.Errorf("--info-fd socket = %q (err: %v), want a child-pid", data, err)
		}
	})

	// A repeated flag uses its last descriptor, also when the descriptor
	// is one that the other flag or the same flag gave before.
	t.Run("RepeatedFD", func(t *testing.T) {
		readOnly, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer readOnly.Close()
		for _, flags := range [][]string{
			{"--info-fd", "3", "--info-fd", "3"},
			{"--block-fd", "3", "--block-fd", "4", "--info-fd", "3"},
		} {
			f, err := os.CreateTemp(t.TempDir(), "info")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			args := append(flags, "--ro-bind", "/", "/", "--", "/bin/echo", "ran")
			stdout, stderr, err := run(t, "", []*os.File{f, readOnly}, args...)
			if err != nil || stdout != "ran\n" {
				t.Errorf("%v: stdout = %q, err = %v, want \"ran\\n\" and no error\nStderr: %s", flags, stdout, err, stderr)
			}
			if data, err := os.ReadFile(f.Name()); err != nil || !strings.Contains(string(data), "child-pid") {
				t.Errorf("%v: --info-fd file = %q (err: %v), want a child-pid", flags, data, err)
			}
		}
	})

	// --info-fd 1 reaches end of file once the info is written, before
	// --block-fd is released and while the command runs.
	t.Run("InfoFDStdoutEOF", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		blockReader, blockWriter, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer blockWriter.Close()
		cmd := exec.Command(specutils.ExePath, "--root", newRunRootDir(t), "bwrap", "--info-fd", "1", "--block-fd", "3", "--ro-bind", "/", "/", "--", "/bin/sleep", "5")
		cmd.Stdout = w
		cmd.ExtraFiles = []*os.File{blockReader}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := testutil.StartCmd(cmd); err != nil {
			t.Fatal(err)
		}
		w.Close()
		blockReader.Close()
		if err := r.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		blockWriter.Close()
		eof := time.Now()
		if err := testutil.WaitCmd(cmd); err != nil {
			t.Fatalf("runsc bwrap failed: %v\nStderr: %s", err, stderr.String())
		}
		if err != nil || !strings.Contains(string(data), "child-pid") {
			t.Errorf("stdout = %q (err: %v), want a child-pid", data, err)
		}
		if d := time.Since(eof); d < 3*time.Second {
			t.Errorf("runsc bwrap exited %v after stdout reached end of file, want the command to run 5s after it", d)
		}
	})

	// A stdio descriptor used as --info-fd or --block-fd is /dev/null to the
	// command.
	t.Run("Stdio", func(t *testing.T) {
		stdout, stderr, err := run(t, "abc", nil, "--block-fd", "0", "--ro-bind", "/", "/", "--", "/bin/cat")
		if err != nil || stdout != "" {
			t.Errorf("--block-fd 0: stdout = %q, err = %v, want no output and no error\nStderr: %s", stdout, err, stderr)
		}
		stdout, stderr, err = run(t, "", nil, "--info-fd", "1", "--ro-bind", "/", "/", "--", "/bin/echo", "ran")
		if err != nil || !strings.Contains(stdout, "child-pid") || strings.Contains(stdout, "ran") {
			t.Errorf("--info-fd 1: stdout = %q, err = %v, want only the JSON object and no error\nStderr: %s", stdout, err, stderr)
		}
		// runsc still reports errors on a stdio descriptor that it uses.
		missing := filepath.Join(t.TempDir(), "missing")
		if _, stderr, err := run(t, "", nil, "--block-fd", "2", "--ro-bind", "/", "/", "--ro-bind", missing, "/mnt", "--", "/bin/true"); err == nil || !strings.Contains(stderr, missing) {
			t.Errorf("--block-fd 2 with a missing bind source: err = %v, stderr = %q, want an error that names %s", err, stderr, missing)
		}
	})

	t.Run("InvalidInfoFD", func(t *testing.T) {
		readOnly, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		defer readOnly.Close()
		pipeReader, pipeWriter, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer pipeReader.Close()
		defer pipeWriter.Close()
		for _, tc := range []struct {
			name  string
			extra []*os.File
			want  string
		}{
			// runsc opens its own descriptors, fd 3 included, close-on-exec.
			{name: "NotInherited", want: "Invalid --info-fd 3"},
			{name: "ReadOnly", extra: []*os.File{readOnly}, want: "failed to write to --info-fd"},
			// poll never reports a read-only pipe as ready to write.
			{name: "ReadOnlyPipe", extra: []*os.File{pipeReader}, want: "failed to write to --info-fd"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, stderr, err := run(t, "", tc.extra, "--info-fd", "3", "--ro-bind", "/", "/", "--", "/bin/true")
				if err == nil {
					t.Fatalf("runsc bwrap succeeded")
				}
				if !strings.Contains(stderr, tc.want) {
					t.Errorf("stderr = %q, want it to contain %q", stderr, tc.want)
				}
			})
		}
	})

	// A descriptor that a global runsc flag gives runsc is not available.
	t.Run("RunscFD", func(t *testing.T) {
		logFile, err := os.CreateTemp(t.TempDir(), "log")
		if err != nil {
			t.Fatal(err)
		}
		defer logFile.Close()
		cmd := exec.Command(specutils.ExePath, "--root", newRunRootDir(t), "--log-fd=3", "bwrap", "--info-fd", "3", "--ro-bind", "/", "/", "--", "/bin/true")
		cmd.ExtraFiles = []*os.File{logFile}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := testutil.RunCmd(cmd); err == nil {
			t.Fatalf("runsc bwrap succeeded")
		}
		if want := "runsc uses it for --log-fd"; !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr.String(), want)
		}
	})
}
