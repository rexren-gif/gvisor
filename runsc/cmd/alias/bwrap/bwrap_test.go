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
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

// sudoUID and sudoGID are pinned into SUDO_UID and SUDO_GID so that the
// mappings --unshare-user produces are deterministic.
const (
	sudoUID = 4242
	sudoGID = 4343
)

// permsPtr returns a pointer to perms, for sandbox.Mount.Mode.
func permsPtr(perms uint32) *uint32 { return &perms }

// wantIDMappings returns the mappings bwrap is expected to build for an
// unshared user namespace that runs as containerID.
func wantIDMappings(containerID, hostID uint32) []specs.LinuxIDMapping {
	mappings := []specs.LinuxIDMapping{
		{ContainerID: containerID, HostID: hostID, Size: 1},
	}
	// Running as root, the gofer needs container 0 mapped to host 0 as well.
	if os.Getuid() == 0 && containerID != 0 {
		mappings = append(mappings, specs.LinuxIDMapping{ContainerID: 0, HostID: 0, Size: 1})
	}
	return mappings
}

// TestSandboxOptions checks the bubblewrap configuration is translated into
// the OCI specification the sandbox bindings build from it.
func TestSandboxOptions(t *testing.T) {
	t.Setenv("SUDO_UID", strconv.Itoa(sudoUID))
	t.Setenv("SUDO_GID", strconv.Itoa(sudoGID))

	// defaultMounts are the filesystems bwrap asks for in every sandbox, as
	// they appear in the specification.
	defaultMounts := []specs.Mount{
		{Type: "proc", Destination: "/proc"},
		{Type: "sysfs", Destination: "/sys"},
		{Type: "devtmpfs", Destination: "/dev"},
		{Type: "devpts", Destination: "/dev/pts"},
		{Type: "cgroupfs", Destination: "/sys/fs/cgroup"},
		{Type: "tmpfs", Destination: "/tmp"},
	}
	appendMounts := func(mounts ...[]specs.Mount) []specs.Mount {
		var result []specs.Mount
		for _, m := range mounts {
			result = append(result, m...)
		}
		return result
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	tests := []struct {
		name        string
		cfg         *bwrapConfig
		wantSpec    specs.Spec
		errContains string
	}{
		{
			name: "WithRootMount",
			cfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeBind, Source: "/src1", Destination: "/dst1"},
					{Type: sandbox.MountTypeBind, Source: "/", Destination: "/", ReadOnly: true, Recursive: true, Private: true, NoSuid: true, NoDev: true},
					{Type: sandbox.MountTypeTmpfs, Destination: "/tmp"},
				},
				UnshareNet: true,
				Args:       []string{"/bin/bash"},
			},
			wantSpec: specs.Spec{
				Root: &specs.Root{Path: "/", Readonly: true},
				// As `/` is binded, the cwd is picked as the container CWD.
				Process: &specs.Process{Cwd: cwd},
				// The root bind hides the earlier mount at /dst1, and the tmpfs
				// at /tmp hides the default one.
				Mounts: appendMounts(
					defaultMounts[:len(defaultMounts)-1],
					[]specs.Mount{{
						Type:        "bind",
						Source:      "/",
						Destination: "/",
						Options:     []string{"rbind", "rprivate", "nosuid", "nodev", "ro"},
					}},
					[]specs.Mount{{Type: "tmpfs", Destination: "/tmp"}},
				),
				Linux: &specs.Linux{},
			},
		},
		{
			name: "NoMountsNoNetNS",
			cfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"ls"},
			},
			wantSpec: specs.Spec{
				// No root mount, so the sandbox gets an empty root directory.
				Root:    &specs.Root{Path: "rootfs"},
				Process: &specs.Process{Cwd: "/"},
				Mounts: appendMounts(
					[]specs.Mount{{Type: "tmpfs", Destination: "/"}},
					defaultMounts,
				),
				Linux: &specs.Linux{},
			},
		},
		{
			name: "UnshareUserWithUIDAndGID",
			cfg: &bwrapConfig{
				Env:         os.Environ(),
				UID:         1234,
				GID:         5678,
				UnshareUser: true,
				Args:        []string{"id"},
			},
			wantSpec: specs.Spec{
				Root:    &specs.Root{Path: "rootfs"},
				Process: &specs.Process{Cwd: "/", User: specs.User{UID: 1234, GID: 5678}},
				Mounts: appendMounts(
					[]specs.Mount{{Type: "tmpfs", Destination: "/"}},
					defaultMounts,
				),
				Linux: &specs.Linux{
					Namespaces:  []specs.LinuxNamespace{{Type: specs.UserNamespace}},
					UIDMappings: wantIDMappings(1234, sudoUID),
					GIDMappings: wantIDMappings(5678, sudoGID),
				},
			},
		},
		{
			name: "ReadOnlyTmpfsRoot",
			cfg: &bwrapConfig{
				Env:               os.Environ(),
				UID:               -1,
				GID:               -1,
				Args:              []string{"ls"},
				TmpfsRootReadOnly: true,
			},
			wantSpec: specs.Spec{
				Root:    &specs.Root{Path: "rootfs"},
				Process: &specs.Process{Cwd: "/"},
				Mounts: appendMounts(
					[]specs.Mount{{Type: "tmpfs", Destination: "/", Options: []string{"ro"}}},
					defaultMounts,
				),
				Linux: &specs.Linux{},
			},
		},
		{
			// A root bind replaces the tmpfs root, so TmpfsRootReadOnly does
			// not apply.
			name: "ReadOnlyTmpfsRootWithRootBind",
			cfg: &bwrapConfig{
				Env:               os.Environ(),
				UID:               -1,
				GID:               -1,
				Mounts:            []sandbox.Mount{{Type: sandbox.MountTypeBind, Source: "/", Destination: "/"}},
				Args:              []string{"ls"},
				TmpfsRootReadOnly: true,
			},
			wantSpec: specs.Spec{
				Root:    &specs.Root{Path: "/"},
				Process: &specs.Process{Cwd: cwd},
				Mounts: appendMounts(
					defaultMounts,
					[]specs.Mount{{Type: "bind", Source: "/", Destination: "/"}},
				),
				Linux: &specs.Linux{},
			},
		},
		{
			// Mounts stack in command-line order, so the last mount at "/"
			// is the root.
			name: "LastRootMount",
			cfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeBind, Source: "/src1", Destination: "/"},
					{Type: sandbox.MountTypeBind, Source: "/src2", Destination: "/", ReadOnly: true},
				},
				Args: []string{"ls"},
			},
			wantSpec: specs.Spec{
				Root:    &specs.Root{Path: "/src2", Readonly: true},
				Process: &specs.Process{Cwd: "/"},
				Mounts: appendMounts(
					defaultMounts,
					[]specs.Mount{{Type: "bind", Source: "/src2", Destination: "/", Options: []string{"ro"}}},
				),
				Linux: &specs.Linux{},
			},
		},
		{
			// A tmpfs at "/" after the root bind replaces it as the root.
			name: "RootBindThenTmpfs",
			cfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeBind, Source: "/src1", Destination: "/"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/"},
				},
				Args: []string{"ls"},
			},
			wantSpec: specs.Spec{
				Root:    &specs.Root{Path: "rootfs"},
				Process: &specs.Process{Cwd: "/"},
				Mounts: appendMounts(
					[]specs.Mount{{Type: "tmpfs", Destination: "/"}},
					defaultMounts,
				),
				Linux: &specs.Linux{},
			},
		},
		{
			// A later mount at or above DEST hides a mount, so it is left
			// out. A mount on the command line hides the default mounts it
			// covers.
			name: "HiddenMounts",
			cfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeBind, Source: "/src1", Destination: "/mnt/sub"},
					{Type: sandbox.MountTypeBind, Source: "/src2", Destination: "/opt"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt", ReadOnly: true},
					{Type: sandbox.MountTypeBind, Source: "/src3", Destination: "/opt", ReadOnly: true},
					{Type: sandbox.MountTypeTmpfs, Destination: "/sys"},
				},
				Args: []string{"ls"},
			},
			wantSpec: specs.Spec{
				Root:    &specs.Root{Path: "rootfs"},
				Process: &specs.Process{Cwd: "/"},
				Mounts: []specs.Mount{
					{Type: "tmpfs", Destination: "/"},
					{Type: "proc", Destination: "/proc"},
					{Type: "devtmpfs", Destination: "/dev"},
					{Type: "devpts", Destination: "/dev/pts"},
					{Type: "tmpfs", Destination: "/tmp"},
					{Type: "tmpfs", Destination: "/mnt", Options: []string{"ro"}},
					{Type: "bind", Source: "/src3", Destination: "/opt", Options: []string{"ro"}},
					{Type: "tmpfs", Destination: "/sys"},
				},
				Linux: &specs.Linux{},
			},
		},
		{
			// A --dir stands for a directory, so the later root bind hides
			// it.
			name: "HiddenDirStandIn",
			cfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeTmpfs, Destination: "/foo"},
					{Type: sandbox.MountTypeBind, Source: "/src1", Destination: "/", ReadOnly: true},
					{Type: sandbox.MountTypeTmpfs, Destination: "/bar"},
				},
				dirMounts: map[int]bool{0: true, 2: true},
				Args:      []string{"ls"},
			},
			wantSpec: specs.Spec{
				Root:    &specs.Root{Path: "/src1", Readonly: true},
				Process: &specs.Process{Cwd: "/"},
				Mounts: appendMounts(
					defaultMounts,
					[]specs.Mount{
						{Type: "bind", Source: "/src1", Destination: "/", Options: []string{"ro"}},
						{Type: "tmpfs", Destination: "/bar"},
					},
				),
				Linux: &specs.Linux{},
			},
		},
		{
			// The root bind hides the earlier tmpfs at /tmp, which then
			// does not hide the default /tmp.
			name: "HiddenMountDoesNotHideDefault",
			cfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeTmpfs, Destination: "/tmp"},
					{Type: sandbox.MountTypeBind, Source: "/src1", Destination: "/", ReadOnly: true},
				},
				Args: []string{"ls"},
			},
			wantSpec: specs.Spec{
				Root:    &specs.Root{Path: "/src1", Readonly: true},
				Process: &specs.Process{Cwd: "/"},
				Mounts: appendMounts(
					defaultMounts,
					[]specs.Mount{{Type: "bind", Source: "/src1", Destination: "/", Options: []string{"ro"}}},
				),
				Linux: &specs.Linux{},
			},
		},
		{
			// runsc adds a devpts at /dev/pts when the specification has
			// none, so the default stays, read-only like the tmpfs over it.
			name: "DevPtsUnderReadOnlyTmpfs",
			cfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/dev", ReadOnly: true}},
				Args:   []string{"ls"},
			},
			wantSpec: specs.Spec{
				Root:    &specs.Root{Path: "rootfs"},
				Process: &specs.Process{Cwd: "/"},
				Mounts: []specs.Mount{
					{Type: "tmpfs", Destination: "/"},
					{Type: "proc", Destination: "/proc"},
					{Type: "sysfs", Destination: "/sys"},
					{Type: "devpts", Destination: "/dev/pts", Options: []string{"ro"}},
					{Type: "cgroupfs", Destination: "/sys/fs/cgroup"},
					{Type: "tmpfs", Destination: "/tmp"},
					{Type: "tmpfs", Destination: "/dev", Options: []string{"ro"}},
				},
				Linux: &specs.Linux{},
			},
		},
		{
			// A devpts on the command line replaces the default one.
			name: "DevPtsFromCommandLine",
			cfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeDevtmpfs, Destination: "/dev"},
					{Type: sandbox.MountTypeDevpts, Destination: "/dev/pts"},
				},
				Args: []string{"ls"},
			},
			wantSpec: specs.Spec{
				Root:    &specs.Root{Path: "rootfs"},
				Process: &specs.Process{Cwd: "/"},
				Mounts: []specs.Mount{
					{Type: "tmpfs", Destination: "/"},
					{Type: "proc", Destination: "/proc"},
					{Type: "sysfs", Destination: "/sys"},
					{Type: "cgroupfs", Destination: "/sys/fs/cgroup"},
					{Type: "tmpfs", Destination: "/tmp"},
					{Type: "devtmpfs", Destination: "/dev"},
					{Type: "devpts", Destination: "/dev/pts"},
				},
				Linux: &specs.Linux{},
			},
		},
		{
			name: "ReadOnlyDefaults",
			cfg: &bwrapConfig{
				Env:              os.Environ(),
				UID:              -1,
				GID:              -1,
				Args:             []string{"ls"},
				ReadOnlyDefaults: []string{"/dev", "/tmp"},
			},
			wantSpec: specs.Spec{
				Root:    &specs.Root{Path: "rootfs"},
				Process: &specs.Process{Cwd: "/"},
				Mounts: []specs.Mount{
					{Type: "tmpfs", Destination: "/"},
					{Type: "proc", Destination: "/proc"},
					{Type: "sysfs", Destination: "/sys"},
					{Type: "devtmpfs", Destination: "/dev", Options: []string{"ro"}},
					{Type: "devpts", Destination: "/dev/pts"},
					{Type: "cgroupfs", Destination: "/sys/fs/cgroup"},
					{Type: "tmpfs", Destination: "/tmp", Options: []string{"ro"}},
				},
				Linux: &specs.Linux{},
			},
		},
		{
			name: "UIDWithoutUnshareUser",
			cfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  1000,
				GID:  -1,
				Args: []string{"ls"},
			},
			errContains: "--uid requires --unshare-user",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.runscConfig = &config.Config{}
			opts, err := tc.cfg.prepareSandbox()
			if tc.errContains != "" {
				if err == nil {
					t.Fatalf("got nil, want error containing: %v", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("got error %v, want error containing %v", err, tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("prepareSandbox failed: %v", err)
			}
			got, err := sandbox.DebugSpec(opts...)
			if err != nil {
				t.Fatalf("sandbox.DebugSpec failed: %v", err)
			}

			if got.Process.Capabilities == nil {
				t.Errorf("specification has no capabilities set")
			}
			if diff := cmp.Diff(got.Process.Env, tc.cfg.Env); diff != "" {
				t.Errorf("Environment mismatch (-got +want):\n%s", diff)
			}

			diff := cmp.Diff(got, &tc.wantSpec,
				cmpopts.IgnoreFields(specs.Process{}, "Capabilities", "Env", "Args"),
				cmpopts.IgnoreFields(specs.Spec{}, "Version"),
				cmpopts.SortSlices(func(a, b specs.LinuxNamespace) bool {
					if a.Type != b.Type {
						return a.Type < b.Type
					}
					return a.Path < b.Path
				}),
			)
			if diff != "" {
				t.Errorf("Specification mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func TestSandboxOptionsSudoIDs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     map[string]string
		wantUID uint32
		wantGID uint32
		wantErr error
	}{
		{
			name:    "unset",
			wantUID: uint32(os.Getuid()),
			wantGID: uint32(os.Getgid()),
		},
		{
			name:    "sudo_user",
			env:     map[string]string{"SUDO_UID": "4242", "SUDO_GID": "4343"},
			wantUID: 4242,
			wantGID: 4343,
		},
		{
			name:    "plus_and_leading_zeros",
			env:     map[string]string{"SUDO_UID": "+0001", "SUDO_GID": "+0002"},
			wantUID: 1,
			wantGID: 2,
		},
		{
			name:    "largest_valid_id",
			env:     map[string]string{"SUDO_UID": "4294967294", "SUDO_GID": "4294967294"},
			wantUID: 4294967294,
			wantGID: 4294967294,
		},
		{name: "empty_uid", env: map[string]string{"SUDO_UID": ""}, wantErr: strconv.ErrSyntax},
		{name: "empty_gid", env: map[string]string{"SUDO_GID": ""}, wantErr: strconv.ErrSyntax},
		{name: "negative_uid", env: map[string]string{"SUDO_UID": "-1"}, wantErr: strconv.ErrRange},
		{name: "negative_gid", env: map[string]string{"SUDO_GID": "-1"}, wantErr: strconv.ErrRange},
		{name: "oversized_uid", env: map[string]string{"SUDO_UID": "4294967296"}, wantErr: strconv.ErrRange},
		{name: "oversized_gid", env: map[string]string{"SUDO_GID": "4294967296"}, wantErr: strconv.ErrRange},
		{name: "reserved_uid", env: map[string]string{"SUDO_UID": "4294967295"}, wantErr: strconv.ErrRange},
		{name: "reserved_gid", env: map[string]string{"SUDO_GID": "4294967295"}, wantErr: strconv.ErrRange},
		{name: "malformed_uid", env: map[string]string{"SUDO_UID": "not-an-id"}, wantErr: strconv.ErrSyntax},
		{name: "malformed_gid", env: map[string]string{"SUDO_GID": "not-an-id"}, wantErr: strconv.ErrSyntax},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range []string{"SUDO_UID", "SUDO_GID"} {
				value, ok := tc.env[key]
				t.Setenv(key, value)
				if !ok {
					if err := os.Unsetenv(key); err != nil {
						t.Fatal(err)
					}
				}
			}
			cfg := bwrapConfig{UnshareUser: true, runscConfig: &config.Config{}}
			if tc.wantErr != nil {
				cfg.HostDirs = []HostDir{{Path: filepath.Join(t.TempDir(), "new"), Perms: 0700}}
			}
			opts, err := cfg.prepareSandbox()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("prepareSandbox() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil {
				if _, err := os.Stat(cfg.HostDirs[0].Path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("host directory after rejected IDs: got %v, want %v", err, os.ErrNotExist)
				}
				return
			}
			spec, err := sandbox.DebugSpec(opts...)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := spec.Linux.UIDMappings, wantIDMappings(0, tc.wantUID); !cmp.Equal(got, want) {
				t.Errorf("UID mappings = %v, want %v", got, want)
			}
			if got, want := spec.Linux.GIDMappings, wantIDMappings(0, tc.wantGID); !cmp.Equal(got, want) {
				t.Errorf("GID mappings = %v, want %v", got, want)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	mntSrc, err := os.MkdirTemp("", "src")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(mntSrc)
	})

	tests := []struct {
		name        string
		args        []string
		wantArgs    []string
		errContains string
	}{
		{
			name:     "NoFlags",
			args:     []string{"bash"},
			wantArgs: []string{"bash"},
		},
		{
			name:     "WithFlags",
			args:     []string{"--unshare-net", "--chdir", "/tmp", "--bind", mntSrc, "dst", "bash"},
			wantArgs: []string{"bash"},
		},
		{
			name:     "WithDelimiter",
			args:     []string{"--unshare-net", "--", "bash", "--bash-args"},
			wantArgs: []string{"bash", "--bash-args"},
		},
		{
			name:        "UnknownFlag",
			args:        []string{"--unknown", "bash"},
			errContains: "Unknown option: --unknown",
		},
		{
			name:        "SingleDashFlag",
			args:        []string{"-u", "bash"},
			errContains: "Unknown option: -u",
		},
		{
			name:        "EmptyArgs",
			args:        []string{},
			errContains: "bwrap: no command specified",
		},
		{
			name:        "MissingArgs",
			args:        []string{""},
			errContains: "bwrap: no command specified",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseBwrapArgs(tc.args)
			wantError := tc.errContains != ""
			if wantError {
				if err == nil {
					t.Fatalf("got nil, want error containing: %v", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("got error %v, want error containing %v", err, tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if len(cfg.Args) != len(tc.wantArgs) {
				t.Fatalf("Args length mismatch: got %v, want %v", len(cfg.Args), len(tc.wantArgs))
			}
			for i, arg := range cfg.Args {
				if arg != tc.wantArgs[i] {
					t.Fatalf("Args[%d] mismatch: got %v, want %v", i, arg, tc.wantArgs[i])
				}
			}
		})
	}
}

func TestSubDirPath(t *testing.T) {
	cfg := &bwrapConfig{}
	tests := []struct {
		parent string
		child  string
		want   string
		ok     bool
	}{
		// Standard
		{parent: "/a/b", child: "/a/b/c", want: "/a/b/c", ok: true},
		{parent: "/a/b", child: "/a/b", want: "/a/b", ok: true},
		{parent: "/a/b/c", child: "/a/b"},

		// Traps & Traversal
		{parent: "/app", child: "/app_backup/data"},                      // Substring, not a subpath
		{parent: "/a/b", child: "/a/b/../../c"},                          // Traverse outside of parent.
		{parent: "/a/b/../c", child: "/a/c/d", want: "/a/c/d", ok: true}, // Parent uses ..

		// Naming Edge Cases
		{parent: "/var", child: "/var/..a/file", want: "/var/..a/file", ok: true},   // Dir named ..a
		{parent: "/usr/...", child: "/usr/.../bin", want: "/usr/.../bin", ok: true}, // Dir named ...

		// Messy Formatting & Roots
		{parent: "/a///b/.", child: "/a////b/c", want: "/a/b/c", ok: true},           // Messy strings
		{parent: "/", child: "/opt/app", want: "/opt/app", ok: true},                 // Root to dir
		{parent: "/", child: "/", want: "/", ok: true},                               // Root to root
		{parent: ".", child: "testdir/file.txt", want: "testdir/file.txt", ok: true}, // Relative paths

		// Empty Cases
		{parent: "", child: "", ok: false},
		{parent: "", child: "test", ok: false},
		{parent: "/a/b", child: ""},
	}

	for _, test := range tests {
		got, ok := cfg.subDirPath(test.parent, test.child)
		if ok != test.ok || got != test.want {
			t.Errorf("cfg.subDirPath(%q, %q): got %q, %v; want %q, %v",
				test.parent, test.child, got, ok, test.want, test.ok)
		}
	}
}

// TestParseFlags tests the parsing of bwrap flags.
func TestParseFlags(t *testing.T) {
	// mntSrc is a host directory for --bind and --ro-bind sources.
	mntSrc := t.TempDir()
	// rootBind is the mount --ro-bind / / produces.
	rootBind := sandbox.Mount{Type: sandbox.MountTypeBind, Source: "/", Destination: "/", ReadOnly: true, Recursive: true, Private: true, NoSuid: true, NoDev: true}

	tests := []struct {
		name        string
		args        []string
		wantCfg     *bwrapConfig
		errContains string
	}{
		{
			name: "ClearEnv",
			args: []string{"--clearenv", "bash"},
			wantCfg: &bwrapConfig{
				Env:  []string{"PWD=/"},
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "SetEnv",
			args: []string{"--setenv", "FOO", "bar", "bash"},
			wantCfg: &bwrapConfig{
				Env:  append(os.Environ(), "FOO=bar"),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "UnsetEnv",
			args: []string{"--unsetenv", "FOO", "bash"},
			wantCfg: &bwrapConfig{
				Env:      os.Environ(),
				UnsetEnv: []string{"FOO"},
				UID:      -1,
				GID:      -1,
				Args:     []string{"bash"},
			},
		},
		{
			name: "UnshareUser",
			args: []string{"--unshare-user", "bash"},
			wantCfg: &bwrapConfig{
				Env:         os.Environ(),
				UID:         -1,
				GID:         -1,
				UnshareUser: true,
				Args:        []string{"bash"},
			},
		},
		{
			name: "UID",
			args: []string{"--unshare-user", "--uid", "0", "--gid", "0", "bash"},
			wantCfg: &bwrapConfig{
				Env:         os.Environ(),
				UID:         0,
				GID:         0,
				UnshareUser: true,
				Args:        []string{"bash"},
			},
		},
		{
			name:        "Userns",
			args:        []string{"--userns", "3", "bash"},
			errContains: "--userns is currently not supported by runsc",
		},
		{
			name:        "ShareNet",
			args:        []string{"--share-net", "bash"},
			errContains: "--share-net is currently not supported by runsc",
		},
		{
			name: "UnshareIPC",
			args: []string{"--unshare-ipc", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "UnsharePID",
			args: []string{"--unshare-pid", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "UnshareUTS",
			args: []string{"--unshare-uts", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "NewSession",
			args: []string{"--new-session", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "DieWithParent",
			args: []string{"--die-with-parent", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name: "AsPID1",
			args: []string{"--as-pid-1", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				AsPID1: true,
				Args:   []string{"bash"},
			},
		},
		{
			name: "ValidHostname",
			args: []string{"--hostname", "test-host", "bash"},
			wantCfg: &bwrapConfig{
				Env:      os.Environ(),
				UID:      -1,
				GID:      -1,
				Hostname: "test-host",
				Args:     []string{"bash"},
			},
		},
		{
			name:        "MissingHostname",
			args:        []string{"--hostname"},
			errContains: "--hostname takes 1 argument",
		},
		{
			name: "SingleProc",
			args: []string{"--proc", "/proc1", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeProc, Destination: "/proc1"},
				},
			},
		},
		{
			name: "DeduplicatedProc",
			args: []string{"--proc", "/proc1", "--proc", "/proc1", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeProc, Destination: "/proc1"},
				},
			},
		},
		{
			name: "MultipleProc",
			args: []string{"--proc", "/proc1", "--proc", "/proc2", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeProc, Destination: "/proc1"},
					{Type: sandbox.MountTypeProc, Destination: "/proc2"},
				},
			},
		},
		{
			name: "Dev",
			args: []string{"--dev", "/dev1/", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeDevtmpfs, Destination: "/dev1"},
					{Type: sandbox.MountTypeDevpts, Destination: "/dev1/pts"},
				},
			},
		},
		{
			name: "DeduplicatedDev",
			args: []string{"--dev", "/dev1", "--dev", "/dev1", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeDevtmpfs, Destination: "/dev1"},
					{Type: sandbox.MountTypeDevpts, Destination: "/dev1/pts"},
				},
			},
		},
		{
			name:        "MissingDevArg",
			args:        []string{"--dev"},
			errContains: "--dev takes 1 argument",
		},
		{
			name: "CapDrop",
			args: []string{"--cap-drop", "all", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				CapOps: []*CapOp{
					{Type: CapOpDrop, Cap: "all"},
				},
			},
		},
		{
			name: "CapAddAndDrop",
			args: []string{"--cap-drop", "all", "--cap-add", "net_admin", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
				CapOps: []*CapOp{
					{Type: CapOpDrop, Cap: "all"},
					{Type: CapOpAdd, Cap: "net_admin"},
				},
			},
		},
		{
			name:        "MissingCapAddArg",
			args:        []string{"--cap-add"},
			errContains: "--cap-add takes 1 argument",
		},
		{
			name:        "MissingCapDropArg",
			args:        []string{"--cap-drop"},
			errContains: "--cap-drop takes 1 argument",
		},
		{
			name: "Argv0",
			args: []string{"--argv0", "custom-sh", "bash"},
			wantCfg: &bwrapConfig{
				Env:   os.Environ(),
				UID:   -1,
				GID:   -1,
				Argv0: "custom-sh",
				Args:  []string{"bash"},
			},
		},
		{
			name:        "MissingArgv0Arg",
			args:        []string{"--argv0"},
			errContains: "--argv0 takes one argument",
		},
		{
			name:        "DuplicateArgv0",
			args:        []string{"--argv0", "foo", "--argv0", "bar", "bash"},
			errContains: "--argv0 used multiple times",
		},
		{
			name:        "EmptyArgv0",
			args:        []string{"--argv0", "", "bash"},
			errContains: "--argv0 does not support an empty value",
		},
		{
			name: "PermsTmpfs",
			args: []string{"--perms", "0700", "--tmpfs", "/foo", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/foo", Mode: permsPtr(0700)}},
				Args:   []string{"bash"},
			},
		},
		{
			// Without --perms the mount carries no mode, leaving gVisor's tmpfs
			// default of 01777 in place.
			name: "TmpfsDefaultPerms",
			args: []string{"--tmpfs", "/foo", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/foo"}},
				Args:   []string{"bash"},
			},
		},
		{
			name: "PermsDir",
			args: []string{"--perms", "0700", "--dir", "/foo", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/foo", Mode: permsPtr(0700)}},
				Args:   []string{"bash"},
			},
		},
		{
			// With no bind mount behind it, --dir becomes a tmpfs mount. Without
			// --perms it carries no mode, leaving gVisor's tmpfs default of 01777
			// in place.
			name: "DirDefaultPerms",
			args: []string{"--dir", "/foo", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/foo"}},
				Args:   []string{"bash"},
			},
		},
		{
			// A bind mount behind DEST makes --dir a host directory with
			// bubblewrap's default mode rather than a tmpfs mount.
			name: "DirUnderBind",
			args: []string{"--bind", mntSrc, "/mnt", "--dir", "/mnt/new", "bash"},
			wantCfg: &bwrapConfig{
				Env:      os.Environ(),
				UID:      -1,
				GID:      -1,
				Mounts:   []sandbox.Mount{{Type: sandbox.MountTypeBind, Source: mntSrc, Destination: "/mnt"}},
				HostDirs: []HostDir{{Dest: "/mnt/new", Path: mntSrc + "/new", Perms: 0755}},
				Args:     []string{"bash"},
			},
		},
		{
			name: "PermsDirUnderBind",
			args: []string{"--bind", mntSrc, "/mnt", "--perms", "0700", "--dir", "/mnt/new", "bash"},
			wantCfg: &bwrapConfig{
				Env:      os.Environ(),
				UID:      -1,
				GID:      -1,
				Mounts:   []sandbox.Mount{{Type: sandbox.MountTypeBind, Source: mntSrc, Destination: "/mnt"}},
				HostDirs: []HostDir{{Dest: "/mnt/new", Path: mntSrc + "/new", Perms: 0700}},
				Args:     []string{"bash"},
			},
		},
		{
			name: "DirUnderReadOnlyBind",
			args: []string{"--ro-bind", "/", "/", "--dir", "/usr", "bash"},
			wantCfg: &bwrapConfig{
				Env:      os.Environ(),
				UID:      -1,
				GID:      -1,
				Mounts:   []sandbox.Mount{rootBind},
				HostDirs: []HostDir{{Dest: "/usr", Path: "/usr", ReadOnly: true, Perms: 0755}},
				Args:     []string{"bash"},
			},
		},
		{
			// A tmpfs mounted over the bind hides it, so DEST lives in the
			// sandbox again and --dir falls back to a tmpfs mount.
			name: "DirUnderTmpfsOverBind",
			args: []string{"--bind", mntSrc, "/mnt", "--tmpfs", "/mnt", "--dir", "/mnt/new", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeBind, Source: mntSrc, Destination: "/mnt"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/new"},
				},
				Args: []string{"bash"},
			},
		},
		{
			// An earlier tmpfs at DEST is the directory already, so --dir
			// leaves it, and its mode, alone.
			name: "DirOnTmpfs",
			args: []string{"--perms", "0700", "--tmpfs", "/mnt", "--dir", "/mnt/", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/mnt", Mode: permsPtr(0700)}},
				Args:   []string{"bash"},
			},
		},
		{
			name: "DirOnProc",
			args: []string{"--proc", "/proc1", "--dir", "/proc1", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeProc, Destination: "/proc1"}},
				Args:   []string{"bash"},
			},
		},
		{
			// A mount point's parents exist once the mount is in place.
			name: "DirAboveMount",
			args: []string{"--tmpfs", "/mnt/a/b", "--dir", "/mnt/a", "--dir", "/mnt", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/a/b"}},
				Args:   []string{"bash"},
			},
		},
		{
			name: "RepeatedDir",
			args: []string{"--dir", "/foo", "--perms", "0700", "--dir", "/foo", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/foo"}},
				Args:   []string{"bash"},
			},
		},
		{
			// A path next to a mount, rather than above it, does not exist yet.
			name: "DirNextToMount",
			args: []string{"--tmpfs", "/mnt/a", "--dir", "/mnt/ab", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/a"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/ab"},
				},
				Args: []string{"bash"},
			},
		},
		{
			name: "DirRoot",
			args: []string{"--dir", "/", "bash"},
			wantCfg: &bwrapConfig{
				Env:  os.Environ(),
				UID:  -1,
				GID:  -1,
				Args: []string{"bash"},
			},
		},
		{
			name:        "MissingDirArg",
			args:        []string{"--dir"},
			errContains: "--dir takes 1 argument",
		},
		{
			name:        "MissingPermsArg",
			args:        []string{"--perms"},
			errContains: "--perms takes 1 argument",
		},
		{
			name:        "NonOctalPerms",
			args:        []string{"--perms", "0799", "--tmpfs", "/foo", "bash"},
			errContains: "--perms takes an octal argument",
		},
		{
			name:        "PermsTooLarge",
			args:        []string{"--perms", "10000", "--tmpfs", "/foo", "bash"},
			errContains: "--perms takes an octal argument",
		},
		{
			name:        "DuplicatePerms",
			args:        []string{"--perms", "0700", "--perms", "0700", "--tmpfs", "/foo", "bash"},
			errContains: "--perms given twice",
		},
		{
			name:        "PermsWithoutOperation",
			args:        []string{"--perms", "0700", "--ro-bind", "/", "/", "--", "bash"},
			errContains: "--perms must be followed by",
		},
		{
			name: "RemountROBind",
			args: []string{"--bind", mntSrc, "/mnt", "--remount-ro", "/mnt", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeBind, Source: mntSrc, Destination: "/mnt", ReadOnly: true}},
				Args:   []string{"bash"},
			},
		},
		{
			name: "RemountROTmpfs",
			args: []string{"--tmpfs", "/mnt", "--remount-ro", "/mnt/", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/mnt", ReadOnly: true}},
				Args:   []string{"bash"},
			},
		},
		{
			// Only the topmost mount at DEST, as of --remount-ro, becomes
			// read-only. Mounts below DEST and mounts declared later keep
			// their mode.
			name: "RemountROTopmostMountOnly",
			args: []string{
				"--bind", mntSrc, "/mnt",
				"--tmpfs", "/mnt",
				"--tmpfs", "/mnt/sub",
				"--remount-ro", "/mnt",
				"--tmpfs", "/mnt",
				"bash",
			},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeBind, Source: mntSrc, Destination: "/mnt"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt", ReadOnly: true},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/sub"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt"},
				},
				Args: []string{"bash"},
			},
		},
		{
			name: "RemountROBindRoot",
			args: []string{"--bind", "/", "/", "--remount-ro", "/", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{rootBind},
				Args:   []string{"bash"},
			},
		},
		{
			name: "RemountROTmpfsRoot",
			args: []string{"--remount-ro", "/", "bash"},
			wantCfg: &bwrapConfig{
				Env:               os.Environ(),
				UID:               -1,
				GID:               -1,
				TmpfsRootReadOnly: true,
				Args:              []string{"bash"},
			},
		},
		{
			name:        "RemountRONotMountPoint",
			args:        []string{"--tmpfs", "/mnt", "--remount-ro", "/mnt/sub", "bash"},
			errContains: "Can't remount readonly on /mnt/sub",
		},
		{
			name:        "MissingRemountROArg",
			args:        []string{"--remount-ro"},
			errContains: "--remount-ro takes 1 argument",
		},
		{
			// --remount-ro keeps the mode that --perms set.
			name: "RemountROPerms",
			args: []string{"--perms", "0777", "--tmpfs", "/mnt", "--remount-ro", "/mnt", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/mnt", Mode: permsPtr(0777), ReadOnly: true}},
				Args:   []string{"bash"},
			},
		},
		{
			// A relative DEST is taken from the root.
			name: "RemountRORelativeDest",
			args: []string{"--tmpfs", "/mnt", "--remount-ro", "mnt", "bash"},
			wantCfg: &bwrapConfig{
				Env:    os.Environ(),
				UID:    -1,
				GID:    -1,
				Mounts: []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/mnt", ReadOnly: true}},
				Args:   []string{"bash"},
			},
		},
		{
			// --dev /dev reuses the default /dev mount, which --remount-ro
			// then finds.
			name: "RemountRODev",
			args: []string{"--dev", "/dev", "--remount-ro", "/dev", "bash"},
			wantCfg: &bwrapConfig{
				Env:              os.Environ(),
				UID:              -1,
				GID:              -1,
				ReadOnlyDefaults: []string{"/dev"},
				Args:             []string{"bash"},
			},
		},
		{
			name: "RemountRODefaultMount",
			args: []string{"--remount-ro", "/tmp", "--remount-ro", "/tmp/", "bash"},
			wantCfg: &bwrapConfig{
				Env:              os.Environ(),
				UID:              -1,
				GID:              -1,
				ReadOnlyDefaults: []string{"/tmp"},
				Args:             []string{"bash"},
			},
		},
		{
			// --proc /proc reuses the default /proc mount.
			name: "RemountROProc",
			args: []string{"--proc", "/proc", "--remount-ro", "/proc", "bash"},
			wantCfg: &bwrapConfig{
				Env:              os.Environ(),
				UID:              -1,
				GID:              -1,
				ReadOnlyDefaults: []string{"/proc"},
				Args:             []string{"bash"},
			},
		},
		{
			// The later tmpfs at /mnt hides the tmpfs at /mnt/sub.
			name:        "RemountROHiddenMount",
			args:        []string{"--tmpfs", "/mnt/sub", "--tmpfs", "/mnt", "--remount-ro", "/mnt/sub", "bash"},
			errContains: "Can't remount readonly on /mnt/sub",
		},
		{
			// A --dir stand-in is a directory in the remounted filesystem, so
			// it becomes read-only with it.
			name: "RemountRODirStandIn",
			args: []string{"--tmpfs", "/mnt", "--dir", "/mnt/foo", "--dir", "/mnt/foo/bar", "--remount-ro", "/mnt", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt", ReadOnly: true},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/foo", ReadOnly: true},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/foo/bar", ReadOnly: true},
				},
				Args: []string{"bash"},
			},
		},
		{
			// Only the stand-ins in the remounted filesystem change.
			name: "RemountRODirStandInOtherMount",
			args: []string{"--tmpfs", "/mnt", "--tmpfs", "/mnt/sub", "--dir", "/mnt/sub/foo", "--remount-ro", "/mnt", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt", ReadOnly: true},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/sub"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/sub/foo"},
				},
				Args: []string{"bash"},
			},
		},
		{
			name: "RemountRODirUnderDefaultMount",
			args: []string{"--dir", "/tmp/foo", "--remount-ro", "/tmp", "bash"},
			wantCfg: &bwrapConfig{
				Env:              os.Environ(),
				UID:              -1,
				GID:              -1,
				Mounts:           []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/tmp/foo", ReadOnly: true}},
				ReadOnlyDefaults: []string{"/tmp"},
				Args:             []string{"bash"},
			},
		},
		{
			name: "RemountROTmpfsRootDir",
			args: []string{"--dir", "/foo", "--remount-ro", "/", "bash"},
			wantCfg: &bwrapConfig{
				Env:               os.Environ(),
				UID:               -1,
				GID:               -1,
				Mounts:            []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/foo", ReadOnly: true}},
				TmpfsRootReadOnly: true,
				Args:              []string{"bash"},
			},
		},
		{
			// A tmpfs at "/" holds the paths below it.
			name:        "DirAfterRemountROTmpfsAtRoot",
			args:        []string{"--tmpfs", "/", "--remount-ro", "/", "--dir", "/foo", "bash"},
			errContains: "Can't mkdir /foo: read-only file system",
		},
		{
			name: "RemountROTmpfsAtRootDir",
			args: []string{"--tmpfs", "/", "--dir", "/foo", "--remount-ro", "/", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeTmpfs, Destination: "/", ReadOnly: true},
					{Type: sandbox.MountTypeTmpfs, Destination: "/foo", ReadOnly: true},
				},
				Args: []string{"bash"},
			},
		},
		{
			// A later --tmpfs hides the first --dir, so the second one
			// creates the directory again.
			name: "DirHiddenThenAgain",
			args: []string{"--dir", "/mnt/foo", "--tmpfs", "/mnt", "--dir", "/mnt/foo", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/foo"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/foo"},
				},
				Args: []string{"bash"},
			},
		},
		{
			name:        "DirHiddenThenAgainReadOnly",
			args:        []string{"--dir", "/mnt/foo", "--tmpfs", "/mnt", "--remount-ro", "/mnt", "--dir", "/mnt/foo", "bash"},
			errContains: "Can't mkdir /mnt/foo: read-only file system",
		},
		{
			// The root bind hides the earlier tmpfs at /tmp, so the default
			// /tmp is the mount there.
			name: "RemountRODefaultUnderHiddenMount",
			args: []string{"--tmpfs", "/tmp", "--ro-bind", "/", "/", "--remount-ro", "/tmp", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeTmpfs, Destination: "/tmp"},
					rootBind,
				},
				ReadOnlyDefaults: []string{"/tmp"},
				Args:             []string{"bash"},
			},
		},
		{
			// The root bind hides the earlier tmpfs at /mnt.
			name:        "RemountROHiddenByRootBind",
			args:        []string{"--tmpfs", "/mnt", "--ro-bind", "/", "/", "--remount-ro", "/mnt", "bash"},
			errContains: "Can't remount readonly on /mnt",
		},
		{
			// A --dir stands for a directory, not a mount point.
			name:        "RemountRODir",
			args:        []string{"--dir", "/foo", "--remount-ro", "/foo", "bash"},
			errContains: "Can't remount readonly on /foo",
		},
		{
			name:        "DirAfterRemountRO",
			args:        []string{"--tmpfs", "/mnt", "--remount-ro", "/mnt", "--dir", "/mnt/new", "bash"},
			errContains: "Can't mkdir /mnt/new: read-only file system",
		},
		{
			name:        "DirAfterRemountROTmpfsRoot",
			args:        []string{"--remount-ro", "/", "--dir", "/new", "bash"},
			errContains: "Can't mkdir /new: read-only file system",
		},
		{
			// An existing DEST needs no mkdir.
			name: "DirAfterRemountROExisting",
			args: []string{"--tmpfs", "/mnt", "--tmpfs", "/mnt/sub", "--remount-ro", "/mnt", "--dir", "/mnt/sub", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt", ReadOnly: true},
					{Type: sandbox.MountTypeTmpfs, Destination: "/mnt/sub"},
				},
				Args: []string{"bash"},
			},
		},
		{
			// DEST exists, so --dir needs no mkdir in the read-only
			// filesystem.
			name: "DirAfterRemountRODefaultMount",
			args: []string{"--remount-ro", "/tmp", "--dir", "/tmp", "--remount-ro", "/sys", "--dir", "/sys/fs", "bash"},
			wantCfg: &bwrapConfig{
				Env:              os.Environ(),
				UID:              -1,
				GID:              -1,
				ReadOnlyDefaults: []string{"/tmp", "/sys"},
				Args:             []string{"bash"},
			},
		},
		{
			// runsc does not know what the dev filesystem holds, so the
			// stand-in is a read-only directory.
			name: "DirAfterRemountRODev",
			args: []string{"--dev", "/dev", "--remount-ro", "/dev", "--dir", "/dev/shm", "bash"},
			wantCfg: &bwrapConfig{
				Env:              os.Environ(),
				UID:              -1,
				GID:              -1,
				Mounts:           []sandbox.Mount{{Type: sandbox.MountTypeTmpfs, Destination: "/dev/shm", ReadOnly: true}},
				ReadOnlyDefaults: []string{"/dev"},
				Args:             []string{"bash"},
			},
		},
		{
			// /dev/pts, not /dev, holds /dev/pts/foo.
			name: "RemountRONestedDefaultMounts",
			args: []string{"--dir", "/dev/pts/foo", "--remount-ro", "/dev", "--dir", "/dev/pts/bar", "--remount-ro", "/sys/fs/cgroup", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeTmpfs, Destination: "/dev/pts/foo"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/dev/pts/bar"},
				},
				ReadOnlyDefaults: []string{"/dev", "/sys/fs/cgroup"},
				Args:             []string{"bash"},
			},
		},
		{
			// The default mounts go on top of the root bind.
			name: "RemountRODefaultMountUnderRootBind",
			args: []string{"--ro-bind", "/", "/", "--remount-ro", "/dev/pts", "bash"},
			wantCfg: &bwrapConfig{
				Env:              os.Environ(),
				UID:              -1,
				GID:              -1,
				Mounts:           []sandbox.Mount{rootBind},
				ReadOnlyDefaults: []string{"/dev/pts"},
				Args:             []string{"bash"},
			},
		},
		{
			// The tmpfs at /sys hides the default mount at /sys/fs/cgroup.
			name:        "RemountROHiddenDefaultMount",
			args:        []string{"--tmpfs", "/sys", "--remount-ro", "/sys/fs/cgroup", "bash"},
			errContains: "Can't remount readonly on /sys/fs/cgroup",
		},
		{
			// A --dev or --proc after --remount-ro mounts a new writable
			// filesystem on top.
			name: "DevAndProcAfterRemountRO",
			args: []string{"--remount-ro", "/dev", "--dev", "/dev", "--proc", "/proc", "--remount-ro", "/proc", "--proc", "/proc", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeDevtmpfs, Destination: "/dev"},
					{Type: sandbox.MountTypeDevpts, Destination: "/dev/pts"},
					{Type: sandbox.MountTypeProc, Destination: "/proc"},
				},
				ReadOnlyDefaults: []string{"/dev", "/proc"},
				Args:             []string{"bash"},
			},
		},
		{
			// --dev also mounts a new devpts, so a read-only DEST/pts makes
			// it mount a new dev filesystem.
			name: "DevAfterRemountROPts",
			args: []string{"--remount-ro", "/dev/pts", "--dev", "/dev", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeDevtmpfs, Destination: "/dev"},
					{Type: sandbox.MountTypeDevpts, Destination: "/dev/pts"},
				},
				ReadOnlyDefaults: []string{"/dev/pts"},
				Args:             []string{"bash"},
			},
		},
		{
			// A --dev or --proc whose earlier mount is hidden mounts a new
			// filesystem on top.
			name: "DevAndProcOverOtherMounts",
			args: []string{"--tmpfs", "/dev", "--dev", "/dev", "--proc", "/p", "--tmpfs", "/p", "--proc", "/p", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeTmpfs, Destination: "/dev"},
					{Type: sandbox.MountTypeDevtmpfs, Destination: "/dev"},
					{Type: sandbox.MountTypeDevpts, Destination: "/dev/pts"},
					{Type: sandbox.MountTypeProc, Destination: "/p"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/p"},
					{Type: sandbox.MountTypeProc, Destination: "/p"},
				},
				Args: []string{"bash"},
			},
		},
		{
			// A default mount over the root bind holds DEST, so --dir does
			// not use the host path behind the bind.
			name: "DirInDefaultMountOverRootBind",
			args: []string{"--bind", mntSrc, "/", "--dir", "/tmp/foo", "bash"},
			wantCfg: &bwrapConfig{
				Env: os.Environ(),
				UID: -1,
				GID: -1,
				Mounts: []sandbox.Mount{
					{Type: sandbox.MountTypeBind, Source: mntSrc, Destination: "/"},
					{Type: sandbox.MountTypeTmpfs, Destination: "/tmp/foo"},
				},
				Args: []string{"bash"},
			},
		},
		{
			name:        "DirInReadOnlyDefaultMountOverRootBind",
			args:        []string{"--bind", mntSrc, "/", "--remount-ro", "/tmp", "--dir", "/tmp/foo", "bash"},
			errContains: "Can't mkdir /tmp/foo: read-only file system",
		},
		{
			// A --dir under a bind is made on the host when the sandbox is
			// set up, but it sees the bind as of its place on the command
			// line.
			name: "HostDirBeforeRemountRO",
			args: []string{"--bind", mntSrc, "/mnt", "--dir", "/mnt/new", "--remount-ro", "/mnt", "bash"},
			wantCfg: &bwrapConfig{
				Env:      os.Environ(),
				UID:      -1,
				GID:      -1,
				Mounts:   []sandbox.Mount{{Type: sandbox.MountTypeBind, Source: mntSrc, Destination: "/mnt", ReadOnly: true}},
				HostDirs: []HostDir{{Dest: "/mnt/new", Path: mntSrc + "/new", Perms: 0755}},
				Args:     []string{"bash"},
			},
		},
		{
			name: "HostDirAfterRemountRO",
			args: []string{"--bind", mntSrc, "/mnt", "--remount-ro", "/mnt", "--dir", "/mnt/new", "bash"},
			wantCfg: &bwrapConfig{
				Env:      os.Environ(),
				UID:      -1,
				GID:      -1,
				Mounts:   []sandbox.Mount{{Type: sandbox.MountTypeBind, Source: mntSrc, Destination: "/mnt", ReadOnly: true}},
				HostDirs: []HostDir{{Dest: "/mnt/new", Path: mntSrc + "/new", ReadOnly: true, Perms: 0755}},
				Args:     []string{"bash"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseBwrapArgs(tc.args)
			wantError := tc.errContains != ""
			if wantError {
				if err == nil {
					t.Fatalf("got nil, want error containing %v", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("got error %v, want error containing %v", err, tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if diff := cmp.Diff(cfg, tc.wantCfg, cmpopts.IgnoreUnexported(bwrapConfig{})); diff != "" {
				t.Errorf("bwrapConfig mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

// TestHostPath checks which mount, if any, backs a sandbox path.
func TestHostPath(t *testing.T) {
	cfg := &bwrapConfig{Mounts: []sandbox.Mount{
		{Type: sandbox.MountTypeBind, Source: "/", Destination: "/", ReadOnly: true},
		{Type: sandbox.MountTypeBind, Source: "/host/data", Destination: "/data"},
		{Type: sandbox.MountTypeTmpfs, Destination: "/data/tmp"},
		{Type: sandbox.MountTypeBind, Source: "/host/cache", Destination: "/data/tmp/cache", ReadOnly: true},
		{Type: sandbox.MountTypeBind, Source: "/host/old", Destination: "/old"},
		{Type: sandbox.MountTypeTmpfs, Destination: "/old"},
	}}
	tests := []struct {
		path     string
		wantHost string
		wantRO   bool
		wantOK   bool
	}{
		// The root bind backs everything no other mount covers.
		{path: "/usr/lib", wantHost: "/usr/lib", wantRO: true, wantOK: true},
		{path: "/", wantHost: "/", wantRO: true, wantOK: true},
		// A bind maps its destination and anything below it.
		{path: "/data", wantHost: "/host/data", wantOK: true},
		{path: "/data/a/b", wantHost: "/host/data/a/b", wantOK: true},
		{path: "/data//a/../b/", wantHost: "/host/data/b", wantOK: true},
		// A tmpfs under the bind takes its subtree out of the host.
		{path: "/data/tmp"},
		{path: "/data/tmp/x"},
		// A bind under that tmpfs puts its subtree back on the host.
		{path: "/data/tmp/cache/x", wantHost: "/host/cache/x", wantRO: true, wantOK: true},
		// A tmpfs mounted over a bind hides the bind.
		{path: "/old/x"},
		// Prefix matches are on path components, not characters.
		{path: "/database", wantHost: "/database", wantRO: true, wantOK: true},
		// A relative path matches no mount.
		{path: "data/x"},
	}
	for _, tc := range tests {
		bind, host, ok := cfg.hostPath(tc.path)
		if ok != tc.wantOK || host != tc.wantHost || bind.ReadOnly != tc.wantRO {
			t.Errorf("hostPath(%q) = %q, readOnly=%v, %v; want %q, readOnly=%v, %v",
				tc.path, host, bind.ReadOnly, ok, tc.wantHost, tc.wantRO, tc.wantOK)
		}
	}
}

// TestMakeHostDirs checks that --dir behaves on the host as bubblewrap's
// --dir does inside the sandbox.
func TestMakeHostDirs(t *testing.T) {
	// bubblewrap clears its umask while it sets up the sandbox, so a
	// restrictive one must not change the modes below.
	oldMask := unix.Umask(077)
	t.Cleanup(func() { unix.Umask(oldMask) })

	tests := []struct {
		name string
		// setup prepares the host directory root and returns the --dir path
		// under it, relative to root.
		setup func(t *testing.T, root string) string
		ro    bool
		perms uint32
		// wantMode is the mode of the directory afterwards, 0 when no directory
		// may exist at the path.
		wantMode os.FileMode
		// wantParentMode is the mode of the directory's parent afterwards.
		wantParentMode os.FileMode
		errContains    string
	}{
		{
			name:           "Creates",
			setup:          func(t *testing.T, root string) string { return "new" },
			perms:          0755,
			wantMode:       0755,
			wantParentMode: 0700,
		},
		{
			name:           "CreatesWithPerms",
			setup:          func(t *testing.T, root string) string { return "new" },
			perms:          0710,
			wantMode:       0710,
			wantParentMode: 0700,
		},
		{
			name:           "CreatesWithStickyBit",
			setup:          func(t *testing.T, root string) string { return "new" },
			perms:          01777,
			wantMode:       0777 | os.ModeSticky,
			wantParentMode: 0700,
		},
		{
			// mkdir(2) passes a parent's setgid bit on to the new directory.
			name: "CreatesUnderSetgidParent",
			setup: func(t *testing.T, root string) string {
				if err := os.Chmod(root, 0700|os.ModeSetgid); err != nil {
					t.Fatal(err)
				}
				return "new"
			},
			perms:          0755,
			wantMode:       0755 | os.ModeSetgid,
			wantParentMode: 0700,
		},
		{
			// Parents get 0755, less the group and other bits the directory
			// itself withholds.
			name:           "CreatesParents",
			setup:          func(t *testing.T, root string) string { return "a/b/c" },
			perms:          0750,
			wantMode:       0750,
			wantParentMode: 0750,
		},
		{
			name:           "CreatesPrivateParents",
			setup:          func(t *testing.T, root string) string { return "a/b/c" },
			perms:          0700,
			wantMode:       0700,
			wantParentMode: 0700,
		},
		{
			// An existing directory keeps its mode and contents.
			name: "Exists",
			setup: func(t *testing.T, root string) string {
				mkdirMode(t, filepath.Join(root, "keep"), 0711)
				if err := os.WriteFile(filepath.Join(root, "keep", "marker"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				return "keep"
			},
			perms:          0755,
			wantMode:       0711,
			wantParentMode: 0700,
		},
		{
			name: "ExistsUnderReadOnlyBind",
			setup: func(t *testing.T, root string) string {
				mkdirMode(t, filepath.Join(root, "keep"), 0711)
				return "keep"
			},
			ro:             true,
			perms:          0755,
			wantMode:       0711,
			wantParentMode: 0700,
		},
		{
			name:           "MissingUnderReadOnlyBind",
			setup:          func(t *testing.T, root string) string { return "new" },
			ro:             true,
			perms:          0755,
			wantParentMode: 0700,
			errContains:    "Can't mkdir /mnt/new: read-only file system",
		},
		{
			name: "ExistsAsFile",
			setup: func(t *testing.T, root string) string {
				if err := os.WriteFile(filepath.Join(root, "file"), nil, 0600); err != nil {
					t.Fatal(err)
				}
				return "file"
			},
			perms:          0755,
			wantParentMode: 0700,
			errContains:    "Can't mkdir /mnt/file: not a directory",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			rel := tc.setup(t, root)
			path := filepath.Join(root, rel)
			cfg := &bwrapConfig{HostDirs: []HostDir{{
				Dest:     filepath.Join("/mnt", rel),
				Path:     path,
				ReadOnly: tc.ro,
				Perms:    tc.perms,
			}}}

			err := cfg.makeHostDirs(-1, -1)
			if tc.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("makeHostDirs() = %v, want error containing %q", err, tc.errContains)
				}
			} else if err != nil {
				t.Fatalf("makeHostDirs() = %v, want nil", err)
			}

			info, err := os.Stat(path)
			if tc.wantMode == 0 {
				if err == nil && info.IsDir() {
					t.Errorf("%q is a directory, want none", path)
				}
			} else if err != nil {
				t.Errorf("os.Stat(%q) = %v, want a directory", path, err)
			} else if !info.IsDir() || info.Mode()&(os.ModePerm|os.ModeSticky|os.ModeSetgid) != tc.wantMode {
				t.Errorf("%q is %v, want a directory with mode %v", path, info.Mode(), tc.wantMode)
			}
			if tc.name == "Exists" {
				if _, err := os.Stat(filepath.Join(path, "marker")); err != nil {
					t.Errorf("existing directory lost its contents: %v", err)
				}
			}
			parent, err := os.Stat(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			if got := parent.Mode() & os.ModePerm; got != tc.wantParentMode {
				t.Errorf("parent of %q has mode %v, want %v", path, got, tc.wantParentMode)
			}
		})
	}
}

// mkdirMode creates the directory path with exactly mode, whatever the umask.
func mkdirMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}
