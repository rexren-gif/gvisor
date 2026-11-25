// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sandbox_test

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

func TestSpec(t *testing.T) {
	for _, netMode := range []sandbox.NetworkMode{sandbox.NetworkModeNone, sandbox.NetworkModeHost, sandbox.NetworkModeSandbox} {
		t.Run(string(netMode), func(t *testing.T) {
			spec, err := sandbox.DebugSpec(sandbox.WithNetwork(netMode))
			if err != nil {
				t.Fatalf("DebugSpec(netMode=%v) failed: %v", netMode, err)
			}

			if spec.Version != "1.0.0" {
				t.Errorf("spec.Version = %q, want %q", spec.Version, "1.0.0")
			}
			if spec.Root == nil || spec.Root.Path != "rootfs" {
				t.Errorf("spec.Root.Path is not 'rootfs', got: %+v", spec.Root)
			}
			if spec.Root.Readonly {
				t.Errorf("spec.Root.Readonly is true, want false")
			}
			if spec.Linux == nil {
				t.Fatalf("spec.Linux is nil")
			}

			var expectedNamespaces []specs.LinuxNamespace
			expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.PIDNamespace})
			if netMode == sandbox.NetworkModeSandbox {
				expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace})
			}
			expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.MountNamespace})
			expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.UTSNamespace})
			expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.IPCNamespace})
			if os.Geteuid() != 0 {
				expectedNamespaces = append(expectedNamespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
			}

			if len(spec.Linux.Namespaces) != len(expectedNamespaces) {
				t.Errorf("netMode=%v: Namespaces length = %d, want %d. Got: %+v, Want: %+v", netMode, len(spec.Linux.Namespaces), len(expectedNamespaces), spec.Linux.Namespaces, expectedNamespaces)
			}
			namespaceComparator := func(a, b specs.LinuxNamespace) int {
				if a.Type == b.Type && a.Path == b.Path {
					return 0
				}
				if a.Type < b.Type || a.Path < b.Path {
					return -1
				}
				return 1
			}
			slices.SortFunc(spec.Linux.Namespaces, namespaceComparator)
			slices.SortFunc(expectedNamespaces, namespaceComparator)
			if !slices.Equal(spec.Linux.Namespaces, expectedNamespaces) {
				t.Errorf("netMode=%v: spec.Linux.Namespaces=%+v, want: %+v", netMode, spec.Linux.Namespaces, expectedNamespaces)
			}
		})
	}
}

func TestSpecMountNormalization(t *testing.T) {
	spec, err := sandbox.DebugSpec(
		sandbox.WithMount(
			sandbox.Mount{
				Source:      "/tmp/foo/../bar",
				Destination: "/mnt/foo/./bar",
				Type:        sandbox.MountTypeBind,
			},
			sandbox.Mount{
				Destination: "/mnt/baz/..",
				Type:        sandbox.MountTypeTmpfs,
			},
		),
	)
	if err != nil {
		t.Fatalf("DebugSpec failed: %v", err)
	}

	var foundBind, foundTmpfs bool
	for _, m := range spec.Mounts {
		if m.Type == "bind" && m.Destination == "/mnt/foo/bar" {
			foundBind = true
			if m.Source != "/tmp/bar" {
				t.Errorf("bind source = %q, want %q", m.Source, "/tmp/bar")
			}
		}
		if m.Type == "tmpfs" && m.Destination == "/mnt" {
			foundTmpfs = true
		}
	}

	if !foundBind {
		t.Errorf("failed to find normalized bind mount '/mnt/foo/bar'")
	}
	if !foundTmpfs {
		t.Errorf("failed to find normalized tmpfs mount '/mnt'")
	}
}

func TestSpecEnv(t *testing.T) {
	spec, err := sandbox.DebugSpec(sandbox.WithEnv("TEST_VAR=A", "TEST_VAR=B"))
	if err != nil {
		t.Fatalf("DebugSpec failed: %v", err)
	}

	expectedEnv := []string{
		"PATH=/bin:/usr/bin:/usr/local/bin",
		"TEST_VAR=A",
		"TEST_VAR=B",
	}

	// Verify default env vars
	if !slices.Equal(spec.Process.Env, expectedEnv) {
		t.Errorf("spec.Process.Env = %+v, want %+v", spec.Process.Env, expectedEnv)
	}
}

func TestSpecWorkingDir(t *testing.T) {
	customCwd := "/custom/absolute/path"

	spec, err := sandbox.DebugSpec(sandbox.WithWorkingDir(customCwd))
	if err != nil {
		t.Fatalf("DebugSpec failed: %v", err)
	}

	if spec.Process.Cwd != customCwd {
		t.Errorf("spec.Process.Cwd = %q, want %q", spec.Process.Cwd, customCwd)
	}
}

func modePtr(mode uint32) *uint32 { return &mode }

func TestSpecMountMode(t *testing.T) {
	const dst = "/mnt/foo"

	tests := []struct {
		name    string
		mount   sandbox.Mount
		wantOpt string
	}{
		{
			name:    "TmpfsWithMode",
			mount:   sandbox.Mount{Destination: dst, Type: sandbox.MountTypeTmpfs, Mode: modePtr(0700)},
			wantOpt: "mode=0700",
		},
		{
			name:    "TmpfsWithDefaultMode",
			mount:   sandbox.Mount{Destination: dst, Type: sandbox.MountTypeTmpfs, Mode: modePtr(01777)},
			wantOpt: "mode=1777",
		},
		{
			// ociMount translates whatever Mode it is given; restricting Mode to
			// tmpfs is the caller's job.
			name:    "ModePassedThroughForBind",
			mount:   sandbox.Mount{Source: "/tmp", Destination: dst, Type: sandbox.MountTypeBind, Mode: modePtr(0700)},
			wantOpt: "mode=0700",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := sandbox.DebugSpec(sandbox.WithMount(tc.mount))
			if err != nil {
				t.Fatalf("DebugSpec failed: %v", err)
			}

			var opts []string
			found := false
			for _, m := range spec.Mounts {
				if m.Destination == dst {
					opts = m.Options
					found = true
				}
			}
			if !found {
				t.Fatalf("no mount with destination %q, got mounts: %+v", dst, spec.Mounts)
			}

			hasMode := slices.ContainsFunc(opts, func(o string) bool {
				return strings.HasPrefix(o, "mode=")
			})
			if tc.wantOpt == "" {
				if hasMode {
					t.Errorf("mount options = %v, want no mode= option", opts)
				}
				return
			}
			if !slices.Contains(opts, tc.wantOpt) {
				t.Errorf("mount options = %v, want it to contain %q", opts, tc.wantOpt)
			}
		})
	}
}

// overlayOpts are the options that leave only the given mounts in the spec,
// after a tmpfs at "/".
func overlayOpts(mounts ...sandbox.Mount) []sandbox.Option {
	return []sandbox.Option{
		sandbox.WithoutLinuxSystemMounts(),
		sandbox.WithoutHostBinaryMounts(),
		sandbox.WithMount(append([]sandbox.Mount{{Destination: "/", Type: sandbox.MountTypeTmpfs}}, mounts...)...),
	}
}

func TestSpecOverlay(t *testing.T) {
	tests := []struct {
		name  string
		mount sandbox.Mount
		want  []specs.Mount
	}{
		{
			name:  "Memory",
			mount: sandbox.Mount{Destination: "/mnt/", Type: sandbox.MountTypeOverlay, Lowers: []string{"/host/a"}},
			want: []specs.Mount{
				{Destination: "/.gvisor-overlay/1/0", Source: "/host/a", Type: "bind", Options: []string{"ro", "nosuid", "nodev"}},
				{Destination: "/mnt", Source: "overlay", Type: "overlay", Options: []string{"dev.gvisor.overlay.lower=/.gvisor-overlay/1/0"}},
			},
		},
		{
			name:  "ReadOnly",
			mount: sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: []string{"/host/a", "/host/b/"}, ReadOnly: true},
			want: []specs.Mount{
				{Destination: "/.gvisor-overlay/1/0", Source: "/host/a", Type: "bind", Options: []string{"ro", "nosuid", "nodev"}},
				{Destination: "/.gvisor-overlay/1/1", Source: "/host/b", Type: "bind", Options: []string{"ro", "nosuid", "nodev"}},
				{Destination: "/mnt", Source: "overlay", Type: "overlay", Options: []string{
					"ro",
					"dev.gvisor.overlay.lower=/.gvisor-overlay/1/0",
					"dev.gvisor.overlay.lower=/.gvisor-overlay/1/1",
				}},
			},
		},
		{
			name:  "NoSuidNoDev",
			mount: sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: []string{"/host/a"}, NoSuid: true, NoDev: true},
			want: []specs.Mount{
				{Destination: "/.gvisor-overlay/1/0", Source: "/host/a", Type: "bind", Options: []string{"ro", "nosuid", "nodev"}},
				{Destination: "/mnt", Source: "overlay", Type: "overlay", Options: []string{
					"nosuid",
					"nodev",
					"dev.gvisor.overlay.lower=/.gvisor-overlay/1/0",
				}},
			},
		},
		{
			name:  "Upper",
			mount: sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: []string{"/host/a"}, Upper: "/host/rw"},
			want: []specs.Mount{
				{Destination: "/.gvisor-overlay/1/0", Source: "/host/a", Type: "bind", Options: []string{"ro", "nosuid", "nodev"}},
				{Destination: "/.gvisor-overlay/1/upper", Source: "/host/rw", Type: "bind", Options: []string{"nosuid", "nodev"}},
				{Destination: "/mnt", Source: "overlay", Type: "overlay", Options: []string{
					"dev.gvisor.overlay.lower=/.gvisor-overlay/1/0",
					"dev.gvisor.overlay.upper=/.gvisor-overlay/1/upper",
				}},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := sandbox.DebugSpec(overlayOpts(tc.mount)...)
			if err != nil {
				t.Fatalf("DebugSpec failed: %v", err)
			}
			want := append([]specs.Mount{{Destination: "/", Type: "tmpfs"}}, tc.want...)
			if !reflect.DeepEqual(spec.Mounts, want) {
				t.Errorf("spec.Mounts = %+v, want %+v", spec.Mounts, want)
			}
		})
	}
}

func TestSpecOverlayErrors(t *testing.T) {
	layers := []string{"/host/a", "/host/b"}
	tests := []struct {
		name    string
		opts    []sandbox.Option
		wantErr string
	}{
		{
			name:    "NoLayers",
			opts:    overlayOpts(sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay}),
			wantErr: "has no layers",
		},
		{
			name:    "EmptyLayer",
			opts:    overlayOpts(sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: []string{""}}),
			wantErr: "empty layer",
		},
		{
			name:    "ReadOnlyOneLayer",
			opts:    overlayOpts(sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers[:1], ReadOnly: true}),
			wantErr: "needs 2 or more layers",
		},
		{
			name:    "ReadOnlyUpper",
			opts:    overlayOpts(sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers, Upper: "/host/rw", ReadOnly: true}),
			wantErr: "cannot have an upper directory",
		},
		{
			name:    "Source",
			opts:    overlayOpts(sandbox.Mount{Source: "/host/x", Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers}),
			wantErr: "cannot have a source",
		},
		{
			name:    "AtRoot",
			opts:    overlayOpts(sandbox.Mount{Destination: "/", Type: sandbox.MountTypeOverlay, Lowers: layers}),
			wantErr: `cannot be at "/"`,
		},
		{
			name: "NoTmpfsRoot",
			opts: []sandbox.Option{
				sandbox.WithMount(sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers}),
			},
			wantErr: "needs an earlier tmpfs mount",
		},
		{
			name: "TmpfsRootAfter",
			opts: []sandbox.Option{
				sandbox.WithMount(
					sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers},
					sandbox.Mount{Destination: "/", Type: sandbox.MountTypeTmpfs},
				),
			},
			wantErr: "needs an earlier tmpfs mount",
		},
		{
			name: "HostRoot",
			opts: append(overlayOpts(sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers}),
				sandbox.WithRootfs("/", true)),
			wantErr: "default root filesystem",
		},
		{
			name: "BindAtRoot",
			opts: overlayOpts(
				sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers},
				sandbox.Mount{Source: "/", Destination: "/", Type: sandbox.MountTypeBind},
			),
			wantErr: "to be a tmpfs",
		},
		{
			name: "MountInLayerDir",
			opts: overlayOpts(
				sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers},
				sandbox.Mount{Destination: "/.gvisor-overlay/x", Type: sandbox.MountTypeTmpfs},
			),
			wantErr: "which overlay mounts use",
		},
		{
			name:    "Mode",
			opts:    overlayOpts(sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers, Mode: modePtr(0700)}),
			wantErr: "cannot have a source, a mode",
		},
		{
			name:    "Recursive",
			opts:    overlayOpts(sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers, Recursive: true}),
			wantErr: "cannot have a source, a mode",
		},
		{
			name:    "RelativeLayer",
			opts:    overlayOpts(sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: []string{"host/a"}}),
			wantErr: "not an absolute path",
		},
		{
			name:    "RelativeUpper",
			opts:    overlayOpts(sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers, Upper: "rw"}),
			wantErr: "not an absolute path",
		},
		{
			name:    "UpperIsLayer",
			opts:    overlayOpts(sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers, Upper: "/host/b/"}),
			wantErr: "both a layer and the upper directory",
		},
		{
			name:    "CleansToRoot",
			opts:    overlayOpts(sandbox.Mount{Destination: "/mnt/..", Type: sandbox.MountTypeOverlay, Lowers: layers}),
			wantErr: `cannot be at "/"`,
		},
		{
			name: "MountAtLayerDir",
			opts: overlayOpts(
				sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers},
				sandbox.Mount{Destination: "/.gvisor-overlay", Type: sandbox.MountTypeTmpfs},
			),
			wantErr: "which overlay mounts use",
		},
		{
			name:    "LayersOnBind",
			opts:    overlayOpts(sandbox.Mount{Source: "/host/x", Destination: "/mnt", Type: sandbox.MountTypeBind, Lowers: layers}),
			wantErr: "only overlay mounts can have",
		},
	}
	// A path that only starts with the name of the layer directory is fine.
	if _, err := sandbox.DebugSpec(overlayOpts(
		sandbox.Mount{Destination: "/mnt", Type: sandbox.MountTypeOverlay, Lowers: layers},
		sandbox.Mount{Destination: "/.gvisor-overlayx", Type: sandbox.MountTypeTmpfs},
	)...); err != nil {
		t.Errorf("DebugSpec() with a mount at /.gvisor-overlayx failed: %v", err)
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sandbox.DebugSpec(tc.opts...)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("DebugSpec() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
