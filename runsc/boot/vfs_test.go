// Copyright 2021 The gVisor Authors.
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

package boot

import (
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/runsc/boot/sentryapi"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

func TestGetMountAccessType(t *testing.T) {
	const source = "foo"
	for _, tst := range []struct {
		name        string
		annotations map[string]string
		want        config.FileAccessType
	}{
		{
			name: "container=exclusive",
			annotations: map[string]string{
				sentryapi.MountPrefix + "mount1.source": source,
				sentryapi.MountPrefix + "mount1.type":   "bind",
				sentryapi.MountPrefix + "mount1.share":  "container",
			},
			want: config.FileAccessExclusive,
		},
		{
			name: "pod=shared",
			annotations: map[string]string{
				sentryapi.MountPrefix + "mount1.source": source,
				sentryapi.MountPrefix + "mount1.type":   "bind",
				sentryapi.MountPrefix + "mount1.share":  "pod",
			},
			want: config.FileAccessShared,
		},
		{
			name: "share=shared",
			annotations: map[string]string{
				sentryapi.MountPrefix + "mount1.source": source,
				sentryapi.MountPrefix + "mount1.type":   "bind",
				sentryapi.MountPrefix + "mount1.share":  "shared",
			},
			want: config.FileAccessShared,
		},
		{
			name: "default=shared",
			annotations: map[string]string{
				sentryapi.MountPrefix + "mount1.source": source + "mismatch",
				sentryapi.MountPrefix + "mount1.type":   "bind",
				sentryapi.MountPrefix + "mount1.share":  "container",
			},
			want: config.FileAccessShared,
		},
		{
			name: "tmpfs+container=exclusive",
			annotations: map[string]string{
				sentryapi.MountPrefix + "mount1.source": source,
				sentryapi.MountPrefix + "mount1.type":   "tmpfs",
				sentryapi.MountPrefix + "mount1.share":  "container",
			},
			want: config.FileAccessExclusive,
		},
		{
			name: "tmpfs+pod=exclusive",
			annotations: map[string]string{
				sentryapi.MountPrefix + "mount1.source": source,
				sentryapi.MountPrefix + "mount1.type":   "tmpfs",
				sentryapi.MountPrefix + "mount1.share":  "pod",
			},
			want: config.FileAccessExclusive,
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			spec := &specs.Spec{Annotations: tst.annotations}
			podHints, err := sentryapi.NewPodMountHints(spec)
			if err != nil {
				t.Fatalf("newPodMountHints failed: %v", err)
			}
			conf := &config.Config{FileAccessMounts: config.FileAccessShared}
			if got := getMountAccessType(conf, podHints.FindMount(source)); got != tst.want {
				t.Errorf("getMountAccessType(), got: %v, want: %v", got, tst.want)
			}
		})
	}
}

func TestGoferMountDataDirectFS(t *testing.T) {
	for _, tc := range []struct {
		name             string
		directFS         bool
		suppressDirectFS bool
		wantEnabled      bool
	}{
		{
			name:        "global on, not suppressed",
			directFS:    true,
			wantEnabled: true,
		},
		{
			name:             "global on, suppressed",
			directFS:         true,
			suppressDirectFS: true,
			wantEnabled:      false,
		},
		{
			name:             "global off, suppressed",
			directFS:         false,
			suppressDirectFS: true,
			wantEnabled:      false,
		},
		{
			name:        "global off, not suppressed",
			directFS:    false,
			wantEnabled: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := &config.Config{DirectFS: tc.directFS, HostFifo: config.HostFifoOpen}
			opts := goferMountData(7, config.FileAccessExclusive, conf, tc.suppressDirectFS)
			gotEnabled := slices.Contains(opts, "directfs")
			if gotEnabled != tc.wantEnabled {
				t.Errorf("directfs option present = %t, want %t (opts=%v)", gotEnabled, tc.wantEnabled, opts)
			}
		})
	}
}

func TestGoferMountDataInodeNumbers(t *testing.T) {
	for _, mode := range []config.InodeNumbers{config.InodeNumbersPassthrough, config.InodeNumbersVirtual} {
		conf := &config.Config{InodeNumbers: mode}
		opts := goferMountData(7, config.FileAccessExclusive, conf, false /* suppressDirectFS */)
		if got, want := slices.Contains(opts, "virtual_inode_numbers"), mode == config.InodeNumbersVirtual; got != want {
			t.Errorf("--inode-numbers=%v: virtual_inode_numbers option present = %t, want %t (opts=%v)", mode, got, want, opts)
		}
	}
}

func TestCgroupfsCPUDefaults(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rawQuota   int64
		rawPeriod  int64
		wantQuota  int64
		wantPeriod int64
	}{
		{
			name:       "finite quota",
			rawQuota:   150000,
			rawPeriod:  100000,
			wantQuota:  150000,
			wantPeriod: 100000,
		},
		{
			name:       "unlimited quota keeps linux default",
			rawQuota:   -1,
			rawPeriod:  100000,
			wantQuota:  -1,
			wantPeriod: 100000,
		},
		{
			name:       "unset period falls back to linux default period",
			rawQuota:   -1,
			rawPeriod:  0,
			wantQuota:  -1,
			wantPeriod: 100000,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defaults := cgroupfsCPUDefaults(tc.rawQuota, tc.rawPeriod)
			if got := defaults["cpu.cfs_quota_us"]; got != tc.wantQuota {
				t.Errorf("quota = %d, want %d", got, tc.wantQuota)
			}
			if got := defaults["cpu.cfs_period_us"]; got != tc.wantPeriod {
				t.Errorf("period = %d, want %d", got, tc.wantPeriod)
			}
		})
	}
}

func TestFindByResourceID(t *testing.T) {
	type testItem struct {
		id checkpoint.ResourceID
	}
	getID := func(item testItem) checkpoint.ResourceID {
		return item.id
	}

	m := map[checkpoint.ResourceID]testItem{
		{ContainerName: "c1", Path: "/data"}: {id: checkpoint.ResourceID{ContainerName: "c1", Path: "/data"}},
		{ContainerName: "", Path: "/shared"}: {id: checkpoint.ResourceID{ContainerName: "", Path: "/shared"}},
	}

	// Exact match.
	if got, ok, err := findByResourceID(m, checkpoint.ResourceID{ContainerName: "c1", Path: "/data"}, getID, "Test"); err != nil || !ok || got.id.Path != "/data" {
		t.Errorf("findByResourceID exact match got (%v, %v, %v), want ({c1, /data}, true, nil)", got, ok, err)
	}

	// Fallback match: query has empty container name, matches c1:/data unambiguously.
	if got, ok, err := findByResourceID(m, checkpoint.ResourceID{ContainerName: "", Path: "/data"}, getID, "Test"); err != nil || !ok || got.id.Path != "/data" {
		t.Errorf("findByResourceID fallback match got (%v, %v, %v), want ({c1, /data}, true, nil)", got, ok, err)
	}

	// Fallback match: query has container name c2, matches :/shared unambiguously.
	if got, ok, err := findByResourceID(m, checkpoint.ResourceID{ContainerName: "c2", Path: "/shared"}, getID, "Test"); err != nil || !ok || got.id.Path != "/shared" {
		t.Errorf("findByResourceID fallback match got (%v, %v, %v), want ({, /shared}, true, nil)", got, ok, err)
	}

	// Conflicting container names: query has c2 for /data, map only has c1. Should not match.
	if got, ok, err := findByResourceID(m, checkpoint.ResourceID{ContainerName: "c2", Path: "/data"}, getID, "Test"); err != nil || ok {
		t.Errorf("findByResourceID conflicting container got (%v, %v, %v), want zero, false, nil", got, ok, err)
	}

	// Ambiguous match: two containers have /multi, query has empty container name. Should error.
	ambiguousMap := map[checkpoint.ResourceID]testItem{
		{ContainerName: "c1", Path: "/multi"}: {id: checkpoint.ResourceID{ContainerName: "c1", Path: "/multi"}},
		{ContainerName: "c2", Path: "/multi"}: {id: checkpoint.ResourceID{ContainerName: "c2", Path: "/multi"}},
	}
	if got, ok, err := findByResourceID(ambiguousMap, checkpoint.ResourceID{ContainerName: "", Path: "/multi"}, getID, "Test"); err == nil || ok {
		t.Errorf("findByResourceID ambiguous match got (%v, %v, %v), want zero, false, error", got, ok, err)
	}
}

// TestGroupOverlayLayers checks that overlay mounts take the mounts that they
// name as layers out of the mount list.
func TestGroupOverlayLayers(t *testing.T) {
	lisafs := specutils.GoferMountConf{Lower: specutils.Lisafs, Upper: specutils.NoOverlay}
	newFD := func(t *testing.T) *fd.FD {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		w.Close()
		f, err := fd.NewFromFile(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	bind := func(t *testing.T, dst string, opts ...string) mountInfo {
		return mountInfo{
			mount:          &specs.Mount{Type: "bind", Source: "/host" + dst, Destination: dst, Options: opts},
			goferFD:        newFD(t),
			goferMountConf: lisafs,
		}
	}
	ovl := func(dst string, opts ...string) mountInfo {
		return mountInfo{mount: &specs.Mount{Type: "overlay", Source: "overlay", Destination: dst, Options: opts}}
	}
	tmp := func(dst string) mountInfo {
		return mountInfo{mount: &specs.Mount{Type: "tmpfs", Destination: dst}}
	}
	lower := func(dst string) string { return specutils.OverlayLowerOption + "=" + dst }
	upper := func(dst string) string { return specutils.OverlayUpperOption + "=" + dst }

	for _, tc := range []struct {
		name  string
		input func(t *testing.T) []mountInfo
		// want lists the destinations of the result. For an overlay mount, the
		// destinations of its lower layers, then "upper:" and that of its upper
		// layer, follow in parentheses.
		want    []string
		wantErr string
	}{
		{
			name: "LowersAndUpper",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{
					tmp("/"),
					bind(t, "/l/0", "ro"),
					bind(t, "/l/1", "ro"),
					bind(t, "/l/u"),
					ovl("/mnt", lower("/l/0"), lower("/l/1"), upper("/l/u")),
					tmp("/mnt"),
				}
			},
			want: []string{"/", "/mnt(/l/0 /l/1 upper:/l/u)", "/mnt"},
		},
		{
			name: "TwoOverlays",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{
					tmp("/"),
					bind(t, "/l/0", "ro"),
					bind(t, "/l/1", "ro"),
					ovl("/a", lower("/l/0")),
					ovl("/b", lower("/l/1")),
				}
			},
			want: []string{"/", "/a(/l/0)", "/b(/l/1)"},
		},
		{
			name: "NoLayerOptions",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{tmp("/"), bind(t, "/l", "ro"), ovl("/mnt", "lowerdir=/l")}
			},
			want: []string{"/", "/l", "/mnt"},
		},
		{
			name: "MissingLayer",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{tmp("/"), ovl("/mnt", lower("/l")), bind(t, "/l")}
			},
			wantErr: `no earlier mount at layer "/l"`,
		},
		{
			name: "SharedLayer",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{tmp("/"), bind(t, "/l", "ro"), ovl("/a", lower("/l")), ovl("/b", lower("/l"))}
			},
			wantErr: "is a layer of another overlay mount",
		},
		{
			name: "TmpfsLayer",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{tmp("/"), tmp("/l"), ovl("/mnt", lower("/l"))}
			},
			wantErr: "must be a bind mount",
		},
		{
			name: "OverlaidLayer",
			input: func(t *testing.T) []mountInfo {
				l := bind(t, "/l", "ro")
				l.goferMountConf = specutils.GoferMountConf{Lower: specutils.Lisafs, Upper: specutils.MemoryOverlay}
				return []mountInfo{tmp("/"), l, ovl("/mnt", lower("/l"))}
			},
			wantErr: "must be a bind mount",
		},
		{
			name: "HintedLayer",
			input: func(t *testing.T) []mountInfo {
				l := bind(t, "/l", "ro")
				l.hint = &sentryapi.MountHint{Name: "l"}
				return []mountInfo{tmp("/"), l, ovl("/mnt", lower("/l"))}
			},
			wantErr: "must be a bind mount",
		},
		{
			name: "ReadOnlyUpper",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{tmp("/"), bind(t, "/l", "ro"), bind(t, "/u", "ro"), ovl("/mnt", lower("/l"), upper("/u"))}
			},
			wantErr: `upper layer "/u" is read-only`,
		},
		{
			name: "ReadWriteLower",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{tmp("/"), bind(t, "/l"), ovl("/mnt", lower("/l"))}
			},
			wantErr: `lower layer "/l" is not read-only`,
		},
		{
			name: "NoTmpfsRoot",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{bind(t, "/l", "ro"), ovl("/mnt", lower("/l"))}
			},
			wantErr: `no earlier tmpfs mount at "/" hides layer "/l"`,
		},
		{
			name: "TmpfsRootAfterLayer",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{bind(t, "/l", "ro"), tmp("/"), ovl("/mnt", lower("/l"))}
			},
			wantErr: `no earlier tmpfs mount at "/" hides layer "/l"`,
		},
		{
			name: "BindAtRoot",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{tmp("/"), bind(t, "/l", "ro"), ovl("/mnt", lower("/l")), bind(t, "/")}
			},
			wantErr: `mount at "/" overlaps layer "/l"`,
		},
		{
			name: "MountAboveLayer",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{tmp("/"), tmp("/l"), bind(t, "/l/0", "ro"), ovl("/mnt", lower("/l/0"))}
			},
			wantErr: `mount at "/l" overlaps layer "/l/0"`,
		},
		{
			name: "MountAtLayer",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{tmp("/"), bind(t, "/l", "ro"), bind(t, "/l", "ro"), ovl("/mnt", lower("/l"))}
			},
			wantErr: `mount at "/l" overlaps layer "/l"`,
		},
		{
			name: "UncleanMountAboveLayer",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{tmp("/"), bind(t, "/l/0", "ro"), ovl("/mnt", lower("/l/0")), tmp("/./l//")}
			},
			wantErr: `mount at "/./l//" overlaps layer "/l/0"`,
		},
		{
			name: "MountBelowLayer",
			input: func(t *testing.T) []mountInfo {
				return []mountInfo{tmp("/"), bind(t, "/l", "ro"), bind(t, "/u"), ovl("/mnt", lower("/l"), upper("/u")), tmp("/u/sub")}
			},
			wantErr: `mount at "/u/sub" overlaps layer "/u"`,
		},
		{
			name: "NonLisafsLayer",
			input: func(t *testing.T) []mountInfo {
				l := bind(t, "/l", "ro")
				l.goferMountConf = specutils.GoferMountConf{Lower: specutils.NoneLower, Upper: specutils.MemoryOverlay}
				return []mountInfo{tmp("/"), l, ovl("/mnt", lower("/l"))}
			},
			wantErr: "must be a bind mount",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := groupOverlayLayers(tc.input(t))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("groupOverlayLayers() = %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("groupOverlayLayers() failed: %v", err)
			}
			var dsts []string
			for _, m := range got {
				dst := m.mount.Destination
				if m.overlay != nil {
					var layers []string
					for _, l := range m.overlay.lowers {
						layers = append(layers, l.mount.Destination)
					}
					if m.overlay.upper != nil {
						layers = append(layers, "upper:"+m.overlay.upper.mount.Destination)
					}
					dst += "(" + strings.Join(layers, " ") + ")"
				}
				dsts = append(dsts, dst)
			}
			if !slices.Equal(dsts, tc.want) {
				t.Errorf("groupOverlayLayers() = %q, want %q", dsts, tc.want)
			}
		})
	}
}

// TestSortMounts checks that parents go before children and that mounts with
// destinations of the same length keep their order.
func TestSortMounts(t *testing.T) {
	var mounts []mountInfo
	var want []string
	// More than 12 mounts, where sort.Slice stops using insertion sort.
	for i := 0; i < 20; i++ {
		src := strconv.Itoa(i)
		mounts = append(mounts, mountInfo{mount: &specs.Mount{Source: src, Destination: "/a/b"}})
		want = append(want, src)
	}
	mounts = append(mounts, mountInfo{mount: &specs.Mount{Source: "root", Destination: "/"}})
	want = append([]string{"root"}, want...)
	sortMounts(mounts)
	var got []string
	for _, m := range mounts {
		got = append(got, m.mount.Source)
	}
	if !slices.Equal(got, want) {
		t.Errorf("sortMounts() = %q, want %q", got, want)
	}
}
