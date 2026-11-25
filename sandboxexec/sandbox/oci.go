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

package sandbox

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/specutils"
)

// defaultInitArgs is the placeholder init that keeps the sandbox alive for
// Exec calls.
var defaultInitArgs = []string{"/bin/sleep", "infinity"}

// baseEnv is prepended to the process environment unless SkipBaseEnv is set.
var baseEnv = []string{"PATH=/bin:/usr/bin:/usr/local/bin"}

var hostBinaryDirs = []string{"/bin", "/usr", "/lib", "/lib64", "/etc/alternatives"}

const defaultRootfsDir = "rootfs"

// bundleConfig holds configuration for creating an OCI bundle. The zero value
// of every field reproduces the default sandbox layout.
type bundleConfig struct {
	ID          string
	RuntimeDir  string
	Network     NetworkMode
	Mounts      []Mount
	Env         []string
	Annotations map[string]string
	WorkingDir  string
	Hostname    string

	// RootPath is the container's root filesystem.
	RootPath string

	// RootReadonly mounts the container's root filesystem read-only.
	RootReadonly bool

	// User is the user the init process runs as. Defaults to 0:0.
	User *specs.User

	// Capabilities is the capability set of the init process. When nil, the
	// runtime applies its own default.
	Capabilities *specs.LinuxCapabilities

	// Namespaces are appended to the namespace set.
	Namespaces []specs.LinuxNamespace

	// UIDMappings and GIDMappings replace the default ID mappings when either
	// is non-nil.
	UIDMappings []specs.LinuxIDMapping
	GIDMappings []specs.LinuxIDMapping

	// SkipDefaultNamespaces omits the automatic namespaces and the ID
	// mappings that come with them.
	SkipDefaultNamespaces bool

	// SkipLinuxSystemMounts omits the automatic /proc and /dev mounts.
	SkipLinuxSystemMounts bool

	// SkipHostBinaryMounts omits the read-only binds of the host's binary and
	// library directories.
	SkipHostBinaryMounts bool

	// SkipBaseEnv omits the default PATH entry otherwise prepended to Env.
	SkipBaseEnv bool
}

// ociType returns the OCI filesystem type name for t.
func (t MountType) ociType() (string, error) {
	switch t {
	case MountTypeBind:
		return "bind", nil
	case MountTypeTmpfs:
		return "tmpfs", nil
	case MountTypeProc:
		return "proc", nil
	case MountTypeSysfs:
		return "sysfs", nil
	case MountTypeDevtmpfs:
		return "devtmpfs", nil
	case MountTypeDevpts:
		return "devpts", nil
	case MountTypeCgroup:
		return "cgroupfs", nil
	case MountTypeOverlay:
		return "overlay", nil
	}
	return "", fmt.Errorf("unknown mount type %d", t)
}

// overlayLayerDir is the directory of the root filesystem where the sandbox
// mounts the layers of its overlay mounts for the gofer. An earlier tmpfs at
// "/" keeps it out of the sandbox's view, and the sandbox does not mount the
// layers there.
const overlayLayerDir = "/.gvisor-overlay"

// ociOverlayMounts converts m, the i-th MountTypeOverlay mount, into the OCI
// mount entries of its layers, followed by the entry of the overlay.
func (m Mount) ociOverlayMounts(i int) ([]specs.Mount, error) {
	if m.Source != "" || m.Mode != nil || m.Recursive || m.Private {
		return nil, fmt.Errorf("overlay mount at %q cannot have a source, a mode, or the recursive or private flags", m.Destination)
	}
	if len(m.Lowers) == 0 {
		return nil, fmt.Errorf("overlay mount at %q has no layers", m.Destination)
	}
	if m.ReadOnly && m.Upper != "" {
		return nil, fmt.Errorf("read-only overlay mount at %q cannot have an upper directory", m.Destination)
	}
	if m.ReadOnly && len(m.Lowers) < 2 {
		return nil, fmt.Errorf("read-only overlay mount at %q needs 2 or more layers", m.Destination)
	}
	dir := path.Join(overlayLayerDir, strconv.Itoa(i))
	var mounts []specs.Mount
	var opts []string
	for _, o := range []struct {
		set  bool
		name string
	}{
		{m.NoSuid, "nosuid"},
		{m.NoDev, "nodev"},
		{m.ReadOnly, "ro"},
	} {
		if o.set {
			opts = append(opts, o.name)
		}
	}
	if m.Upper != "" && !filepath.IsAbs(m.Upper) {
		return nil, fmt.Errorf("overlay mount at %q has upper directory %q, which is not an absolute path", m.Destination, m.Upper)
	}
	for j, layer := range m.Lowers {
		if layer == "" {
			return nil, fmt.Errorf("overlay mount at %q has an empty layer", m.Destination)
		}
		if !filepath.IsAbs(layer) {
			return nil, fmt.Errorf("overlay mount at %q has layer %q, which is not an absolute path", m.Destination, layer)
		}
		if m.Upper != "" && filepath.Clean(layer) == filepath.Clean(m.Upper) {
			return nil, fmt.Errorf("overlay mount at %q has %q as both a layer and the upper directory", m.Destination, layer)
		}
		dst := path.Join(dir, strconv.Itoa(j))
		mounts = append(mounts, specs.Mount{
			Destination: dst,
			Source:      filepath.Clean(layer),
			Type:        "bind",
			Options:     []string{"ro", "nosuid", "nodev"},
		})
		opts = append(opts, specutils.OverlayLowerOption+"="+dst)
	}
	if m.Upper != "" {
		dst := path.Join(dir, "upper")
		mounts = append(mounts, specs.Mount{
			Destination: dst,
			Source:      filepath.Clean(m.Upper),
			Type:        "bind",
			Options:     []string{"nosuid", "nodev"},
		})
		opts = append(opts, specutils.OverlayUpperOption+"="+dst)
	}
	fsType, err := m.Type.ociType()
	if err != nil {
		return nil, err
	}
	return append(mounts, specs.Mount{
		Destination: filepath.Clean(m.Destination),
		Source:      fsType,
		Type:        fsType,
		Options:     opts,
	}), nil
}

// checkOverlayMounts reports an error if the mounts of cfg do not meet the
// needs of MountTypeOverlay.
func checkOverlayMounts(cfg bundleConfig) error {
	hasOverlay := slices.ContainsFunc(cfg.Mounts, func(m Mount) bool { return m.Type == MountTypeOverlay })
	if !hasOverlay {
		return nil
	}
	if cfg.RootPath != "" {
		return fmt.Errorf("overlay mounts need the default root filesystem")
	}
	tmpfsRoot := false
	for _, m := range cfg.Mounts {
		dst := filepath.Clean(m.Destination)
		if m.Type == MountTypeOverlay {
			if dst == "/" {
				return fmt.Errorf("overlay mount cannot be at \"/\"")
			}
			if !tmpfsRoot {
				return fmt.Errorf("overlay mount at %q needs an earlier tmpfs mount at \"/\"", dst)
			}
		}
		if dst == "/" {
			if m.Type != MountTypeTmpfs {
				return fmt.Errorf("overlay mounts need every mount at \"/\" to be a tmpfs")
			}
			tmpfsRoot = true
		}
		if dst == overlayLayerDir || strings.HasPrefix(dst, overlayLayerDir+"/") {
			return fmt.Errorf("mount at %q is in %q, which overlay mounts use", dst, overlayLayerDir)
		}
	}
	return nil
}

// ociMount converts m into an OCI mount entry.
func (m Mount) ociMount() (specs.Mount, error) {
	if m.Type == MountTypeOverlay {
		return specs.Mount{}, fmt.Errorf("overlay mount at %q converts to more than one OCI mount", m.Destination)
	}
	if len(m.Lowers) > 0 || m.Upper != "" {
		return specs.Mount{}, fmt.Errorf("mount at %q has layers or an upper directory, which only overlay mounts can have", m.Destination)
	}
	fsType, err := m.Type.ociType()
	if err != nil {
		return specs.Mount{}, err
	}
	source := m.Source
	if source != "" {
		source = filepath.Clean(source)
	}
	var opts []string
	for _, o := range []struct {
		set  bool
		name string
	}{
		{m.Recursive, "rbind"},
		{m.Private, "rprivate"},
		{m.NoSuid, "nosuid"},
		{m.NoDev, "nodev"},
		{m.ReadOnly, "ro"},
	} {
		if o.set {
			opts = append(opts, o.name)
		}
	}
	if m.Mode != nil {
		opts = append(opts, fmt.Sprintf("mode=%04o", *m.Mode))
	}

	return specs.Mount{
		Destination: filepath.Clean(m.Destination),
		Source:      source,
		Type:        fsType,
		Options:     opts,
	}, nil
}

// newSpec builds the OCI runtime specification described by cfg.
func newSpec(cfg bundleConfig) (*specs.Spec, error) {
	// Without an explicit root, the container gets an empty root filesystem.
	rootPath := cfg.RootPath
	if rootPath == "" {
		rootPath = defaultRootfsDir
	}

	var namespaces []specs.LinuxNamespace
	if !cfg.SkipDefaultNamespaces {
		namespaces = []specs.LinuxNamespace{
			{Type: specs.PIDNamespace},
			{Type: specs.MountNamespace},
			{Type: specs.UTSNamespace},
			{Type: specs.IPCNamespace},
		}
		if os.Geteuid() != 0 {
			namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
		}
		if cfg.Network == NetworkModeSandbox {
			namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace})
		}
	}
	namespaces = append(namespaces, cfg.Namespaces...)

	user := specs.User{UID: 0, GID: 0}
	if cfg.User != nil {
		user = *cfg.User
	}

	spec := &specs.Spec{
		Version:     "1.0.0",
		Annotations: cfg.Annotations,
		Root: &specs.Root{
			Path:     rootPath,
			Readonly: cfg.RootReadonly,
		},
		Process: &specs.Process{
			User:         user,
			Args:         defaultInitArgs,
			Cwd:          cfg.WorkingDir,
			Capabilities: cfg.Capabilities,
		},
		// enable basic namespaces for gVisor.
		Linux: &specs.Linux{
			Namespaces: namespaces,
		},
		Hostname: cfg.Hostname,
	}

	if cfg.SkipBaseEnv {
		spec.Process.Env = cfg.Env
	} else {
		spec.Process.Env = slices.Concat(baseEnv, cfg.Env)
	}

	switch {
	case cfg.UIDMappings != nil || cfg.GIDMappings != nil:
		spec.Linux.UIDMappings = cfg.UIDMappings
		spec.Linux.GIDMappings = cfg.GIDMappings
	case os.Geteuid() != 0 && !cfg.SkipDefaultNamespaces:
		spec.Linux.UIDMappings = []specs.LinuxIDMapping{
			{ContainerID: 0, HostID: uint32(os.Geteuid()), Size: 1},
		}
		spec.Linux.GIDMappings = []specs.LinuxIDMapping{
			{ContainerID: 0, HostID: uint32(os.Getegid()), Size: 1},
		}
	}

	if !cfg.SkipLinuxSystemMounts {
		spec.Mounts = append(spec.Mounts,
			specs.Mount{Destination: "/proc", Type: "proc", Source: "proc"},
			specs.Mount{Destination: "/dev", Type: "tmpfs", Source: "tmpfs"},
		)
	}

	// Map host binaries & libraries as readonly. The binaries will be
	// executed in gVisor sandbox, not on the host.
	if !cfg.SkipHostBinaryMounts {
		for _, p := range hostBinaryDirs {
			if _, err := os.Stat(p); err == nil {
				opts := []string{"rbind", "ro", "nosuid", "nodev"}
				if p == "/etc/alternatives" {
					opts = []string{"rbind", "ro"}
				}
				spec.Mounts = append(spec.Mounts, specs.Mount{
					Destination: p,
					Type:        "bind",
					Source:      p,
					Options:     opts,
				})
			}
		}
	}

	// Add custom mounts. Custom mounts overriding default host mounts create duplicate OCI
	// entries. The later entry overrides the earlier one, as expected by OCI specs.
	if err := checkOverlayMounts(cfg); err != nil {
		return nil, err
	}
	for i, m := range cfg.Mounts {
		if m.Type == MountTypeOverlay {
			oms, err := m.ociOverlayMounts(i)
			if err != nil {
				return nil, err
			}
			spec.Mounts = append(spec.Mounts, oms...)
			continue
		}
		om, err := m.ociMount()
		if err != nil {
			return nil, err
		}
		spec.Mounts = append(spec.Mounts, om)
	}

	return spec, nil
}

// newBundle creates an OCI bundle on the fly with the given configuration and
// returns its directory.
func newBundle(cfg bundleConfig) (string, error) {
	spec, err := newSpec(cfg)
	if err != nil {
		return "", err
	}

	bundleDir := filepath.Join(cfg.RuntimeDir, cfg.ID)
	createDir := bundleDir
	if cfg.RootPath == "" {
		createDir = filepath.Join(bundleDir, defaultRootfsDir)
	}
	if err := os.MkdirAll(createDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create bundle directories: %w", err)
	}

	// Write the spec to config.json
	configPath := filepath.Join(bundleDir, "config.json")
	configFile, err := os.Create(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to create config.json: %w", err)
	}
	defer configFile.Close()

	encoder := json.NewEncoder(configFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(spec); err != nil {
		return "", fmt.Errorf("failed to encode config.json: %w", err)
	}

	return bundleDir, nil
}
