// Copyright 2018 The gVisor Authors.
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

package specutils

import (
	"fmt"
	"math/bits"
	"path"
	"slices"
	"sort"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
)

type mapping struct {
	set bool
	val uint32
}

// optionsMap maps mount propagation-related OCI filesystem options to mount(2)
// syscall flags.
var optionsMap = map[string]mapping{
	"acl":           {set: true, val: unix.MS_POSIXACL},
	"async":         {set: false, val: unix.MS_SYNCHRONOUS},
	"atime":         {set: false, val: unix.MS_NOATIME},
	"bind":          {set: true, val: unix.MS_BIND},
	"defaults":      {set: true, val: 0},
	"dev":           {set: false, val: unix.MS_NODEV},
	"diratime":      {set: false, val: unix.MS_NODIRATIME},
	"dirsync":       {set: true, val: unix.MS_DIRSYNC},
	"exec":          {set: false, val: unix.MS_NOEXEC},
	"noexec":        {set: true, val: unix.MS_NOEXEC},
	"iversion":      {set: true, val: unix.MS_I_VERSION},
	"loud":          {set: false, val: unix.MS_SILENT},
	"mand":          {set: true, val: unix.MS_MANDLOCK},
	"noacl":         {set: false, val: unix.MS_POSIXACL},
	"noatime":       {set: true, val: unix.MS_NOATIME},
	"nodev":         {set: true, val: unix.MS_NODEV},
	"nodiratime":    {set: true, val: unix.MS_NODIRATIME},
	"noiversion":    {set: false, val: unix.MS_I_VERSION},
	"nomand":        {set: false, val: unix.MS_MANDLOCK},
	"norelatime":    {set: false, val: unix.MS_RELATIME},
	"nostrictatime": {set: false, val: unix.MS_STRICTATIME},
	"nosuid":        {set: true, val: unix.MS_NOSUID},
	"rbind":         {set: true, val: unix.MS_BIND | unix.MS_REC},
	"relatime":      {set: true, val: unix.MS_RELATIME},
	"remount":       {set: true, val: unix.MS_REMOUNT},
	"ro":            {set: true, val: unix.MS_RDONLY},
	"rw":            {set: false, val: unix.MS_RDONLY},
	"silent":        {set: true, val: unix.MS_SILENT},
	"strictatime":   {set: true, val: unix.MS_STRICTATIME},
	"suid":          {set: false, val: unix.MS_NOSUID},
	"sync":          {set: true, val: unix.MS_SYNCHRONOUS},
}

// propOptionsMap is similar to optionsMap, but it lists propagation options
// that cannot be used together with other flags.
var propOptionsMap = map[string]mapping{
	"private":     {set: true, val: unix.MS_PRIVATE},
	"rprivate":    {set: true, val: unix.MS_PRIVATE | unix.MS_REC},
	"slave":       {set: true, val: unix.MS_SLAVE},
	"rslave":      {set: true, val: unix.MS_SLAVE | unix.MS_REC},
	"unbindable":  {set: true, val: unix.MS_UNBINDABLE},
	"runbindable": {set: true, val: unix.MS_UNBINDABLE | unix.MS_REC},
}

// invalidOptions list options not allowed.
//   - shared: sandbox must be isolated from the host. Propagating mount changes
//     from the sandbox to the host breaks the isolation. The sandbox's mount
//     table is maintained in sentry memory. Mount operations from the application
//     are not propagated to the host.
var invalidOptions = []string{"shared", "rshared"}

// OptionsToFlags converts mount options to syscall flags.
func OptionsToFlags(opts []string) uint32 {
	return optionsToFlags(opts, optionsMap)
}

// PropOptionsToFlags converts propagation mount options to syscall flags.
// Propagation options cannot be set other with other options and must be
// handled separately.
func PropOptionsToFlags(opts []string) uint32 {
	return optionsToFlags(opts, propOptionsMap)
}

func optionsToFlags(opts []string, source map[string]mapping) uint32 {
	var rv uint32
	for _, opt := range opts {
		if m, ok := source[opt]; ok {
			if m.set {
				rv |= m.val
			} else {
				rv &= ^m.val
			}
		}
	}
	return rv
}

// IsReadonlyMount returns true if the mount options has read only option.
func IsReadonlyMount(opts []string) bool {
	for _, o := range opts {
		if o == "ro" {
			return true
		}
	}
	return false
}

// validateMount validates that spec mounts are correct.
func validateMount(mnt *specs.Mount) error {
	if !path.IsAbs(mnt.Destination) {
		return fmt.Errorf("Mount.Destination must be an absolute path: %v", mnt)
	}
	if IsGoferMount(*mnt) {
		return ValidateMountOptions(mnt.Options)
	}
	if _, _, err := OverlayLayersOf(*mnt); err != nil {
		return err
	}
	return nil
}

const (
	// OverlayLowerOption is an option of a mount of type "overlay". Its value
	// is the destination of an earlier bind mount in the same spec, which
	// becomes a read-only layer of the overlay. Give it once for each layer,
	// from the bottom layer to the top layer. runsc mounts the layer mounts
	// of an overlay only as its layers, but the gofer still mounts them at
	// their destinations in the root filesystem. So an earlier tmpfs mount at
	// "/" must hide them, no other mount can be at, above or below them, and
	// their destinations must not go through symlinks in the root
	// filesystem.
	OverlayLowerOption = "dev.gvisor.overlay.lower"

	// OverlayUpperOption is an option of a mount of type "overlay". Its value
	// is the destination of an earlier mount in the same spec, which receives
	// the changes made in the overlay. Without it, the changes stay in memory,
	// or fail with EROFS if the overlay is read-only.
	OverlayUpperOption = "dev.gvisor.overlay.upper"
)

// OverlayLayers holds the layers of an overlay mount, by the destinations of
// the mounts that supply them.
type OverlayLayers struct {
	// Lowers are the read-only layers, from the bottom layer to the top layer.
	Lowers []string

	// Upper is the writable layer, or "" if the overlay has none.
	Upper string
}

// OverlayLayersOf returns the layers of m and the rest of its options. If m is
// not an overlay mount with OverlayLowerOption, OverlayLayersOf returns nil
// layers and m.Options. runsc does not mount such overlay mounts.
func OverlayLayersOf(m specs.Mount) (*OverlayLayers, []string, error) {
	if m.Type != "overlay" {
		return nil, m.Options, nil
	}
	var (
		layers   OverlayLayers
		rest     []string
		hasUpper bool
	)
	for _, o := range m.Options {
		key, val, _ := strings.Cut(o, "=")
		switch key {
		case OverlayLowerOption:
			layers.Lowers = append(layers.Lowers, val)
		case OverlayUpperOption:
			if hasUpper {
				return nil, nil, fmt.Errorf("overlay mount at %q has more than one %s option", m.Destination, OverlayUpperOption)
			}
			hasUpper = true
			layers.Upper = val
		default:
			rest = append(rest, o)
		}
	}
	if len(layers.Lowers) == 0 {
		if hasUpper {
			return nil, nil, fmt.Errorf("overlay mount at %q has a %s option but no %s option", m.Destination, OverlayUpperOption, OverlayLowerOption)
		}
		return nil, m.Options, nil
	}
	all := layers.Lowers
	if hasUpper {
		all = append(slices.Clone(all), layers.Upper)
	}
	for i, l := range all {
		if !path.IsAbs(l) || path.Clean(l) != l {
			return nil, nil, fmt.Errorf("overlay mount at %q has layer %q, which is not a clean absolute path", m.Destination, l)
		}
		if slices.Contains(all[:i], l) {
			return nil, nil, fmt.Errorf("overlay mount at %q uses layer %q more than once", m.Destination, l)
		}
	}
	if IsReadonlyMount(rest) {
		if hasUpper {
			return nil, nil, fmt.Errorf("read-only overlay mount at %q cannot have a %s option", m.Destination, OverlayUpperOption)
		}
		if len(layers.Lowers) < 2 {
			return nil, nil, fmt.Errorf("read-only overlay mount at %q needs 2 or more %s options", m.Destination, OverlayLowerOption)
		}
	}
	return &layers, rest, nil
}

// FilterMountOptions filters out all invalid mount options.
func FilterMountOptions(opts []string) []string {
	out := make([]string, 0, len(opts))
	for _, o := range opts {
		if err := validateMountOption(o); err == nil {
			out = append(out, o)
		} else {
			log.Warningf("mount option skipped %q: %v", o, err)
		}
	}
	return out
}

// ValidateMountOptions validates that mount options are correct.
func ValidateMountOptions(opts []string) error {
	for _, o := range opts {
		if err := validateMountOption(o); err != nil {
			return err
		}
	}
	return nil
}

func validateMountOption(o string) error {
	if slices.Contains(invalidOptions, o) {
		return fmt.Errorf("mount option %q is not supported", o)
	}
	return validatePropagation(o)
}

// ValidateRootfsPropagation validates that rootfs propagation options are
// correct.
func validateRootfsPropagation(opt string) error {
	flags := PropOptionsToFlags([]string{opt})
	if flags&(unix.MS_SLAVE|unix.MS_PRIVATE) == 0 {
		return fmt.Errorf("root mount propagation option must specify private or slave: %q", opt)
	}
	return validatePropagation(opt)
}

func validatePropagation(opt string) error {
	flags := PropOptionsToFlags([]string{opt})
	exclusive := flags & (unix.MS_SLAVE | unix.MS_PRIVATE | unix.MS_SHARED | unix.MS_UNBINDABLE)
	if bits.OnesCount32(exclusive) > 1 {
		return fmt.Errorf("mount propagation options are mutually exclusive: %q", opt)
	}
	return nil
}

// KnownMountOptions returns a sorted list of all supported mount options.
// Used by `runsc features`.
func KnownMountOptions() []string {
	res := make([]string, 0, len(optionsMap)+len(propOptionsMap))
	for k := range optionsMap {
		res = append(res, k)
	}
	for k := range propOptionsMap {
		res = append(res, k)
	}
	sort.Strings(res)
	return res
}
