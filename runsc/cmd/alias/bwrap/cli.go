// Copyright 2025 The gVisor Authors.
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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

const (
	flagBind          = "bind"
	flagRoBind        = "ro-bind"
	flagTmpfs         = "tmpfs"
	flagUnshareNet    = "unshare-net"
	flagChdir         = "chdir"
	flagHelp          = "help"
	flagSetEnv        = "setenv"
	flagClearEnv      = "clearenv"
	flagUnsetEnv      = "unsetenv"
	flagUID           = "uid"
	flagGID           = "gid"
	flagUnshareUser   = "unshare-user"
	flagUserns        = "userns"
	flagUnshareIPC    = "unshare-ipc"
	flagUnsharePID    = "unshare-pid"
	flagUnshareUTS    = "unshare-uts"
	flagHostname      = "hostname"
	flagProc          = "proc"
	flagUnshareCgroup = "unshare-cgroup"
	flagUnshareAll    = "unshare-all"
	flagShareNet      = "share-net"
	flagCapDrop       = "cap-drop"
	flagCapAdd        = "cap-add"
	flagNewSession    = "new-session"
	flagDieWithParent = "die-with-parent"
	flagArgv0         = "argv0"
	flagPerms         = "perms"
	flagDir           = "dir"
	flagAsPID1        = "as-pid-1"
	flagDev           = "dev"
	flagOverlaySrc    = "overlay-src"
	flagOverlay       = "overlay"
	flagTmpOverlay    = "tmp-overlay"
	flagRoOverlay     = "ro-overlay"
)

// Cli implements subcommands.Command for the "bwrap" command.
type Cli struct {
	// Placeholders for bwrap flags.
	bind          string
	roBind        string
	tmpfs         string
	unshareNet    bool
	chdir         string
	setEnv        string
	clearEnv      bool
	unsetEnv      string
	uid           int
	gid           int
	unshareUser   bool
	unshareIPC    bool
	unsharePID    bool
	unshareUTS    bool
	unshareCgroup bool
	unshareAll    bool
	hostname      string
	proc          string
	capDrop       string
	capAdd        string
	newSession    bool
	dieWithParent bool
	argv0         string
	perms         string
	dir           string
	asPID1        bool
	dev           string
	overlaySrc    string
	overlay       string
	tmpOverlay    string
	roOverlay     string
}

// Name implements subcommands.Command.Name.
func (*Cli) Name() string {
	return "bwrap"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Cli) Synopsis() string {
	return "Bubblewrap-compatible sandboxing command."
}

// Usage implements subcommands.Command.Usage.
func (*Cli) Usage() string {
	return "bwrap [flags] <cmd> - runs command in gVisor sandbox with a bubblewrap-like cli.\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Cli) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.bind, flagBind, "", "Bind mount SRC to DEST.")
	f.StringVar(&c.roBind, flagRoBind, "", "Read-only bind mount SRC to DEST.")
	f.StringVar(&c.tmpfs, flagTmpfs, "", "Mount tmpfs at DEST.")
	f.BoolVar(&c.unshareNet, flagUnshareNet, false, "Unshare network namespace.")
	f.StringVar(&c.chdir, flagChdir, "", "Change directory to DIR.")
	f.StringVar(&c.setEnv, flagSetEnv, "", "Set an environment variable")
	f.BoolVar(&c.clearEnv, flagClearEnv, false, "Unset all environment variables")
	f.StringVar(&c.unsetEnv, flagUnsetEnv, "", "Unset an environment variable")
	f.IntVar(&c.uid, flagUID, -1, "Custom uid in the sandbox (requires --unshare-user or --userns)")
	f.IntVar(&c.gid, flagGID, -1, "Custom gid in the sandbox (requires --unshare-user or --userns)")
	f.BoolVar(&c.unshareUser, flagUnshareUser, false, "Create new user namespace (may be automatically implied if not root)")
	f.BoolVar(&c.unshareIPC, flagUnshareIPC, false, "Create new ipc namespace")
	f.BoolVar(&c.unsharePID, flagUnsharePID, false, "Create new pid namespace")
	f.BoolVar(&c.unshareUTS, flagUnshareUTS, false, "Create new uts namespace")
	f.StringVar(&c.hostname, flagHostname, "", "Custom hostname in the sandbox")
	f.StringVar(&c.proc, flagProc, "", "Mount new procfs on DEST")
	f.BoolVar(&c.unshareCgroup, flagUnshareCgroup, false, "Create new cgroup namespace")
	f.BoolVar(&c.unshareAll, flagUnshareAll, false, "Unshare every namespace we support by default")
	f.StringVar(&c.capDrop, flagCapDrop, "", "Drop capabilities when running as privileged user")
	f.StringVar(&c.capAdd, flagCapAdd, "", "Add capabilities when running as privileged user")
	f.BoolVar(&c.newSession, flagNewSession, false, "Create a new terminal session")
	f.BoolVar(&c.dieWithParent, flagDieWithParent, false, "Kills with SIGKILL child process (COMMAND) when runsc or runsc's parent dies")
	f.StringVar(&c.argv0, flagArgv0, "", "Set argv[0] to VALUE before running the program")
	f.StringVar(&c.perms, flagPerms, "", "Set permissions of the next argument (--tmpfs, --dir)")
	f.StringVar(&c.dir, flagDir, "", "Create dir at DEST")
	f.BoolVar(&c.asPID1, flagAsPID1, false, "Do not install a reaper process with PID=1")
	f.StringVar(&c.dev, flagDev, "", "Mount new dev on DEST")
	f.StringVar(&c.overlaySrc, flagOverlaySrc, "", "Add SRC as an overlay layer")
	f.StringVar(&c.overlay, flagOverlay, "", "Mount an overlay at DEST that writes changes to RWSRC (args: RWSRC WORKDIR DEST)")
	f.StringVar(&c.tmpOverlay, flagTmpOverlay, "", "Mount an overlay at DEST that keeps changes in memory")
	f.StringVar(&c.roOverlay, flagRoOverlay, "", "Mount a read-only overlay at DEST")

	// Override the default usage function to print the custom usage message.
	f.Usage = func() {
		fmt.Fprint(f.Output(), c.Usage())
		fmt.Fprint(f.Output(), "\nSupported flags:\n")
		f.VisitAll(func(fl *flag.Flag) {
			fmt.Fprintf(f.Output(), "  --%-20s %s\n", fl.Name, fl.Usage)
		})
	}
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (c *Cli) FetchSpec(_ *config.Config, _ *flag.FlagSet) (string, *specs.Spec, error) {
	return "", nil, nil
}

// parseBwrapArgs parses the bwrap arguments and returns a bwrapConfig struct.
func parseBwrapArgs(bwrapArgs []string) (*bwrapConfig, error) {
	cfg := &bwrapConfig{
		Env: os.Environ(),
		UID: -1,
		GID: -1,
	}
	var err error
	for i := 0; i < len(bwrapArgs); {
		arg := bwrapArgs[i]

		// --perms only modifies the operation that immediately follows it.
		if cfg.nextPerms != nil && (!strings.HasPrefix(arg, "--") || !acceptsPerms(strings.TrimPrefix(arg, "--"))) {
			return nil, fmt.Errorf("bwrap: --%s must be followed by an option that creates a file", flagPerms)
		}

		// The --overlay-src layers go only to the overlay option right after
		// them.
		if len(cfg.overlaySrcs) > 0 && !isOverlayFlag(arg) {
			return nil, errOverlaySrcUnused
		}

		// Bwrap passes the rest of the arguments to the command.
		if arg == "--" {
			cfg.Args = bwrapArgs[i+1:]
			break
		}
		if !strings.HasPrefix(arg, "--") {
			// Bwrap does not allow flags with `-` prefix.
			if strings.HasPrefix(arg, "-") {
				return nil, fmt.Errorf("bwrap: Unknown option: %s", arg)
			}
			// If the argument is not a flag, pass the rest of the args as application arguments.
			cfg.Args = bwrapArgs[i:]
			break
		}
		// Parse the flags.
		strippedArg := strings.TrimPrefix(arg, "--")
		switch strippedArg {
		case flagBind:
			i, err = cfg.parseBind(bwrapArgs, i)
		case flagRoBind:
			i, err = cfg.parseRoBind(bwrapArgs, i)
		case flagTmpfs:
			i, err = cfg.parseTmpfs(bwrapArgs, i)
		case flagUnshareNet:
			i, err = cfg.parseUnshareNet(bwrapArgs, i)
		case flagShareNet:
			i, err = cfg.parseShareNet(bwrapArgs, i)
		case flagChdir:
			i, err = cfg.parseChdir(bwrapArgs, i)
		case flagSetEnv:
			i, err = cfg.parseSetEnv(bwrapArgs, i)
		case flagClearEnv:
			i, err = cfg.parseClearEnv(bwrapArgs, i)
		case flagUnsetEnv:
			i, err = cfg.parseUnsetEnv(bwrapArgs, i)
		case flagUID:
			i, err = cfg.parseUID(bwrapArgs, i)
		case flagGID:
			i, err = cfg.parseGID(bwrapArgs, i)
		case flagUnshareUser:
			i, err = cfg.parseUnshareUser(bwrapArgs, i)
		case flagUserns:
			i, err = cfg.parseUserns(bwrapArgs, i)
		case flagHostname:
			i, err = cfg.parseHostname(bwrapArgs, i)
		case flagUnshareIPC, flagUnsharePID, flagUnshareUTS, flagUnshareCgroup, flagNewSession, flagDieWithParent:
			i, err = cfg.parseNoopZeroArg(bwrapArgs, i)
		case flagProc:
			i, err = cfg.parseProc(bwrapArgs, i)
		case flagUnshareAll:
			i, err = cfg.parseUnshareAll(bwrapArgs, i)
		case flagCapDrop:
			i, err = cfg.parseCapDrop(bwrapArgs, i)
		case flagCapAdd:
			i, err = cfg.parseCapAdd(bwrapArgs, i)
		case flagArgv0:
			i, err = cfg.parseArgv0(bwrapArgs, i)
		case flagPerms:
			i, err = cfg.parsePerms(bwrapArgs, i)
		case flagDir:
			i, err = cfg.parseDir(bwrapArgs, i)
		case flagAsPID1:
			i, err = cfg.parseAsPID1(bwrapArgs, i)
		case flagDev:
			i, err = cfg.parseDev(bwrapArgs, i)
		case flagOverlaySrc:
			i, err = cfg.parseOverlaySrc(bwrapArgs, i)
		case flagOverlay:
			i, err = cfg.parseOverlay(bwrapArgs, i)
		case flagTmpOverlay:
			i, err = cfg.parseTmpOverlay(bwrapArgs, i)
		case flagRoOverlay:
			i, err = cfg.parseRoOverlay(bwrapArgs, i)
		default:
			return nil, fmt.Errorf("bwrap: Unknown option: %s", arg)
		}
		if err != nil {
			return nil, err
		}
	}

	if len(cfg.overlaySrcs) > 0 {
		return nil, errOverlaySrcUnused
	}

	cfg.resolveEnv()

	if len(cfg.Args) == 0 || cfg.Args[0] == "" {
		return nil, fmt.Errorf("bwrap: no command specified")
	}
	return cfg, nil
}

func (c *Cli) getBwrapArgs(args []string) []string {
	delimiter := c.Name()
	// Skip all arguments until the delimiter.
	for i, arg := range args {
		if arg == delimiter {
			return args[i+1:]
		}
	}
	return nil
}

// Execute implements subcommands.Command.Execute.
func (c *Cli) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	conf := args[0].(*config.Config)
	waitStatus := args[1].(*unix.WaitStatus)

	// Parse bwrap arguments.
	bwrapArgs := c.getBwrapArgs(os.Args)
	cfg, err := parseBwrapArgs(bwrapArgs)
	if err != nil {
		return util.Errorf("bwrap: %v", err)
	}
	cfg.runscConfig = conf
	// When called as `runsc bwrap`, arguments start at index 2.
	return do(ctx, cfg, waitStatus)
}

/*
Flags parsing functions below.
*/

func (c *bwrapConfig) parseBind(args []string, i int) (int, error) {
	if i+2 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 2 arguments", flagBind)
	}
	mnt, err := c.newMount(args[i+1], args[i+2], sandbox.MountTypeBind, false /* readOnly */)
	if err != nil {
		return i, err
	}
	c.Mounts = append(c.Mounts, mnt)
	return i + 3, nil
}

func (c *bwrapConfig) parseRoBind(args []string, i int) (int, error) {
	if i+2 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 2 arguments", flagRoBind)
	}
	mnt, err := c.newMount(args[i+1], args[i+2], sandbox.MountTypeBind, true /* readOnly */)
	if err != nil {
		return i, err
	}
	c.Mounts = append(c.Mounts, mnt)
	return i + 3, nil
}

func (c *bwrapConfig) parseTmpfs(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagTmpfs)
	}
	mnt, err := c.newMount("", args[i+1], sandbox.MountTypeTmpfs, false /* readOnly */)
	if err != nil {
		return i, err
	}
	mnt.Mode = c.takePerms()
	c.Mounts = append(c.Mounts, mnt)
	return i + 2, nil
}

// parseDir handles --dir DEST. It is a no-op
// when DEST exists, otherwise a mkdir in whatever filesystem holds DEST. When
// a bind mount declared before --dir covers DEST, that filesystem is on the
// host, so do() applies the same rules to the host path. Otherwise DEST lives
// in a sandbox filesystem that runsc cannot reach before the sandbox starts.
// DEST already exists there if an earlier mount sits at or below it, so --dir
// does nothing. If not, an empty tmpfs mounted at DEST stands in for the
// directory.
func (c *bwrapConfig) parseDir(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagDir)
	}
	dst := args[i+1]
	perms := c.takePerms()
	if bind, hostPath, ok := c.hostPath(dst); ok {
		dir := HostDir{Dest: dst, Path: hostPath, ReadOnly: bind.ReadOnly, Perms: defaultDirPerms}
		if perms != nil {
			dir.Perms = *perms
		}
		c.HostDirs = append(c.HostDirs, dir)
		return i + 2, nil
	}
	if c.hasMountAtOrBelow(dst) {
		return i + 2, nil
	}
	mnt, err := c.newMount("", dst, sandbox.MountTypeTmpfs, false /* readOnly */)
	if err != nil {
		return i, err
	}
	mnt.Mode = perms
	c.Mounts = append(c.Mounts, mnt)
	return i + 2, nil
}

func (c *bwrapConfig) parseUnshareNet(args []string, i int) (int, error) {
	c.UnshareNet = true
	return i + 1, nil
}

func (c *bwrapConfig) parseChdir(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("--%s takes 1 argument", flagChdir)
	}
	c.Chdir = args[i+1]
	return i + 2, nil
}

func (c *bwrapConfig) parseSetEnv(args []string, i int) (int, error) {
	if i+2 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 2 arguments", flagSetEnv)
	}
	c.Env = append(c.Env, args[i+1]+"="+args[i+2])
	return i + 3, nil
}

func (c *bwrapConfig) parseClearEnv(args []string, i int) (int, error) {
	pwd, err := c.mapCWD()
	if err != nil {
		return i, fmt.Errorf("bwrap: failed to get current working directory: %v", err)
	}
	c.Env = nil
	if pwd != "" {
		c.Env = []string{"PWD=" + pwd}
	}
	c.UnsetEnv = nil
	return i + 1, nil
}

func (c *bwrapConfig) parseUnsetEnv(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagUnsetEnv)
	}
	c.UnsetEnv = append(c.UnsetEnv, args[i+1])
	return i + 2, nil
}

func (c *bwrapConfig) parseUID(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagUID)
	}
	uid, err := strconv.ParseUint(args[i+1], 10, 32)
	if err != nil {
		return i, fmt.Errorf("bwrap: Invalid uid %v: %v", args[i+1], err)
	}
	c.UID = int(uid)

	return i + 2, nil
}

func (c *bwrapConfig) parseGID(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagGID)
	}
	gid, err := strconv.ParseUint(args[i+1], 10, 32)
	if err != nil {
		return i, fmt.Errorf("bwrap: Invalid gid %v: %v", args[i+1], err)
	}
	c.GID = int(gid)

	return i + 2, nil
}

func (c *bwrapConfig) parseUnshareUser(args []string, i int) (int, error) {
	c.UnshareUser = true
	return i + 1, nil
}

func (c *bwrapConfig) parseHostname(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagHostname)
	}
	c.Hostname = args[i+1]
	return i + 2, nil
}

func (c *bwrapConfig) parseProc(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("--%s takes 1 argument", flagProc)
	}

	dst := filepath.Clean(args[i+1])
	for _, m := range c.Mounts {
		if m.Type == sandbox.MountTypeProc && m.Destination == dst {
			return i + 2, nil
		}
	}
	mnt, err := c.newMount("", dst, sandbox.MountTypeProc, false /* readOnly */)
	if err != nil {
		return i, err
	}
	c.Mounts = append(c.Mounts, mnt)

	return i + 2, nil
}

// parseDev handles --dev DEST. gVisor's dev filesystem provides the device
// nodes and symlinks that bubblewrap bind mounts from the host, but only an
// empty pts directory, so a devpts is mounted at DEST/pts as bubblewrap does.
func (c *bwrapConfig) parseDev(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagDev)
	}

	dst := filepath.Clean(args[i+1])
	for _, m := range append(defaultMounts(), c.Mounts...) {
		if m.Type == sandbox.MountTypeDevtmpfs && m.Destination == dst {
			return i + 2, nil
		}
	}
	dev, err := c.newMount("", dst, sandbox.MountTypeDevtmpfs, false /* readOnly */)
	if err != nil {
		return i, err
	}
	pts, err := c.newMount("", filepath.Join(dst, "pts"), sandbox.MountTypeDevpts, false /* readOnly */)
	if err != nil {
		return i, err
	}
	c.Mounts = append(c.Mounts, dev, pts)

	return i + 2, nil
}

// errOverlaySrcUnused reports --overlay-src layers that no overlay option
// takes.
var errOverlaySrcUnused = fmt.Errorf("bwrap: no overlay option takes the --%s layers; put --%s, --%s or --%s directly after them", flagOverlaySrc, flagOverlay, flagTmpOverlay, flagRoOverlay)

// isOverlayFlag reports whether arg is --overlay-src or an option that mounts
// the --overlay-src layers.
func isOverlayFlag(arg string) bool {
	switch arg {
	case "--" + flagOverlaySrc, "--" + flagOverlay, "--" + flagTmpOverlay, "--" + flagRoOverlay:
		return true
	}
	return false
}

// parseOverlaySrc handles --overlay-src SRC. In the overlay that the next
// overlay option mounts, SRC goes on top of the layers given before it.
func (c *bwrapConfig) parseOverlaySrc(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagOverlaySrc)
	}
	src, err := hostDir(args[i+1])
	if err != nil {
		return i, err
	}
	c.overlaySrcs = append(c.overlaySrcs, src)
	return i + 2, nil
}

// parseOverlay handles --overlay RWSRC WORKDIR DEST. The changes made in the
// overlay go to RWSRC. runsc does not use WORKDIR, but it must be a directory
// that does not overlap RWSRC, and that is not a layer or above one.
func (c *bwrapConfig) parseOverlay(args []string, i int) (int, error) {
	if i+3 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 3 arguments", flagOverlay)
	}
	upper, err := hostDir(args[i+1])
	if err != nil {
		return i, err
	}
	work, err := hostDir(args[i+2])
	if err != nil {
		return i, err
	}
	resolved, err := resolveDirs(append([]string{work, upper}, c.overlaySrcs...))
	if err != nil {
		return i, err
	}
	rWork, rUpper := resolved[0], resolved[1]
	if contains(rWork, rUpper) || contains(rUpper, rWork) {
		return i, fmt.Errorf("bwrap: --%s: WORKDIR %s and RWSRC %s overlap", flagOverlay, work, upper)
	}
	for j, rLower := range resolved[2:] {
		if contains(rWork, rLower) {
			return i, fmt.Errorf("bwrap: --%s: WORKDIR %s is or contains the layer %s", flagOverlay, work, c.overlaySrcs[j])
		}
	}
	mnt, err := c.newOverlay(flagOverlay, args[i+3], 1, upper)
	if err != nil {
		return i, err
	}
	c.Mounts = append(c.Mounts, mnt)
	return i + 4, nil
}

// parseTmpOverlay handles --tmp-overlay DEST. The changes made in the overlay
// stay in sandbox memory.
func (c *bwrapConfig) parseTmpOverlay(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagTmpOverlay)
	}
	mnt, err := c.newOverlay(flagTmpOverlay, args[i+1], 1, "" /* upper */)
	if err != nil {
		return i, err
	}
	c.Mounts = append(c.Mounts, mnt)
	return i + 2, nil
}

// parseRoOverlay handles --ro-overlay DEST. Writes to the overlay fail with
// EROFS.
func (c *bwrapConfig) parseRoOverlay(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagRoOverlay)
	}
	mnt, err := c.newOverlay(flagRoOverlay, args[i+1], 2, "" /* upper */)
	if err != nil {
		return i, err
	}
	mnt.ReadOnly = true
	c.Mounts = append(c.Mounts, mnt)
	return i + 2, nil
}

// newOverlay returns an overlay mount at dst of the --overlay-src layers given
// since the last overlay option, from the first one at the bottom to the last
// one at the top, and of the upper directory upper, if any. The overlay option
// flag needs at least minLayers layers. The overlay ignores set-user-ID bits.
func (c *bwrapConfig) newOverlay(flag, dst string, minLayers int, upper string) (sandbox.Mount, error) {
	if len(c.overlaySrcs) < minLayers {
		return sandbox.Mount{}, fmt.Errorf("bwrap: --%s needs %d or more --%s options directly before it", flag, minLayers, flagOverlaySrc)
	}
	dirs := c.overlaySrcs
	if upper != "" {
		dirs = append(slices.Clone(dirs), upper)
	}
	// Mount the paths that the check sees.
	resolved, err := checkNoOverlap(flag, dirs)
	if err != nil {
		return sandbox.Mount{}, err
	}
	lowers := resolved[:len(c.overlaySrcs)]
	if upper != "" {
		upper = resolved[len(c.overlaySrcs)]
	}
	if dst == "" {
		return sandbox.Mount{}, fmt.Errorf("bwrap: destination path is empty")
	}
	dst = filepath.Clean(dst)
	if dst == "/" {
		return sandbox.Mount{}, fmt.Errorf("bwrap: --%s at / is not supported by runsc", flag)
	}
	mnt := sandbox.Mount{
		Type:        sandbox.MountTypeOverlay,
		Destination: dst,
		Lowers:      lowers,
		Upper:       upper,
		NoSuid:      true,
	}
	c.overlaySrcs = nil
	return mnt, nil
}

// checkNoOverlap returns the host directories dirs with all symlinks
// resolved. It reports an error if two of them are the same directory or one
// contains the other. The layers of an overlay must not overlap, so that
// changes to the overlay cannot reach a lower layer.
func checkNoOverlap(flag string, dirs []string) ([]string, error) {
	resolved, err := resolveDirs(dirs)
	if err != nil {
		return nil, err
	}
	for i := range resolved {
		for j := range i {
			if contains(resolved[j], resolved[i]) || contains(resolved[i], resolved[j]) {
				return nil, fmt.Errorf("bwrap: --%s: the overlay directories %s and %s overlap", flag, dirs[j], dirs[i])
			}
		}
	}
	return resolved, nil
}

// resolveDirs returns the absolute host paths dirs with all symlinks resolved.
func resolveDirs(dirs []string) ([]string, error) {
	resolved := make([]string, len(dirs))
	for i, d := range dirs {
		r, err := filepath.EvalSymlinks(d)
		if err != nil {
			return nil, fmt.Errorf("bwrap: Can't find source path %v: %v", d, err)
		}
		resolved[i] = r
	}
	return resolved, nil
}

// contains reports whether the clean absolute path dir is path or one of its
// parents.
func contains(dir, path string) bool {
	return dir == path || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// hostDir returns the absolute path of dir, which must be a directory on the
// host. An empty dir is an error, not the current directory.
func hostDir(dir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("bwrap: Can't find source path: the path is empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("bwrap: Can't get absolute path for source path %v: %v", dir, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("bwrap: Can't find source path %v: %v", abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("bwrap: %v: %v", abs, unix.ENOTDIR)
	}
	return abs, nil
}

// TODO: b/518882196 - Support joining existing user namespaces.
// Currently, runsc cannot join an existing user namespace (specs.UserNamespace with Path != "").
func (c *bwrapConfig) parseUserns(args []string, i int) (int, error) {
	return i + 2, fmt.Errorf("bwrap: --userns is currently not supported by runsc")
}

// parseNoopZeroArg parses flags that are treated as no-ops.
//
// --unshare-ipc, --unshare-pid, --unshare-uts and --unshare-cgroup are no-ops
// because the Sentry already virtualizes those namespaces in every sandbox.
//
// --new-session is a no-op because its purpose is to block TIOCSTI input
// injection into the host terminal, and the Sentry leaves TIOCSTI
// unimplemented (see pkg/sentry/fsimpl/host/tty.go).
//
// --die-with-parent is a no-op because the sandbox init process is a
// /bin/sleep placeholder (see sandboxexec/sandbox/oci.go) and COMMAND runs as
// an exec inside it, so there is no parent-child relationship for
// PR_SET_PDEATHSIG to act on. do() instead bounds the sandbox lifetime with
// sandbox.Close(), which does not run if runsc is SIGKILLed.
//
// All are accepted for bubblewrap CLI compatibility.
func (c *bwrapConfig) parseNoopZeroArg(args []string, i int) (int, error) {
	return i + 1, nil
}

// parseAsPID1 handles --as-pid-1. The /bin/sleep placeholder is PID 1 of the
// sandbox and COMMAND runs as an exec inside it, so do() runs COMMAND in a new
// PID namespace where it is PID 1. The Sentry always gives the sandbox its own
// PID namespace, so this does not require --unshare-pid.
func (c *bwrapConfig) parseAsPID1(args []string, i int) (int, error) {
	c.AsPID1 = true
	return i + 1, nil
}

// TODO: Support --share-net once netstack has a rootless mode.
func (c *bwrapConfig) parseShareNet(args []string, i int) (int, error) {
	return i + 1, fmt.Errorf("bwrap: --%s is currently not supported by runsc", flagShareNet)
}

// Todo: - set unshare-user-try to true also after implementing it.
func (c *bwrapConfig) parseUnshareAll(args []string, i int) (int, error) {
	c.UnshareUser = true
	c.UnshareNet = true
	return i + 1, nil
}

func (c *bwrapConfig) parseCapDrop(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("--%s takes 1 argument", flagCapDrop)
	}
	c.CapOps = append(c.CapOps, &CapOp{Type: CapOpDrop, Cap: args[i+1]})
	return i + 2, nil
}

func (c *bwrapConfig) parseCapAdd(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("--%s takes 1 argument", flagCapAdd)
	}
	c.CapOps = append(c.CapOps, &CapOp{Type: CapOpAdd, Cap: args[i+1]})
	return i + 2, nil
}

func (c *bwrapConfig) parseArgv0(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes one argument", flagArgv0)
	}

	if args[i+1] == "" {
		return i, fmt.Errorf("bwrap: --%s does not support an empty value", flagArgv0)
	}

	if c.hasArgv0 {
		return i, fmt.Errorf("bwrap: --%s used multiple times", flagArgv0)
	}
	c.Argv0 = args[i+1]
	c.hasArgv0 = true
	return i + 2, nil
}

const maxPerms = 07777

func (c *bwrapConfig) parsePerms(args []string, i int) (int, error) {
	if i+1 >= len(args) {
		return i, fmt.Errorf("bwrap: --%s takes 1 argument", flagPerms)
	}
	if c.nextPerms != nil {
		return i, fmt.Errorf("bwrap: --%s given twice for the same action", flagPerms)
	}
	perms, err := strconv.ParseUint(args[i+1], 8, 32)
	if err != nil || perms > maxPerms {
		return i, fmt.Errorf("bwrap: --%s takes an octal argument <= %#o", flagPerms, maxPerms)
	}
	p := uint32(perms)
	c.nextPerms = &p
	return i + 2, nil
}

// acceptsPerms reports whether the flag consumes a pending --perms value.
// --perms itself is included so that repeating it reports its own error.
//
// TODO: b/508701483 - bubblewrap also accepts --perms before --file, --bind-data
// and --ro-bind-data. Add them here as they are implemented.
func acceptsPerms(flagName string) bool {
	return flagName == flagTmpfs || flagName == flagDir || flagName == flagPerms
}
