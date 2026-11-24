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

// Package bwrap implements a bubblewrap-compatible command line for running
// commands in a gVisor sandbox.
package bwrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/sandboxexec/sandbox"
)

// generateUID generates a random ID for the runsc container.
func generateUID() string {
	return fmt.Sprintf("runsc-bwrap-%06d", rand.Int31n(1000000))
}

// CapOpType represents the type of capability operation.
type CapOpType string

const (
	// CapOpDrop represents a capability drop operation.
	CapOpDrop CapOpType = "drop"
	// CapOpAdd represents a capability add operation.
	CapOpAdd CapOpType = "add"
)

// CapOp represents a capability operation.
type CapOp struct {
	Type CapOpType
	Cap  string
}

// defaultDirPerms is the mode bubblewrap gives a --dir without --perms.
const defaultDirPerms = 0755

// HostDir is a --dir that a bind mount backs, so it is created on the host
// rather than mounted as a tmpfs.
type HostDir struct {
	// Dest is the sandbox path, as given on the command line.
	Dest string
	// Path is the host path behind Dest.
	Path string
	// ReadOnly reports whether the bind mount behind Dest is read-only.
	ReadOnly bool
	// Perms is the mode of the directory, from --perms or defaultDirPerms.
	Perms uint32
}

// bwrapConfig represents the configuration for the bwrap sandbox.
type bwrapConfig struct {
	Mounts      []sandbox.Mount
	HostDirs    []HostDir
	CapOps      []*CapOp
	UnshareNet  bool
	Args        []string
	Chdir       string
	runscConfig *config.Config
	Env         []string
	UnsetEnv    []string
	UID         int
	GID         int
	UnshareUser bool
	Hostname    string
	Argv0       string
	AsPID1      bool
	hasArgv0    bool
	nextPerms   *uint32

	// InfoFD is the --info-fd file descriptor, or nil.
	InfoFD *int
	// BlockFD is the --block-fd file descriptor, or nil.
	BlockFD *int
	// unusedFDs holds the descriptors of --info-fd and --block-fd flags that
	// a later one of the same flag replaces.
	unusedFDs []int
}

// String returns a string representation of the bwrapConfig.
func (c *bwrapConfig) String() string {
	j, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("failed to marshal bwrapConfig to JSON: %v", err))
	}
	return string(j)
}

// defaultMounts are the filesystems bwrap provides in every sandbox.
func defaultMounts() []sandbox.Mount {
	return []sandbox.Mount{
		{Destination: "/proc", Type: sandbox.MountTypeProc},
		{Destination: "/sys", Type: sandbox.MountTypeSysfs},
		{Destination: "/dev", Type: sandbox.MountTypeDevtmpfs},
		{Destination: "/dev/pts", Type: sandbox.MountTypeDevpts},
		{Destination: "/sys/fs/cgroup", Type: sandbox.MountTypeCgroup},
		{Destination: "/tmp", Type: sandbox.MountTypeTmpfs},
	}
}

// newMount creates a mount for the sandbox bindings.
func (c *bwrapConfig) newMount(src, dst string, mountType sandbox.MountType, readOnly bool) (sandbox.Mount, error) {
	if dst == "" {
		return sandbox.Mount{}, fmt.Errorf("bwrap: destination path is empty")
	}
	dst = filepath.Clean(dst)
	if mountType != sandbox.MountTypeBind {
		return sandbox.Mount{Type: mountType, Destination: dst}, nil
	}
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return sandbox.Mount{}, fmt.Errorf("bwrap: Can't get absolute path for source path %v: %v", src, err)
	}
	if _, err := os.Stat(src); err != nil {
		return sandbox.Mount{}, fmt.Errorf("bwrap: Can't find source path %v: %v", absSrc, err)
	}
	m := sandbox.Mount{
		Type:        sandbox.MountTypeBind,
		Source:      absSrc,
		Destination: dst,
		ReadOnly:    readOnly,
	}
	if absSrc == "/" {
		m.Recursive, m.Private, m.NoSuid, m.NoDev = true, true, true, true
	}
	return m, nil
}

// getRootMount returns the root mount if it exists.
func (c *bwrapConfig) getRootMount() (sandbox.Mount, bool) {
	for _, m := range c.Mounts {
		if m.Destination == "/" {
			return m, true
		}
	}
	return sandbox.Mount{}, false
}

// subDirPath returns the absolute path of a child path
// if it is a subpath of the parent path.
func (c *bwrapConfig) subDirPath(parent, child string) (string, bool) {
	// Empty paths are not valid.
	if parent == "" || child == "" {
		return "", false
	}
	splitFunc := func(c rune) bool {
		return c == filepath.Separator
	}
	absParent, err := filepath.Abs(parent)
	if err != nil {
		return "", false
	}
	parentParts := strings.FieldsFunc(absParent, splitFunc)

	absChild, err := filepath.Abs(child)
	if err != nil {
		return "", false
	}
	childParts := strings.FieldsFunc(absChild, splitFunc)

	if len(childParts) < len(parentParts) {
		return "", false
	}
	for i := 0; i < len(parentParts); i++ {
		if parentParts[i] != childParts[i] {
			return "", false
		}
	}
	return filepath.Join(parent, filepath.Join(childParts[len(parentParts):]...)), true
}

// mapCWD maps the current working directory to the sandbox directory.
// Follows similar logic as bwrap.
func (c *bwrapConfig) mapCWD() (string, error) {
	cwd := ""
	if c.Chdir != "" {
		cwd = c.Chdir
	} else {
		hostCWD, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get current working directory: %v", err)
		}
		cwd = hostCWD
	}
	for _, m := range c.Mounts {
		if m.Source == "" {
			continue
		}
		if path, ok := c.subDirPath(m.Source, cwd); ok {
			return filepath.Join(m.Destination, strings.TrimPrefix(path, m.Source)), nil
		}
	}
	return "/", nil
}

// hostPath maps a sandbox path to the host path behind it. Mounts stack in
// command-line order, so the most recent mount that covers path decides: a
// bind mount yields its source plus the rest of path, while any other mount
// type, or no mount at all, means the path exists only inside the sandbox.
func (c *bwrapConfig) hostPath(path string) (bind sandbox.Mount, host string, ok bool) {
	path = filepath.Clean(path)
	for i := len(c.Mounts) - 1; i >= 0; i-- {
		m := c.Mounts[i]
		rel, err := filepath.Rel(m.Destination, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		if m.Type != sandbox.MountTypeBind {
			return sandbox.Mount{}, "", false
		}
		return m, filepath.Join(m.Source, rel), true
	}
	return sandbox.Mount{}, "", false
}

// hasMountAtOrBelow reports whether the sandbox already has a directory at
// path because of the mounts declared so far: path is the root, a mount
// point, or a parent of one.
func (c *bwrapConfig) hasMountAtOrBelow(path string) bool {
	path = filepath.Clean(path)
	if path == "/" {
		return true
	}
	for _, m := range c.Mounts {
		rel, err := filepath.Rel(path, m.Destination)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			return true
		}
	}
	return false
}

// userNamespace returns the namespace and the user options implied by
// --unshare-user, --uid and --gid.
func (c *bwrapConfig) userNamespace(sudoUID, sudoGID uint32) []sandbox.Option {
	hostUID := os.Getuid()
	targetUID := hostUID
	if c.UID != -1 {
		targetUID = c.UID
	}
	hostGID := os.Getgid()
	targetGID := hostGID
	if c.GID != -1 {
		targetGID = c.GID
	}

	uidMappings := []specs.LinuxIDMapping{
		{ContainerID: uint32(targetUID), HostID: sudoUID, Size: 1},
	}
	gidMappings := []specs.LinuxIDMapping{
		{ContainerID: uint32(targetGID), HostID: sudoGID, Size: 1},
	}

	// When runsc is executed by root (hostUID == 0), gVisor's Gofer initialization requires Container 0:0
	// to be mapped to Host 0:0 so the Gofer process can successfully call setuid(0)/setgid(0).
	// TODO(gvisor.dev/issue/13747): Have the sandbox bindings add the 0:0 mapping for root sandboxes with a user namespace.
	if hostUID == 0 {
		if targetUID != 0 {
			uidMappings = append(uidMappings, specs.LinuxIDMapping{ContainerID: 0, HostID: 0, Size: 1})
		}
		if targetGID != 0 {
			gidMappings = append(gidMappings, specs.LinuxIDMapping{ContainerID: 0, HostID: 0, Size: 1})
		}
	}

	return []sandbox.Option{
		sandbox.WithUser(uint32(targetUID), uint32(targetGID)),
		sandbox.WithIDMappings(uidMappings, gidMappings),
	}
}

// prepareSandbox validates the sandbox options before creating host directories.
func (c *bwrapConfig) prepareSandbox() ([]sandbox.Option, error) {
	if c.UID != -1 && !c.UnshareUser {
		return nil, fmt.Errorf("bwrap: Specifying --uid requires --unshare-user")
	}
	if c.GID != -1 && !c.UnshareUser {
		return nil, fmt.Errorf("bwrap: Specifying --gid requires --unshare-user")
	}

	cwd, err := c.mapCWD()
	if err != nil {
		return nil, fmt.Errorf("failed to map current working directory: %v", err)
	}

	network := sandbox.NetworkModeHost
	if c.UnshareNet {
		network = sandbox.NetworkModeNone
	}

	opts := []sandbox.Option{
		sandbox.WithID(generateUID()),
		sandbox.WithWorkingDir(cwd),
		// A bubblewrap sandbox holds only what the command line asks for.
		sandbox.WithoutLinuxSystemMounts(),
		sandbox.WithoutHostBinaryMounts(),
		sandbox.WithoutBaseEnv(),
		sandbox.WithEnv(c.Env...),
		// TODO: b/508701483 - Fix support for network args.
		sandbox.WithNetwork(network),
	}
	opts = append(opts,
		sandbox.WithStateDir(c.runscConfig.RootDir),
	)
	if c.runscConfig.Debug {
		opts = append(opts, sandbox.WithDebug(c.runscConfig.DebugLog))
	}
	if c.Hostname != "" {
		opts = append(opts, sandbox.WithHostname(c.Hostname))
	}

	var mounts []sandbox.Mount
	if rootMount, ok := c.getRootMount(); ok {
		opts = append(opts, sandbox.WithRootfs(rootMount.Source, rootMount.ReadOnly))
	} else {
		mounts = append(mounts, sandbox.Mount{Destination: "/", Type: sandbox.MountTypeTmpfs})
	}
	mounts = append(mounts, defaultMounts()...)
	mounts = append(mounts, c.Mounts...)
	opts = append(opts, sandbox.WithMount(mounts...))

	var namespaces []specs.LinuxNamespace
	// Leave ownership unchanged without a user namespace. Otherwise the mapped
	// user must own new host directories so it can enter them even with mode 0700.
	dirUID, dirGID := -1, -1
	if c.UnshareUser {
		sudoUID, err := getEnvID("SUDO_UID", uint32(os.Getuid()))
		if err != nil {
			return nil, err
		}
		sudoGID, err := getEnvID("SUDO_GID", uint32(os.Getgid()))
		if err != nil {
			return nil, err
		}
		namespaces = append(namespaces, specs.LinuxNamespace{Type: specs.UserNamespace})
		opts = append(opts, c.userNamespace(sudoUID, sudoGID)...)
		dirUID, dirGID = int(sudoUID), int(sudoGID)
	}
	opts = append(opts, sandbox.WithNamespaces(namespaces...))

	caps := specutils.AllCapabilities()
	for _, capOp := range c.CapOps {
		normCap, err := normalizeCap(capOp.Cap)
		if err != nil {
			return nil, err
		}
		switch capOp.Type {
		case CapOpAdd:
			addCapability(caps, normCap)
		case CapOpDrop:
			dropCapability(caps, normCap)
		}
	}
	opts = append(opts, sandbox.WithCapabilities(caps))

	if err := c.makeHostDirs(dirUID, dirGID); err != nil {
		return nil, err
	}
	return opts, nil
}

// makeHostDirs applies every --dir that a bind mount backs, as bubblewrap's
// --dir would inside the sandbox: an existing directory is left as it
// is, a missing one is created along with its parents, and a missing one
// under a read-only bind fails with EROFS. The directories outlive the
// sandbox, as they do with bubblewrap.
func (c *bwrapConfig) makeHostDirs(uid, gid int) error {
	for _, d := range c.HostDirs {
		if err := d.make(uid, gid); err != nil {
			return fmt.Errorf("bwrap: Can't mkdir %s: %v", d.Dest, err)
		}
	}
	return nil
}

// make creates d on the host unless it already exists. Every directory it
// creates is handed to uid:gid.
func (d HostDir) make(uid, gid int) error {
	if info, err := os.Stat(d.Path); err == nil {
		if !info.IsDir() {
			return unix.ENOTDIR
		}
		return nil
	}
	if d.ReadOnly {
		return unix.EROFS
	}
	// Collect the missing parents, nearest first, then create them from the
	// top down.
	var parents []string
	for p := filepath.Dir(d.Path); p != "/"; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil {
			break
		}
		parents = append(parents, p)
	}
	for i := len(parents) - 1; i >= 0; i-- {
		if err := mkdir(parents[i], d.parentPerms(), uid, gid); err != nil {
			return err
		}
	}
	return mkdir(d.Path, d.Perms, uid, gid)
}

// parentPerms returns the mode bubblewrap gives the parents it creates for d:
// 0755, minus the group and other bits that d itself does not grant.
func (d HostDir) parentPerms() uint32 {
	perms := uint32(0755)
	if d.Perms&0070 == 0 {
		perms &^= 0050
	}
	if d.Perms&0007 == 0 {
		perms &^= 0005
	}
	return perms
}

// mkdir creates path with mode perms and hands it to uid:gid. bubblewrap
// clears its umask while it sets up the sandbox, so the umask runsc inherits
// must not narrow perms: a chmod after mkdir(2) restores any bits it masked,
// keeping a setgid bit inherited from the parent as mkdir(2) would. A path
// that appeared in the meantime is left as it is.
func mkdir(path string, perms uint32, uid, gid int) error {
	if err := unix.Mkdir(path, perms); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil
		}
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return err
	}
	return unix.Chmod(path, perms|st.Mode&unix.S_ISGID)
}

// inherited reports whether fd is an open descriptor that runsc inherited.
// runsc opens its own descriptors close-on-exec, and a descriptor that
// survived execve is not close-on-exec. The Go runtime opens /dev/null as a
// stdio descriptor that is closed at startup, so such a descriptor counts as
// inherited.
func inherited(fd int) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		return err
	}
	if flags&unix.FD_CLOEXEC != 0 {
		return unix.EBADF
	}
	return nil
}

// runscFDFlags are the global runsc flags that give runsc a descriptor of its
// own.
var runscFDFlags = []string{"log-fd", "debug-log-fd", "panic-log-fd", "coverage-fd"}

// runscFD returns the global runsc flag that gives runsc fd, or "".
func runscFD(fd int) string {
	for _, name := range runscFDFlags {
		if f := flag.Lookup(name); f != nil && f.Value.String() == strconv.Itoa(fd) {
			return name
		}
	}
	return ""
}

// takeFD takes over the --info-fd or --block-fd descriptor fd, named after the
// flag, and returns a close-on-exec duplicate. It closes fd, so that the runsc
// processes that run the sandbox do not keep it open. A stdio descriptor stays
// open, so that runsc can still report errors; nullStdio replaces it later.
func takeFD(fd int, name string) (int, error) {
	if err := inherited(fd); err != nil {
		return -1, fmt.Errorf("bwrap: Invalid --%s %d: %v", name, fd, err)
	}
	if runscName := runscFD(fd); runscName != "" {
		return -1, fmt.Errorf("bwrap: Invalid --%s %d: runsc uses it for --%s", name, fd, runscName)
	}
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		if fd > 2 {
			unix.CloseOnExec(fd)
		}
		return -1, fmt.Errorf("bwrap: Can't use --%s %d: %v", name, fd, err)
	}
	if fd > 2 {
		unix.Close(fd)
	}
	return dup, nil
}

// nullStdio replaces the stdio descriptor fd with /dev/null, which the command
// then sees there. It does nothing if fd is not a stdio descriptor.
func nullStdio(fd int) error {
	if fd < 0 || fd > 2 {
		return nil
	}
	null, err := unix.Open(os.DevNull, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(null)
	if err := unix.Dup3(null, fd, 0); err != nil {
		return fmt.Errorf("can't replace fd %d with %s: %v", fd, os.DevNull, err)
	}
	return nil
}

// infoPollInterval is how often writeInfo checks for a signal while it waits
// for --info-fd to take data.
const infoPollInterval = 100 * time.Millisecond

// writeInfo writes the --info-fd JSON object, with the host PID of the
// sandbox process as "child-pid", to fd, and closes fd. It waits until fd can
// take the object, which is smaller than PIPE_BUF, so the write does not
// block. If a signal comes in sigCh before the write, writeInfo writes
// nothing and returns that signal.
func writeInfo(ctx context.Context, sb *sandbox.Sandbox, fd int, sigCh <-chan os.Signal) (os.Signal, error) {
	defer unix.Close(fd)
	// poll never reports a read-only pipe as ready to write.
	if mode, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err == nil && mode&unix.O_ACCMODE == unix.O_RDONLY {
		return nil, fmt.Errorf("failed to write to --%s: %v", flagInfoFD, unix.EBADF)
	}
	pid, err := sb.PID(ctx)
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(map[string]int{"child-pid": pid}, "", "    ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	for {
		if sig := pendingSignal(sigCh); sig != nil {
			return sig, nil
		}
		n, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}, int(infoPollInterval.Milliseconds()))
		if err == unix.EINTR || (err == nil && n == 0) {
			continue
		}
		// fd is ready, or the write reports the error.
		break
	}
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("failed to write to --%s: %v", flagInfoFD, err)
		}
		data = data[n:]
	}
	return nil, nil
}

// waitBlock waits until fd has data to read, reaches end of file or fails to
// read, then closes fd. It reads at most one byte. A read that would block,
// on a non-blocking descriptor, counts as a failed read.
func waitBlock(fd int) {
	var b [1]byte
	for {
		if _, err := unix.Read(fd, b[:]); err != unix.EINTR {
			break
		}
	}
	unix.Close(fd)
}

// interruptible runs fn and returns nil when fn returns. If a signal is in
// sigCh before or while fn runs, interruptible returns that signal instead,
// and fn continues to run in the background.
func interruptible(sigCh <-chan os.Signal, fn func()) os.Signal {
	if sig := pendingSignal(sigCh); sig != nil {
		return sig
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return nil
	case sig := <-sigCh:
		return sig
	}
}

// pendingSignal returns the signal waiting in sigCh, if any.
func pendingSignal(sigCh <-chan os.Signal) os.Signal {
	select {
	case sig := <-sigCh:
		return sig
	default:
		return nil
	}
}

// do runs the command in a gVisor sandbox and records its exit status.
func do(ctx context.Context, c *bwrapConfig, waitStatus *unix.WaitStatus) subcommands.ExitStatus {
	infoFD, blockFD := -1, -1
	// infoStdio and blockStdio are the descriptors of --info-fd and
	// --block-fd if they are stdio descriptors that runsc uses, or -1.
	infoStdio, blockStdio := -1, -1
	if c.InfoFD != nil {
		fd, err := takeFD(*c.InfoFD, flagInfoFD)
		if err != nil {
			return util.Errorf("%v", err)
		}
		infoFD = fd
		if *c.InfoFD <= 2 {
			infoStdio = *c.InfoFD
		}
		defer func() {
			if infoFD >= 0 {
				unix.Close(infoFD)
			}
		}()
	}
	// A --block-fd that cannot be read releases the command at once. So
	// does one that --info-fd already used, as writing the info closes it.
	if c.BlockFD != nil && (c.InfoFD == nil || *c.BlockFD != *c.InfoFD) {
		if fd, err := takeFD(*c.BlockFD, flagBlockFD); err != nil {
			log.Warningf("%v; not waiting for it", err)
		} else {
			blockFD = fd
			if *c.BlockFD <= 2 {
				blockStdio = *c.BlockFD
			}
		}
	}
	// A replaced --info-fd or --block-fd descriptor must not stay open in the
	// runsc processes that run the sandbox. takeFD has already closed the
	// descriptors in use.
	for _, fd := range c.unusedFDs {
		if fd > 2 && inherited(fd) == nil {
			unix.CloseOnExec(fd)
		}
	}

	// While the sandbox waits for --info-fd and --block-fd, a signal that
	// would otherwise end runsc stops the sandbox instead of leaving it
	// behind. A SIGINT or SIGHUP that runsc started with ignored stays
	// ignored. The Go runtime does not keep SIGTERM and SIGQUIT ignored, so
	// signal.Ignored cannot report them.
	var sigCh chan os.Signal
	if infoFD >= 0 || blockFD >= 0 {
		sigCh = make(chan os.Signal, 1)
		for _, sig := range []os.Signal{unix.SIGINT, unix.SIGTERM, unix.SIGHUP, unix.SIGQUIT} {
			if !signal.Ignored(sig) {
				signal.Notify(sigCh, sig)
			}
		}
		defer signal.Stop(sigCh)
	}
	// stoppedBy records that sig stopped the sandbox before the command ran.
	stoppedBy := func(sig os.Signal) subcommands.ExitStatus {
		log.Infof("bwrap: stopping the sandbox on %v", sig)
		*waitStatus = unix.WaitStatus(sig.(unix.Signal))
		return subcommands.ExitSuccess
	}

	opts, err := c.prepareSandbox()
	if err != nil {
		return util.Errorf("%v", err)
	}
	// Configure the sandbox to invoke the current runsc executable.
	if err := os.Setenv(sandbox.RunscPathEnvVar, specutils.ExePath); err != nil {
		return util.Errorf("bwrap: %v", err)
	}

	sb, err := sandbox.New(ctx, opts...)
	if err != nil {
		return util.Errorf("bwrap: %v", err)
	}
	defer func() {
		if err := sb.Close(ctx); err != nil {
			log.Warningf("bwrap: failed to clean up sandbox: %v", err)
		}
	}()

	execOpts := []sandbox.ExecOption{
		sandbox.WithExecStdio(os.Stdin, os.Stdout, os.Stderr),
		sandbox.WithExecSignalRelay(),
	}
	if c.AsPID1 {
		execOpts = append(execOpts, sandbox.WithExecNewPIDNamespace())
	}
	argv := c.Args
	if c.hasArgv0 {
		// bwrap names the program with COMMAND and lets --argv0 replace argv[0],
		// so pass the program path separately from the argv it runs with.
		execOpts = append(execOpts, sandbox.WithExecPath(argv[0]))
		argv = append([]string{c.Argv0}, argv[1:]...)
	}

	// The sandbox runs before --info-fd reports its PID, and the command
	// waits for --block-fd. A signal stops either wait, which lasts as long
	// as the process at the other end of the descriptor wants. Once a signal
	// stops the sandbox, nothing is written to --info-fd.
	if infoFD >= 0 {
		fd := infoFD
		infoFD = -1
		sig, err := writeInfo(ctx, sb, fd, sigCh)
		if sig != nil {
			return stoppedBy(sig)
		}
		if err != nil {
			return util.Errorf("bwrap: %v", err)
		}
		if err := nullStdio(infoStdio); err != nil {
			return util.Errorf("bwrap: %v", err)
		}
	}
	if blockFD >= 0 {
		if sig := interruptible(sigCh, func() { waitBlock(blockFD) }); sig != nil {
			return stoppedBy(sig)
		}
	}
	if sig := pendingSignal(sigCh); sig != nil {
		return stoppedBy(sig)
	}
	// sigCh stays registered until do returns, so that a signal from now
	// until sb.Exec relays signals does not end runsc and leave the sandbox
	// behind. sb.Exec drops the signals that come before the command runs.
	if err := nullStdio(blockStdio); err != nil {
		return util.Errorf("bwrap: %v", err)
	}

	res, err := sb.Exec(ctx, argv, execOpts...)
	if err != nil {
		return util.Errorf("bwrap: %v", err)
	}
	*waitStatus = unix.WaitStatus(res.ExitCode << 8)
	return subcommands.ExitSuccess
}

// getEnvID returns fallback when the variable is unset. Invalid IDs
// must not silently select a different host user or group.
func getEnvID(key string, fallback uint32) (uint32, error) {
	s, ok := os.LookupEnv(key)
	if !ok {
		return fallback, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", key, s, err)
	}
	// Linux reserves the all-ones ID; it cannot identify a host user or group.
	if v < 0 || v >= math.MaxUint32 {
		return 0, fmt.Errorf("%s=%q: %w", key, s, strconv.ErrRange)
	}
	return uint32(v), nil
}

func (c *bwrapConfig) resolveEnv() {
	var env []string
	for _, e := range c.Env {
		if strings.Contains(e, "=") {
			env = append(env, e)
		}
	}
	for _, e := range c.UnsetEnv {
		for i, v := range env {
			if strings.HasPrefix(v, e+"=") {
				env = append(env[:i], env[i+1:]...)
				break
			}
		}
	}
	c.Env = env
}

// normalizeCap normalizes a capability name to uppercase and prepends "CAP_"
// if necessary. "ALL" is treated as a special CLI keyword and returned as-is.
func normalizeCap(capName string) (string, error) {
	normCap := strings.ToUpper(strings.TrimSpace(capName))
	if normCap != "ALL" {
		if !strings.HasPrefix(normCap, "CAP_") {
			normCap = "CAP_" + normCap
		}
		if !isKnownCapability(normCap) {
			return "", fmt.Errorf("bwrap: unknown cap: %s", capName)
		}
	}
	return normCap, nil
}

// isKnownCapability checks if capName is a valid Linux capability known to gVisor.
func isKnownCapability(capName string) bool {
	for _, c := range specutils.AllCapabilities().Bounding {
		if c == capName {
			return true
		}
	}
	return false
}

// addCapability adds a single capability to all 5 capability sets.
// This is used by bwrap to support re-adding capabilities after --cap-drop ALL.
// If capName is "ALL" (a CLI keyword for --cap-add ALL), every capability is
// restored, which is a no-op unless a previous --cap-drop removed some.
func addCapability(caps *specs.LinuxCapabilities, capName string) {
	if capName == "ALL" {
		*caps = *specutils.AllCapabilities()
		return
	}

	addUnique := func(set []string) []string {
		for _, c := range set {
			if c == capName {
				return set
			}
		}
		return append(set, capName)
	}
	caps.Bounding = addUnique(caps.Bounding)
	caps.Effective = addUnique(caps.Effective)
	caps.Inheritable = addUnique(caps.Inheritable)
	caps.Permitted = addUnique(caps.Permitted)
	caps.Ambient = addUnique(caps.Ambient)
}

// dropCapability removes a capability from all 5 capability sets.
//
// If capName is "ALL" (a CLI keyword for --cap-drop ALL), all capability
// sets are cleared. This logic is kept in bwrap rather than specutils because
// "ALL" is not a valid Linux capability name, and bwrap uniquely supports
// dropping all capabilities and subsequently re-adding specific ones via --cap-add.
func dropCapability(caps *specs.LinuxCapabilities, capName string) {
	if capName == "ALL" {
		caps.Bounding = nil
		caps.Effective = nil
		caps.Inheritable = nil
		caps.Permitted = nil
		caps.Ambient = nil
		return
	}
	specutils.DropCapability(caps, capName)
}

// takePerms returns the pending --perms value if one was given, otherwise nil,
// and clears the pending value either way. A nil result leaves the mount at the
// filesystem's own default mode, which is 01777 for tmpfs.
func (c *bwrapConfig) takePerms() *uint32 {
	perms := c.nextPerms
	c.nextPerms = nil
	return perms
}
