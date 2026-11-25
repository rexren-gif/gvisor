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
	"io"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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

// defaultFilePerms is the mode of a --file without --perms.
const defaultFilePerms = 0666

// File is a --file entry.
type File struct {
	// FD is the descriptor that holds the data.
	FD int
	// Dest is the sandbox path, absolute and clean.
	Dest string
	// Perms is the mode of a new file, from --perms or defaultFilePerms.
	Perms uint32
	// Hidden reports whether a later mount hides Dest. The sandbox does not
	// create a hidden file, but runsc still reads its descriptor.
	Hidden bool
}

// bwrapConfig represents the configuration for the bwrap sandbox.
type bwrapConfig struct {
	Mounts      []sandbox.Mount
	HostDirs    []HostDir
	Files       []File
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

// addMounts applies each mount in mnts to the --file entries declared so far
// (see coverFiles), and appends it to the mount list.
func (c *bwrapConfig) addMounts(mnts ...sandbox.Mount) error {
	for _, m := range mnts {
		if err := c.coverFiles(m); err != nil {
			return err
		}
		c.Mounts = append(c.Mounts, m)
	}
	return nil
}

// coverFiles applies a mount m to the --file entries declared so far. A
// regular file is not a directory, so m fails below a file, and also at a
// file, unless m binds a host file that is not a directory. m hides the files
// at or below its destination.
func (c *bwrapConfig) coverFiles(m sandbox.Mount) error {
	dst := filepath.Join("/", m.Destination)
	if f, ok := c.fileAtOrAbove(dst); ok && (f.Dest != dst || !isFileBind(m)) {
		return fmt.Errorf("bwrap: Can't mount on %s: --%s %s is not a directory", dst, flagFile, f.Dest)
	}
	for i := range c.Files {
		if _, ok := pathBelow(dst, c.Files[i].Dest); ok {
			c.Files[i].Hidden = true
		}
	}
	return nil
}

// isFileBind reports whether m binds a host file that is not a directory.
func isFileBind(m sandbox.Mount) bool {
	if m.Type != sandbox.MountTypeBind {
		return false
	}
	info, err := os.Stat(m.Source)
	return err == nil && !info.IsDir()
}

// fileAtOrAbove returns the visible --file entry declared so far whose path
// is path or a parent of path. A relative path starts at "/".
func (c *bwrapConfig) fileAtOrAbove(path string) (File, bool) {
	path = filepath.Join("/", path)
	for _, f := range c.Files {
		if _, ok := pathBelow(f.Dest, path); ok && !f.Hidden {
			return f, true
		}
	}
	return File{}, false
}

// hasFileBelow reports whether a visible --file entry declared so far has its
// path below path. A relative path starts at "/".
func (c *bwrapConfig) hasFileBelow(path string) bool {
	path = filepath.Join("/", path)
	for _, f := range c.Files {
		if rel, ok := pathBelow(path, f.Dest); ok && rel != "." && !f.Hidden {
			return true
		}
	}
	return false
}

// pathBelow reports whether path is parent or below parent, and returns path
// relative to parent.
func pathBelow(parent, path string) (string, bool) {
	rel, err := filepath.Rel(parent, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
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

// readFiles reads the data of each --file in command-line order, from the
// current offset of its descriptor to the end, into a new memfd, and then
// closes the descriptor (see consumeFD). A descriptor is consumed once, so a
// second --file with the same descriptor fails with EBADF. It returns the
// files that the sandbox must create, which leave out the hidden entries, and
// a function that closes their memfds.
func (c *bwrapConfig) readFiles() ([]sandbox.File, func(), error) {
	var files []sandbox.File
	closeFiles := func() {
		for _, f := range files {
			f.Data.Close()
		}
	}
	fail := func(err error) ([]sandbox.File, func(), error) {
		closeFiles()
		return nil, nil, err
	}
	// Check every descriptor before the first memfd can take the number of
	// one that is not open. A descriptor that runsc inherited has no
	// FD_CLOEXEC flag, because it went through execve(2). runsc opens its
	// own descriptors with FD_CLOEXEC, so they do not count as open here.
	for _, f := range c.Files {
		if name := runscFD(f.FD); name != "" {
			return fail(fmt.Errorf("bwrap: Can't read data for file %s: runsc uses fd %d for --%s", f.Dest, f.FD, name))
		}
		flags, err := unix.FcntlInt(uintptr(f.FD), unix.F_GETFD, 0)
		if err == nil && flags&unix.FD_CLOEXEC != 0 {
			err = unix.EBADF
		}
		if err != nil {
			return fail(fmt.Errorf("bwrap: Can't read data for file %s: %v", f.Dest, err))
		}
	}
	consumed := make(map[int]bool)
	for _, f := range c.Files {
		if consumed[f.FD] {
			return fail(fmt.Errorf("bwrap: Can't read data for file %s: %v", f.Dest, unix.EBADF))
		}
		consumed[f.FD] = true
		data, err := consumeFD(f.FD)
		if err != nil {
			return fail(fmt.Errorf("bwrap: Can't read data for file %s: %v", f.Dest, err))
		}
		if f.Hidden {
			data.Close()
			continue
		}
		files = append(files, sandbox.File{Path: f.Dest, Mode: f.Perms, Data: data})
	}
	return files, closeFiles, nil
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

// consumeFD copies the data of descriptor fd, from its current offset to its
// end, into a new memfd, and then closes fd. Descriptors 0 to 2 get
// /dev/null instead, so that the standard streams of runsc stay valid.
func consumeFD(fd int) (*os.File, error) {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	src := os.NewFile(uintptr(dup), "")
	defer src.Close()
	memfd, err := unix.MemfdCreate("runsc-bwrap-file", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, err
	}
	data := os.NewFile(uintptr(memfd), "")
	if _, err := io.Copy(data, src); err != nil {
		data.Close()
		var errno unix.Errno
		if errors.As(err, &errno) {
			return nil, errno
		}
		return nil, err
	}
	if err := closeFD(fd); err != nil {
		data.Close()
		return nil, err
	}
	return data, nil
}

// closeFD closes fd, or points it to /dev/null if it is a standard stream.
func closeFD(fd int) error {
	if fd > 2 {
		return unix.Close(fd)
	}
	null, err := unix.Open("/dev/null", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(null)
	return unix.Dup3(null, fd, 0)
}

// do runs the command in a gVisor sandbox and records its exit status.
func do(ctx context.Context, c *bwrapConfig, waitStatus *unix.WaitStatus) subcommands.ExitStatus {
	// Read the files before prepareSandbox creates host directories, so that
	// a bad descriptor leaves the host as it is.
	files, closeFiles, err := c.readFiles()
	if err != nil {
		return util.Errorf("%v", err)
	}
	opts, err := c.prepareSandbox()
	if err != nil {
		closeFiles()
		return util.Errorf("%v", err)
	}
	if len(files) > 0 {
		opts = append(opts, sandbox.WithFiles(files...))
	}
	// Configure the sandbox to invoke the current runsc executable.
	if err := os.Setenv(sandbox.RunscPathEnvVar, specutils.ExePath); err != nil {
		closeFiles()
		return util.Errorf("bwrap: %v", err)
	}

	sb, err := sandbox.New(ctx, opts...)
	// The sandbox has read the files once it is created.
	closeFiles()
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
