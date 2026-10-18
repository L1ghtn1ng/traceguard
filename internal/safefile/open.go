package safefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const noSymlinks = unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

// MaxSecretBytes bounds credential files read by ReadSecret.
const MaxSecretBytes = 8 * 1024

func OpenAbsolute(path string, flags int, mode os.FileMode) (*os.File, error) {
	return openAbsolute(path, flags, mode, unix.Openat2)
}

type openat2Func func(dirfd int, path string, how *unix.OpenHow) (fd int, err error)

func openAbsolute(path string, flags int, mode os.FileMode, openat2 openat2Func) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("path %q must be absolute", path)
	}
	cleaned := filepath.Clean(path)
	openFlags, err := openHowFlags(flags)
	if err != nil {
		return nil, err
	}
	fd, err := openat2(unix.AT_FDCWD, cleaned, &unix.OpenHow{
		Flags:   openFlags,
		Mode:    uint64(mode.Perm()),
		Resolve: noSymlinks,
	})
	if errors.Is(err, unix.ENOSYS) {
		return openAbsoluteAt(cleaned, flags, mode)
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, os.ErrInvalid
	}
	return file, nil
}

// openAbsoluteAt provides the same no-symlink guarantee as OpenAbsolute on
// kernels or syscall filters that do not implement openat2. Each path
// component is opened relative to the preceding directory descriptor so an
// attacker cannot swap a validated directory before the final open.
func openAbsoluteAt(path string, flags int, mode os.FileMode) (*os.File, error) {
	dirfd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 1 && components[0] == "" {
		components[0] = "."
	}
	for index, component := range components {
		componentFlags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if index == len(components)-1 {
			componentFlags = flags | unix.O_CLOEXEC | unix.O_NOFOLLOW
		}
		nextfd, openErr := unix.Openat(dirfd, component, componentFlags, uint32(mode.Perm()))
		if closeErr := unix.Close(dirfd); openErr == nil && closeErr != nil {
			_ = unix.Close(nextfd)
			return nil, closeErr
		}
		if openErr != nil {
			return nil, openErr
		}
		dirfd = nextfd
	}

	file := os.NewFile(uintptr(dirfd), path)
	if file == nil {
		_ = unix.Close(dirfd)
		return nil, os.ErrInvalid
	}
	return file, nil
}

func OpenBeneath(dirfd int, name string, flags int, mode os.FileMode) (*os.File, error) {
	if !filepath.IsLocal(name) {
		return nil, fmt.Errorf("path %q must be local", name)
	}
	openFlags, err := openHowFlags(flags)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat2(dirfd, name, &unix.OpenHow{
		Flags:   openFlags,
		Mode:    uint64(mode.Perm()),
		Resolve: noSymlinks | unix.RESOLVE_BENEATH,
	})
	if errors.Is(err, unix.ENOSYS) {
		return openBeneathAt(dirfd, name, flags, mode)
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, os.ErrInvalid
	}
	return file, nil
}

// openBeneathAt gives OpenBeneath's guarantees without openat2: the local
// name is cleaned, so it has no ".." components, and each component is opened
// with O_NOFOLLOW relative to the one before it.
func openBeneathAt(dirfd int, name string, flags int, mode os.FileMode) (*os.File, error) {
	components := strings.Split(filepath.Clean(name), string(filepath.Separator))
	current := dirfd
	for index, component := range components {
		componentFlags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if index == len(components)-1 {
			componentFlags = flags | unix.O_CLOEXEC | unix.O_NOFOLLOW
		}
		nextfd, openErr := unix.Openat(current, component, componentFlags, uint32(mode.Perm()))
		if current != dirfd {
			_ = unix.Close(current)
		}
		if openErr != nil {
			return nil, openErr
		}
		current = nextfd
	}
	file := os.NewFile(uintptr(current), name)
	if file == nil {
		_ = unix.Close(current)
		return nil, os.ErrInvalid
	}
	return file, nil
}

func ReadFile(path string, maxBytes int64) (payload []byte, readErr error) {
	file, err := OpenAbsolute(path, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		readErr = errors.Join(readErr, file.Close())
	}()
	return readRegular(file, maxBytes)
}

func ReadFileBeneath(dirfd int, name string, maxBytes int64) (payload []byte, readErr error) {
	file, err := OpenBeneath(dirfd, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		readErr = errors.Join(readErr, file.Close())
	}()
	return readRegular(file, maxBytes)
}

// ReadSecret reads a single-line credential, such as a systemd
// LoadCredential= file, from a regular file owned by root or the effective
// user with no group or other permission bits. One trailing newline is removed.
func ReadSecret(path string) (secret string, readErr error) {
	file, err := OpenAbsolute(path, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer func() {
		readErr = errors.Join(readErr, file.Close())
	}()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("file mode %04o grants group or other access; use 0600 or 0400", perm)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || (stat.Uid != 0 && int(stat.Uid) != os.Geteuid()) {
		return "", errors.New("file must be owned by root")
	}
	payload, err := readRegular(file, MaxSecretBytes)
	if err != nil {
		return "", err
	}
	secret = strings.TrimSuffix(strings.TrimSuffix(string(payload), "\n"), "\r")
	if strings.ContainsAny(secret, "\r\n\x00") {
		return "", errors.New("file must contain a single line")
	}
	if strings.TrimSpace(secret) == "" {
		return "", errors.New("file is empty")
	}
	return secret, nil
}

func readRegular(file *os.File, maxBytes int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("file is not regular")
	}
	if maxBytes <= 0 {
		return nil, errors.New("maximum file size must be positive")
	}
	payload, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maxBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return payload, nil
}

func WriteFileAtomic(path string, payload []byte, mode os.FileMode) (writeErr error) {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path %q must be absolute", path)
	}
	cleanPath := filepath.Clean(path)
	dirPath := filepath.Dir(cleanPath)
	baseName := filepath.Base(cleanPath)
	if err := os.MkdirAll(dirPath, 0o750); err != nil {
		return err
	}
	dir, err := OpenAbsolute(dirPath, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer func() {
		writeErr = errors.Join(writeErr, dir.Close())
	}()

	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	tempName := ".traceguard-" + hex.EncodeToString(random) + ".tmp"
	temp, err := OpenBeneath(int(dir.Fd()), tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, mode)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = unix.Unlinkat(int(dir.Fd()), tempName, 0)
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		cleanup()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		cleanup()
		return err
	}
	if err := temp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := unix.Renameat(int(dir.Fd()), tempName, int(dir.Fd()), baseName); err != nil {
		cleanup()
		return err
	}
	return unix.Fsync(int(dir.Fd()))
}

func openHowFlags(flags int) (uint64, error) {
	flags |= unix.O_CLOEXEC | unix.O_NOFOLLOW
	if flags < 0 {
		return 0, errors.New("open flags must not be negative")
	}
	return uint64(flags), nil
}
