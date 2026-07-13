package safefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const noSymlinks = unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

func OpenAbsolute(path string, flags int, mode os.FileMode) (*os.File, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("path %q must be absolute", path)
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, filepath.Clean(path), &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Mode:    uint64(mode.Perm()),
		Resolve: noSymlinks,
	})
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

func OpenBeneath(dirfd int, name string, flags int, mode os.FileMode) (*os.File, error) {
	if !filepath.IsLocal(name) {
		return nil, fmt.Errorf("path %q must be local", name)
	}
	fd, err := unix.Openat2(dirfd, name, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Mode:    uint64(mode.Perm()),
		Resolve: noSymlinks | unix.RESOLVE_BENEATH,
	})
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

func ReadFile(path string, maxBytes int64) ([]byte, error) {
	file, err := OpenAbsolute(path, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readRegular(file, maxBytes)
}

func ReadFileBeneath(dirfd int, name string, maxBytes int64) ([]byte, error) {
	file, err := OpenBeneath(dirfd, name, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readRegular(file, maxBytes)
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

func WriteFileAtomic(path string, payload []byte, mode os.FileMode) error {
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
	defer dir.Close()

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
