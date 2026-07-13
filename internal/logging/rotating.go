package logging

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/L1ghtn1ng/traceguard/internal/safefile"
	"golang.org/x/sys/unix"
)

const symlinkAllowedLogDirectory = "/var/log/traceguard"

type Options struct {
	MaxSizeBytes int64
	MaxBackups   int
	FileMode     os.FileMode
	DirMode      os.FileMode
}

type RotatingFile struct {
	mu       sync.Mutex
	path     string
	dir      string
	maxSize  int64
	backups  int
	fileMode os.FileMode
	dirMode  os.FileMode
	file     *os.File
	dirFile  *os.File
	base     string
	closed   bool
}

func NewRotatingFile(path string, opts Options) (*RotatingFile, error) {
	if path == "" {
		return nil, errors.New("log path is empty")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("log path must be absolute")
	}
	if opts.MaxSizeBytes <= 0 {
		return nil, errors.New("max log size must be positive")
	}
	if opts.MaxBackups < 1 {
		return nil, errors.New("max backups must be at least 1")
	}
	if opts.FileMode == 0 {
		opts.FileMode = 0o640
	}
	if opts.DirMode == 0 {
		opts.DirMode = 0o750
	}

	r := &RotatingFile{
		path:     filepath.Clean(path),
		dir:      filepath.Dir(filepath.Clean(path)),
		maxSize:  opts.MaxSizeBytes,
		backups:  opts.MaxBackups,
		fileMode: opts.FileMode,
		dirMode:  opts.DirMode,
		base:     filepath.Base(filepath.Clean(path)),
	}

	if err := r.ensureReady(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, os.ErrClosed
	}

	if err := r.ensureReady(); err != nil {
		return 0, err
	}

	info, err := r.file.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat log file: %w", err)
	}
	if info.Size() > 0 && info.Size()+int64(len(p)) > r.maxSize {
		if err := r.rotateLocked(); err != nil {
			return 0, err
		}
	}

	n, err := r.file.Write(p)
	if err != nil {
		return n, fmt.Errorf("write log file: %w", err)
	}
	return n, nil
}

func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true
	var errs []error
	if r.file != nil {
		errs = append(errs, r.file.Close())
		r.file = nil
	}
	if r.dirFile != nil {
		errs = append(errs, r.dirFile.Close())
		r.dirFile = nil
	}
	return errors.Join(errs...)
}

func (r *RotatingFile) ensureReady() error {
	if r.closed {
		return os.ErrClosed
	}
	if err := r.ensureDirectory(); err != nil {
		return err
	}
	if r.file != nil {
		return nil
	}

	file, err := openFileNoFollowAt(int(r.dirFile.Fd()), r.base, r.path, r.fileMode)
	if err != nil {
		return err
	}
	r.file = file
	return nil
}

func (r *RotatingFile) ensureDirectory() error {
	if r.dirFile != nil {
		return nil
	}
	if err := os.MkdirAll(r.dir, r.dirMode); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}
	var dir *os.File
	var err error
	if allowsLogDirectorySymlink(r.dir) {
		dir, err = openDirectoryAllowFinalSymlink(r.dir)
	} else {
		dir, err = safefile.OpenAbsolute(r.dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	}
	if err != nil {
		return fmt.Errorf("log directory %q must not traverse symlinks: %w", r.dir, err)
	}
	info, err := dir.Stat()
	if err != nil {
		_ = dir.Close()
		return fmt.Errorf("stat log directory: %w", err)
	}
	if !info.IsDir() {
		_ = dir.Close()
		return fmt.Errorf("log directory %q is not a directory", r.dir)
	}
	r.dirFile = dir
	return nil
}

func allowsLogDirectorySymlink(path string) bool {
	return filepath.Clean(path) == symlinkAllowedLogDirectory
}

func openDirectoryAllowFinalSymlink(path string) (*os.File, error) {
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return nil, fmt.Errorf("path %q must be absolute", path)
	}

	dir, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	components := strings.Split(strings.TrimPrefix(cleaned, string(filepath.Separator)), string(filepath.Separator))
	for idx, component := range components {
		flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC
		if idx != len(components)-1 {
			flags |= unix.O_NOFOLLOW
		}
		fd, openErr := unix.Openat(int(dir.Fd()), component, flags, 0)
		if openErr != nil {
			_ = dir.Close()
			return nil, openErr
		}
		next := os.NewFile(uintptr(fd), component)
		if next == nil {
			_ = unix.Close(fd)
			_ = dir.Close()
			return nil, os.ErrInvalid
		}
		if closeErr := dir.Close(); closeErr != nil {
			_ = next.Close()
			return nil, closeErr
		}
		dir = next
	}
	return dir, nil
}

func (r *RotatingFile) rotateLocked() error {
	if r.file != nil {
		if err := r.file.Close(); err != nil {
			return fmt.Errorf("close log file for rotation: %w", err)
		}
		r.file = nil
	}

	oldest := rotatedName(r.base, r.backups)
	if err := removeIfExistsAt(int(r.dirFile.Fd()), oldest); err != nil {
		return err
	}

	for idx := r.backups - 1; idx >= 1; idx-- {
		src := rotatedName(r.base, idx)
		dst := rotatedName(r.base, idx+1)
		if err := renameIfExistsAt(int(r.dirFile.Fd()), src, dst); err != nil {
			return err
		}
	}

	if err := renameIfExistsAt(int(r.dirFile.Fd()), r.base, rotatedName(r.base, 1)); err != nil {
		return err
	}

	file, err := openFileNoFollowAt(int(r.dirFile.Fd()), r.base, r.path, r.fileMode)
	if err != nil {
		return err
	}
	r.file = file
	return nil
}

func rotatedPath(path string, idx int) string {
	return fmt.Sprintf("%s.%d", path, idx)
}

func rotatedName(base string, idx int) string {
	return fmt.Sprintf("%s.%d", base, idx)
}

func openFileNoFollowAt(dirfd int, name, displayPath string, mode os.FileMode) (*os.File, error) {
	if !filepath.IsLocal(name) {
		return nil, fmt.Errorf("open log file %q: path must be local", displayPath)
	}
	fd, err := unix.Openat(dirfd, name, unix.O_APPEND|unix.O_CLOEXEC|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_WRONLY, uint32(mode.Perm()))
	if err != nil {
		return nil, fmt.Errorf("open log file %q: %w", displayPath, err)
	}
	file := os.NewFile(uintptr(fd), displayPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("open log file %q: %w", displayPath, os.ErrInvalid)
	}

	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return nil, fmt.Errorf("stat log file %q: %w", displayPath, errors.Join(err, file.Close()))
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("close non-regular log file %q: %w", displayPath, err)
		}
		return nil, fmt.Errorf("log file %q is not a regular file", displayPath)
	}

	return file, nil
}

func rejectSymlinkAt(dirfd int, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(dirfd, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("path %q must not be a symlink", name)
	}
	return nil
}

func removeIfExistsAt(dirfd int, name string) error {
	if err := rejectSymlinkAt(dirfd, name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	err := unix.Unlinkat(dirfd, name, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove rotated log %q: %w", name, err)
	}
	return nil
}

func renameIfExistsAt(dirfd int, src, dst string) error {
	if err := rejectSymlinkAt(dirfd, src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := rejectSymlinkAt(dirfd, dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := unix.Renameat(dirfd, src, dirfd, dst); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("rotate log %q -> %q: %w", src, dst, err)
	}
	return nil
}
