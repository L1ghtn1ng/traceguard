package logging

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

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
	}

	if err := r.ensureReady(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

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

	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

func (r *RotatingFile) ensureReady() error {
	if err := r.ensureDirectory(); err != nil {
		return err
	}
	if err := rejectSymlink(r.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if r.file != nil {
		return nil
	}

	file, err := openFileNoFollow(r.path, r.fileMode)
	if err != nil {
		return err
	}
	r.file = file
	return nil
}

func (r *RotatingFile) ensureDirectory() error {
	if err := os.MkdirAll(r.dir, r.dirMode); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}

	resolved, err := filepath.EvalSymlinks(r.dir)
	if err != nil {
		return fmt.Errorf("resolve log directory: %w", err)
	}
	if filepath.Clean(resolved) != r.dir {
		return fmt.Errorf("log directory %q must not traverse symlinks", r.dir)
	}

	info, err := os.Stat(r.dir)
	if err != nil {
		return fmt.Errorf("stat log directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("log directory %q is not a directory", r.dir)
	}
	return nil
}

func (r *RotatingFile) rotateLocked() error {
	if r.file != nil {
		if err := r.file.Close(); err != nil {
			return fmt.Errorf("close log file for rotation: %w", err)
		}
		r.file = nil
	}

	oldest := rotatedPath(r.path, r.backups)
	if err := removeIfExists(oldest); err != nil {
		return err
	}

	for idx := r.backups - 1; idx >= 1; idx-- {
		src := rotatedPath(r.path, idx)
		dst := rotatedPath(r.path, idx+1)
		if err := renameIfExists(src, dst); err != nil {
			return err
		}
	}

	if err := renameIfExists(r.path, rotatedPath(r.path, 1)); err != nil {
		return err
	}

	file, err := openFileNoFollow(r.path, r.fileMode)
	if err != nil {
		return err
	}
	r.file = file
	return nil
}

func rotatedPath(path string, idx int) string {
	return fmt.Sprintf("%s.%d", path, idx)
}

func openFileNoFollow(path string, mode os.FileMode) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_APPEND|unix.O_CLOEXEC|unix.O_CREAT|unix.O_WRONLY|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return nil, fmt.Errorf("open log file %q: %w", path, err)
	}

	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("wrap log file %q: %w", path, io.ErrUnexpectedEOF)
	}

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		file.Close()
		return nil, fmt.Errorf("stat log file %q: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		file.Close()
		return nil, fmt.Errorf("log file %q is not a regular file", path)
	}

	return file, nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %q must not be a symlink", path)
	}
	return nil
}

func removeIfExists(path string) error {
	if err := rejectSymlink(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove rotated log %q: %w", path, err)
	}
	return nil
}

func renameIfExists(src, dst string) error {
	if err := rejectSymlink(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := rejectSymlink(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("rotate log %q -> %q: %w", src, dst, err)
	}
	return nil
}
