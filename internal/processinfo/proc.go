package processinfo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type statusSnapshot struct {
	Name string
	PPID uint32
	UID  uint32
}

func (c *Cache) readStatus(pid uint32) statusSnapshot {
	file, err := os.Open(c.procPath(pid, "status"))
	if err != nil {
		return statusSnapshot{}
	}
	defer file.Close()

	snapshot, err := parseStatus(file)
	if err != nil {
		return statusSnapshot{}
	}
	return snapshot
}

func (c *Cache) readStartTime(pid uint32) uint64 {
	raw, err := os.ReadFile(c.procPath(pid, "stat"))
	if err != nil {
		return 0
	}
	startTime, err := parseStatStartTime(string(raw))
	if err != nil {
		return 0
	}
	return startTime
}

func (c *Cache) procPath(pid uint32, names ...string) string {
	pidString := strconv.FormatUint(uint64(pid), 10)
	size := len(c.root) + 1 + len(pidString)
	for _, name := range names {
		size += 1 + len(name)
	}

	var builder strings.Builder
	builder.Grow(size)
	builder.WriteString(c.root)
	if c.root[len(c.root)-1] != os.PathSeparator {
		builder.WriteByte(os.PathSeparator)
	}
	builder.WriteString(pidString)
	for _, name := range names {
		if name == "" {
			continue
		}
		builder.WriteByte(os.PathSeparator)
		builder.WriteString(name)
	}
	return builder.String()
}

func parseStatus(r io.Reader) (statusSnapshot, error) {
	var snapshot statusSnapshot
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			snapshot.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "PPid:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			if parsed, err := strconv.ParseUint(value, 10, 32); err == nil {
				snapshot.PPID = uint32(parsed)
			}
		case strings.HasPrefix(line, "Uid:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "Uid:"))
			fields := strings.Fields(value)
			if len(fields) == 0 {
				continue
			}
			if parsed, err := strconv.ParseUint(fields[0], 10, 32); err == nil {
				snapshot.UID = uint32(parsed)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return statusSnapshot{}, fmt.Errorf("scan status: %w", err)
	}
	return snapshot, nil
}

func parseStatStartTime(raw string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	closeComm := strings.LastIndex(raw, ")")
	if closeComm == -1 || closeComm+2 >= len(raw) {
		return 0, errors.New("malformed stat")
	}
	fields := strings.Fields(raw[closeComm+2:])
	if len(fields) < 20 {
		return 0, errors.New("stat missing starttime")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func parseCmdline(raw []byte) []string {
	trimmed := strings.TrimRight(string(raw), "\x00")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "\x00")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func ValidateRoot(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("proc root is not a directory")
	}
	return nil
}

func parseCgroup(raw []byte) (path, service, container, podUID, runtime string) {
	lines := strings.SplitSeq(strings.TrimSpace(string(raw)), "\n")
	for line := range lines {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		candidate := strings.TrimSpace(parts[2])
		if candidate == "" {
			continue
		}
		path = candidate
		if service == "" {
			service = extractService(candidate)
		}
		if container == "" {
			container = extractContainerID(candidate)
		}
		if podUID == "" {
			podUID = extractPodUID(candidate)
		}
		if runtime == "" {
			runtime = extractRuntime(candidate)
		}
	}
	return path, service, container, podUID, runtime
}

func extractService(path string) string {
	for part := range strings.SplitSeq(path, "/") {
		if strings.HasSuffix(part, ".service") || strings.HasSuffix(part, ".scope") {
			return part
		}
	}
	return ""
}

func extractContainerID(path string) string {
	for i := 0; i < len(path); i++ {
		if !isHex(path[i]) {
			continue
		}
		j := i + 1
		for j < len(path) && isHex(path[j]) {
			j++
		}
		switch j - i {
		case 64, 32:
			return strings.ToLower(path[i:j])
		}
		i = j
	}
	return ""
}

func extractPodUID(path string) string {
	for i := 0; i+3 < len(path); i++ {
		if !strings.EqualFold(path[i:i+3], "pod") {
			continue
		}
		start := i + 3
		end := start + 36
		if end > len(path) || !isPodUID(path[start:end]) {
			continue
		}
		return strings.ReplaceAll(strings.ToLower(path[start:end]), "_", "-")
	}
	return ""
}

func extractRuntime(path string) string {
	switch {
	case strings.Contains(path, "cri-containerd"), strings.Contains(path, "containerd"):
		return "containerd"
	case strings.Contains(path, "crio"):
		return "cri-o"
	case strings.Contains(path, "docker"):
		return "docker"
	case strings.Contains(path, "libpod"):
		return "podman"
	default:
		return ""
	}
}

func looksLikeSELinuxContext(value string) bool {
	parts := strings.Split(value, ":")
	return len(parts) >= 3 && parts[0] != "" && parts[1] != "" && parts[2] != ""
}

func parseAppArmorLabel(value string) (profile, mode string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	open := strings.LastIndex(value, " (")
	if open == -1 || !strings.HasSuffix(value, ")") {
		return value, ""
	}
	profile = strings.TrimSpace(value[:open])
	mode = strings.TrimSuffix(value[open+2:], ")")
	return profile, strings.TrimSpace(mode)
}

func isHex(ch byte) bool {
	return ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F'
}

func isPodUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := 0; i < len(value); i++ {
		switch i {
		case 8, 13, 18, 23:
			if value[i] != '-' && value[i] != '_' {
				return false
			}
		default:
			if !isHex(value[i]) {
				return false
			}
		}
	}
	return true
}
