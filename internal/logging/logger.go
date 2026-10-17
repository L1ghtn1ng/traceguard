package logging

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

type Logger struct {
	mu       sync.Mutex
	format   Format
	hostname string
	text     *log.Logger
	writer   io.Writer
}

func NewLogger(writer io.Writer, format string) (*Logger, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read hostname: %w", err)
	}
	return newLogger(writer, format, hostname)
}

func newLogger(writer io.Writer, format, hostname string) (*Logger, error) {
	normalized := Format(strings.ToLower(strings.TrimSpace(format)))
	switch normalized {
	case FormatText, FormatJSON:
	default:
		return nil, fmt.Errorf("unsupported log format %q", format)
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return nil, errors.New("hostname must not be empty")
	}

	return &Logger{
		format:   normalized,
		hostname: hostname,
		text:     log.New(writer, "", log.LstdFlags|log.LUTC),
		writer:   writer,
	}, nil
}

func (l *Logger) Hostname() string {
	return l.hostname
}

func (l *Logger) Info(msg string, fields map[string]any) error {
	return l.emitAt(time.Now().UTC(), "info", msg, fields)
}

func (l *Logger) Log(level, msg string, fields map[string]any) error {
	return l.emitAt(time.Now().UTC(), level, msg, fields)
}

func (l *Logger) LogAt(timestamp time.Time, level, msg string, fields map[string]any) error {
	return l.emitAt(timestamp.UTC(), level, msg, fields)
}

func (l *Logger) Error(msg string, err error, fields map[string]any) error {
	merged := cloneFields(fields)
	if err != nil {
		merged["error"] = err.Error()
	}
	return l.emitAt(time.Now().UTC(), "error", msg, merged)
}

func (l *Logger) emitAt(timestamp time.Time, level, msg string, fields map[string]any) error {
	if fields == nil {
		fields = map[string]any{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.format == FormatJSON {
		record := make(map[string]any, len(fields)+4)
		record["timestamp"] = timestamp.Format(time.RFC3339Nano)
		record["level"] = level
		record["message"] = msg
		record["hostname"] = l.hostname
		for key, value := range fields {
			if isReservedField(key) {
				continue
			}
			record[key] = value
		}
		payload, err := json.Marshal(record)
		if err != nil {
			l.text.Printf("log marshal failure hostname=%q level=%q message=%q error=%q", l.hostname, level, msg, err.Error())
			return err
		}
		_, err = l.writer.Write(append(payload, '\n'))
		return err
	}

	_, err := fmt.Fprintf(l.writer, "%s %s\n", timestamp.Format("2006/01/02 15:04:05"), formatTextLine(msg, level, l.hostname, fields))
	return err
}

func cloneFields(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(fields))
	maps.Copy(cloned, fields)
	return cloned
}

func formatTextLine(msg, level, hostname string, fields map[string]any) string {
	keys := make([]string, 0, len(fields)+1)
	keys = append(keys, "level")
	for key := range fields {
		if isReservedField(key) {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys[1:])

	var builder strings.Builder
	builder.WriteString(msg)
	builder.WriteString(" level=")
	builder.WriteString(strconv.Quote(level))
	builder.WriteString(" hostname=")
	builder.WriteString(strconv.Quote(hostname))
	for _, key := range keys[1:] {
		builder.WriteByte(' ')
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(formatValue(fields[key]))
	}
	return builder.String()
}

func isReservedField(key string) bool {
	return key == "timestamp" || key == "level" || key == "message" || key == "hostname"
}

func formatValue(value any) string {
	switch typed := value.(type) {
	case string:
		return strconv.Quote(typed)
	case fmt.Stringer:
		return strconv.Quote(typed.String())
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case int:
		return strconv.FormatInt(int64(typed), 10)
	case int32:
		return strconv.FormatInt(int64(typed), 10)
	case int64:
		return strconv.FormatInt(typed, 10)
	case uint:
		return strconv.FormatUint(uint64(typed), 10)
	case uint16:
		return strconv.FormatUint(uint64(typed), 10)
	case uint32:
		return strconv.FormatUint(uint64(typed), 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	case []string:
		payload, err := json.Marshal(typed)
		if err != nil {
			return strconv.Quote(fmt.Sprint(typed))
		}
		return string(payload)
	default:
		payload, err := json.Marshal(typed)
		if err != nil {
			return strconv.Quote(fmt.Sprint(typed))
		}
		return string(payload)
	}
}
