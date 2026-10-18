package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestEveryObjectCarriesSecurityTracepoints(t *testing.T) {
	t.Parallel()

	var programs securityPrograms
	for _, load := range []func() (*ebpf.CollectionSpec, error){
		loadTraceguard, loadTraceguardDNSCompat, loadTraceguardRecvmsgCompat, loadTraceguardDNSRecvmsgCompat,
		loadTraceguardLinux71, loadTraceguardLinux71DNSCompat, loadTraceguardLinux71RecvmsgCompat, loadTraceguardLinux71DNSRecvmsgCompat,
	} {
		spec, err := load()
		if err != nil {
			t.Fatal(err)
		}
		for _, tracepoint := range programs.tracepoints() {
			program := spec.Programs[tracepoint.program]
			if want := "tracepoint/syscalls/" + tracepoint.tracepoint; program == nil || program.SectionName != want {
				t.Fatalf("program %s = %v, want section %s", tracepoint.program, program, want)
			}
		}
	}
}

func TestSecurityProgramTagsMatchTracepointTable(t *testing.T) {
	t.Parallel()

	source, err := ebpfFieldTags(securityPrograms{})
	if err != nil {
		t.Fatal(err)
	}
	var programs securityPrograms
	table := programs.tracepoints()
	if len(table) != len(source) {
		t.Fatalf("tracepoint table has %d programs, struct has %d", len(table), len(source))
	}
	for index, tracepoint := range table {
		if tracepoint.program != source[index] {
			t.Fatalf("table entry %d = %s, struct field tag = %s", index, tracepoint.program, source[index])
		}
		if !strings.HasPrefix(tracepoint.tracepoint, "sys_enter_") {
			t.Fatalf("tracepoint %q is not a syscall entry", tracepoint.tracepoint)
		}
	}
}

func TestDecodeSecurityEvents(t *testing.T) {
	t.Parallel()

	decode := func(raw rawEvent) Event {
		t.Helper()
		var encoded bytes.Buffer
		if err := binary.Write(&encoded, binary.NativeEndian, raw); err != nil {
			t.Fatal(err)
		}
		event, err := decodeEvent(encoded.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return event
	}

	ptrace := decode(rawEvent{Kind: EventPtrace, RuleID: 16, FileMode: 4242})
	if ptrace.Operation != 16 || ptrace.FileMode != 4242 || ptrace.RuleNumber != 0 || ptrace.Domain != "" {
		t.Fatalf("ptrace event = %+v", ptrace)
	}

	raw := rawEvent{Kind: EventMount, FileFlags: 1}
	copy(raw.Domain[:], "/dev/sda1")
	copy(raw.Domain[mountSourceSize:], "ext4")
	copy(raw.Filename[:], "/mnt/host")
	mount := decode(raw)
	if mount.MountSource != "/dev/sda1" || mount.MountFSType != "ext4" || mount.Filename != "/mnt/host" || mount.Domain != "" {
		t.Fatalf("mount event = %+v", mount)
	}
}

// ebpfFieldTags returns the ebpf struct tags of value's fields in order.
func ebpfFieldTags(value any) ([]string, error) {
	typ := reflect.TypeOf(value)
	tags := make([]string, 0, typ.NumField())
	for index := range typ.NumField() {
		tag := typ.Field(index).Tag.Get("ebpf")
		if tag == "" {
			return nil, fmt.Errorf("field %s has no ebpf tag", typ.Field(index).Name)
		}
		tags = append(tags, tag)
	}
	return tags, nil
}

func TestDecodeExecEventCommandLine(t *testing.T) {
	t.Parallel()

	raw := rawEvent{Kind: EventExec, RuleID: 1, FileMode: 7, FileFlags: 0x1000 | execArgvTruncated, Port: 3}
	copy(raw.Domain[:], "bash\x00-c\x00\x00")
	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.NativeEndian, raw); err != nil {
		t.Fatal(err)
	}
	event, err := decodeEvent(encoded.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(event.Args, []string{"bash", "-c", ""}) || !event.ArgsTruncated {
		t.Fatalf("args = %q truncated %t", event.Args, event.ArgsTruncated)
	}
	if event.Operation != 1 || event.FileMode != 7 || event.FileFlags != 0x1000 || event.Port != 0 {
		t.Fatalf("exec metadata = op %d fd %d flags %#x port %d", event.Operation, event.FileMode, event.FileFlags, event.Port)
	}
}

func TestSplitArgsHandlesCutFinalArgument(t *testing.T) {
	t.Parallel()

	if got := splitArgs([]byte("one\x00tw"), 2); !reflect.DeepEqual(got, []string{"one", "tw"}) {
		t.Fatalf("splitArgs = %q", got)
	}
	if got := splitArgs([]byte("one\x00two\x00"), 1); !reflect.DeepEqual(got, []string{"one"}) {
		t.Fatalf("splitArgs with count 1 = %q", got)
	}
	if got := splitArgs(make([]byte, 8), 0); len(got) != 0 {
		t.Fatalf("splitArgs with count 0 = %q", got)
	}
}

func TestEveryObjectCarriesFileChangeTracepoints(t *testing.T) {
	t.Parallel()

	var programs fileChangePrograms
	tags, err := ebpfFieldTags(fileChangePrograms{})
	if err != nil {
		t.Fatal(err)
	}
	table := programs.fileChangeTracepoints()
	if len(table) != len(tags) {
		t.Fatalf("file change table has %d programs, struct has %d", len(table), len(tags))
	}
	spec, err := loadTraceguardLinux71()
	if err != nil {
		t.Fatal(err)
	}
	for index, tracepoint := range table {
		if tracepoint.program != tags[index] {
			t.Fatalf("table entry %d = %s, struct tag = %s", index, tracepoint.program, tags[index])
		}
		program := spec.Programs[tracepoint.program]
		if want := "tracepoint/syscalls/" + tracepoint.tracepoint; program == nil || program.SectionName != want {
			t.Fatalf("program %s = %v, want section %s", tracepoint.program, program, want)
		}
	}
}

func TestDecodeFileChangeEvent(t *testing.T) {
	t.Parallel()

	raw := rawEvent{Kind: EventFileChange, RuleID: 1, FileMode: 0xffffff9c, SocketCookie: 7}
	copy(raw.Filename[:], "/etc/passwd+")
	copy(raw.Domain[:], "/etc/passwd")
	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.NativeEndian, raw); err != nil {
		t.Fatal(err)
	}
	event, err := decodeEvent(encoded.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if event.Operation != 1 || event.Filename != "/etc/passwd+" || event.NewPath != "/etc/passwd" || event.Value != 7 || event.SocketCookie != 0 || event.Domain != "" {
		t.Fatalf("file change event = %+v", event)
	}
}

func TestDecodeKeepsSignedDirfdHighBit(t *testing.T) {
	t.Parallel()

	const atFDCWD = uint32(0xffffff9c)
	for _, kind := range []uint32{EventFileChange, EventExec} {
		var encoded bytes.Buffer
		if err := binary.Write(&encoded, binary.NativeEndian, rawEvent{Kind: kind, FileMode: atFDCWD}); err != nil {
			t.Fatal(err)
		}
		event, err := decodeEvent(encoded.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if event.FileMode != atFDCWD || event.PathTruncated {
			t.Fatalf("kind %d: FileMode = %#x truncated %t, want AT_FDCWD kept intact", kind, event.FileMode, event.PathTruncated)
		}
	}

	var encoded bytes.Buffer
	if err := binary.Write(&encoded, binary.NativeEndian, rawEvent{Kind: EventFileBlocked, FileMode: pathTruncatedFlag | 0o4}); err != nil {
		t.Fatal(err)
	}
	event, err := decodeEvent(encoded.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if event.FileMode != 0o4 || !event.PathTruncated {
		t.Fatalf("enforcement event FileMode = %#x truncated %t, want the flag split out", event.FileMode, event.PathTruncated)
	}
}
