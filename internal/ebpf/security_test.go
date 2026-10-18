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
