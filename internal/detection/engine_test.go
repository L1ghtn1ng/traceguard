package detection

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

func TestBaselineRulesEnabledAndDisableable(t *testing.T) {
	t.Parallel()
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := engine.RuleCount(), 4; got != want {
		t.Fatalf("rule count = %d, want %d", got, want)
	}
	alerts := engine.Evaluate(Event{
		Timestamp: time.Unix(1, 0),
		Name:      "connection",
		Fields: map[string]any{
			"direction":    "outbound",
			"peer_address": "169.254.169.254",
			"peer_port":    uint16(80),
		},
	})
	if got, want := len(alerts), 1; got != want {
		t.Fatalf("alert count = %d, want %d", got, want)
	}
	if got, want := alerts[0].RuleID, "baseline.cloud-metadata-access"; got != want {
		t.Fatalf("rule id = %q, want %q", got, want)
	}

	if err := engine.Replace(nil, []string{"baseline.cloud-metadata-access"}); err != nil {
		t.Fatal(err)
	}
	if alerts := engine.Evaluate(Event{
		Timestamp: time.Unix(2, 0),
		Name:      "connection",
		Fields: map[string]any{
			"direction": "outbound", "peer_address": "169.254.169.254", "peer_port": uint16(80),
		},
	}); len(alerts) != 0 {
		t.Fatalf("disabled baseline emitted %d alerts", len(alerts))
	}
}

func TestCloudMetadataBaselineCoversIPv6AndKeepsPerProcessCooldown(t *testing.T) {
	t.Parallel()
	engine, err := New(nil, []string{"baseline.direct-email-egress", "baseline.policy-denial-burst"})
	if err != nil {
		t.Fatal(err)
	}
	connect := func(at int64, address string, cgroup uint64, program string) int {
		return len(engine.Evaluate(Event{
			Timestamp: time.Unix(at, 0),
			Name:      "connection",
			Fields: map[string]any{
				"event": "connection", "direction": "outbound", "peer_address": address,
				"peer_port": uint16(80), "cgroup_id": cgroup, "program": program,
			},
		}))
	}
	if got := connect(1, "fd00:ec2::254", 10, "ssm-agent"); got != 1 {
		t.Fatalf("IPv6 IMDS alerts = %d, want 1", got)
	}
	if got := connect(2, "169.254.169.254", 10, "ssm-agent"); got != 0 {
		t.Fatalf("agent alerts during cooldown = %d, want 0", got)
	}
	// A different process must not be hidden by the agent's cooldown.
	if got := connect(3, "169.254.169.254", 20, "curl"); got != 1 {
		t.Fatalf("second process alerts = %d, want 1", got)
	}
}

func TestExecDenialBurstGroupsByCallingProgram(t *testing.T) {
	t.Parallel()
	engine, err := New(nil, []string{"baseline.cloud-metadata-access", "baseline.direct-email-egress"})
	if err != nil {
		t.Fatal(err)
	}
	alerts := 0
	for index, target := range []string{"/usr/bin/nc", "/usr/bin/socat", "/usr/bin/nmap", "/usr/bin/wget", "/usr/bin/curl"} {
		alerts += len(engine.Evaluate(Event{
			Timestamp: time.Unix(int64(index+1), 0),
			Name:      "exec_blocked",
			Fields: map[string]any{
				"event": "exec_blocked", "exe": target, "program": "dropper.sh", "cgroup_id": uint64(7),
			},
		}))
	}
	if alerts != 1 {
		t.Fatalf("denial burst alerts = %d, want 1 for one caller trying five targets", alerts)
	}
}

func TestMappedDestinationCIDRMatchesDecodedIPv4Address(t *testing.T) {
	t.Parallel()

	enabled := true
	engine, err := New([]policy.DetectionRule{{
		ID: "mapped-destination", Enabled: &enabled, Severity: "warning", Events: []string{"connection"},
		Match:   policy.DetectionMatch{DestinationCIDRs: []string{"::ffff:192.0.2.129/120"}},
		Message: "mapped destination",
	}}, []string{
		"baseline.cloud-metadata-access",
		"baseline.direct-email-egress",
		"baseline.policy-denial-burst",
	})
	if err != nil {
		t.Fatal(err)
	}
	alerts := engine.Evaluate(Event{
		Timestamp: time.Unix(1, 0), Name: "connection", Fields: map[string]any{"peer_address": "192.0.2.129"},
	})
	if len(alerts) != 1 || alerts[0].RuleID != "mapped-destination" {
		t.Fatalf("mapped destination alerts = %#v, want mapped-destination", alerts)
	}
	if alerts := engine.Evaluate(Event{
		Timestamp: time.Unix(2, 0), Name: "connection", Fields: map[string]any{"peer_address": "::ffff:192.0.2.129"},
	}); len(alerts) != 1 || alerts[0].RuleID != "mapped-destination" {
		t.Fatalf("mapped-form event address alerts = %#v, want mapped-destination", alerts)
	}
	if alerts := engine.Evaluate(Event{
		Timestamp: time.Unix(3, 0), Name: "connection", Fields: map[string]any{"peer_address": "192.0.3.1"},
	}); len(alerts) != 0 {
		t.Fatalf("out-of-prefix address emitted alerts: %#v", alerts)
	}
}

func TestThresholdGroupingCooldownAndExclusion(t *testing.T) {
	t.Parallel()
	enabled := true
	engine, err := New([]policy.DetectionRule{{
		ID:       "metadata-burst",
		Enabled:  &enabled,
		Severity: "warning",
		Events:   []string{"connection"},
		Match: policy.DetectionMatch{
			DestinationCIDRs: []string{"169.254.169.254/32"},
			Ports:            []uint16{80},
		},
		Exclude: policy.DetectionMatch{
			UIDs: []uint32{0},
		},
		Threshold: policy.Threshold{
			Count:   3,
			Within:  policy.Duration{Duration: time.Minute},
			GroupBy: []string{"cgroup"},
		},
		Cooldown: policy.Duration{Duration: 5 * time.Minute},
		Message:  "metadata burst",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1000, 0)
	fields := map[string]any{
		"peer_address": "169.254.169.254",
		"peer_port":    uint16(80),
		"uid":          uint32(1000),
		"cgroup_id":    uint64(42),
	}
	for index := range 2 {
		if alerts := engine.Evaluate(Event{Timestamp: base.Add(time.Duration(index) * time.Second), Name: "connection", Fields: fields}); len(alerts) != 0 {
			t.Fatalf("event %d emitted early alert", index)
		}
	}
	alerts := engine.Evaluate(Event{Timestamp: base.Add(2 * time.Second), Name: "connection", Fields: fields})
	if got, want := len(alerts), 1; got != want {
		t.Fatalf("threshold alert count = %d, want %d", got, want)
	}
	if alerts := engine.Evaluate(Event{Timestamp: base.Add(3 * time.Second), Name: "connection", Fields: fields}); len(alerts) != 0 {
		t.Fatalf("cooldown emitted %d alerts", len(alerts))
	}

	excluded := cloneFields(fields)
	excluded["uid"] = uint32(0)
	if alerts := engine.Evaluate(Event{Timestamp: base.Add(10 * time.Minute), Name: "connection", Fields: excluded}); len(alerts) != 0 {
		t.Fatalf("excluded event emitted %d alerts", len(alerts))
	}
}

func TestEngineBoundsThresholdState(t *testing.T) {
	t.Parallel()
	enabled := true
	engine, err := New([]policy.DetectionRule{{
		ID:       "bounded",
		Enabled:  &enabled,
		Severity: "notice",
		Events:   []string{"exec"},
		Threshold: policy.Threshold{
			Count:   2,
			Within:  policy.Duration{Duration: time.Minute},
			GroupBy: []string{"cgroup"},
		},
		Message: "bounded",
	}}, []string{
		"baseline.cloud-metadata-access",
		"baseline.direct-email-egress",
		"baseline.policy-denial-burst",
	})
	if err != nil {
		t.Fatal(err)
	}
	engine.maxGroups = 4
	for index := range 20 {
		engine.Evaluate(Event{
			Timestamp: time.Unix(int64(index), 0),
			Name:      "exec",
			Fields:    map[string]any{"cgroup_id": uint64(index + 1)},
		})
	}
	if got := engine.StateCount(); got > 4 {
		t.Fatalf("state count = %d, want <= 4", got)
	}
}

func TestGlobsMatchAcrossPathSeparatorsAndCommandArguments(t *testing.T) {
	t.Parallel()
	if !matchGlobs([]string{"*/curl"}, "/usr/bin/curl") {
		t.Fatal("executable glob did not match nested path")
	}
	if !matchGlobs([]string{"*--data*"}, "/usr/bin/curl --data secret") {
		t.Fatal("command glob did not match command containing a path")
	}
}

func TestEngineBoundsGlobalThresholdSamples(t *testing.T) {
	t.Parallel()

	enabled := true
	engine, err := New([]policy.DetectionRule{{
		ID:       "sample-budget",
		Enabled:  &enabled,
		Severity: "notice",
		Events:   []string{"connection"},
		Threshold: policy.Threshold{
			Count:   10,
			Within:  policy.Duration{Duration: time.Minute},
			GroupBy: []string{"cgroup"},
		},
		Message: "bounded samples",
	}}, []string{
		"baseline.cloud-metadata-access",
		"baseline.direct-email-egress",
		"baseline.policy-denial-burst",
	})
	if err != nil {
		t.Fatal(err)
	}
	engine.maxSamples = 8
	for index := range 100 {
		engine.Evaluate(Event{
			Timestamp: time.Unix(int64(index), 0),
			Name:      "connection",
			Fields:    map[string]any{"cgroup_id": uint64(index + 1)},
		})
	}
	if got := engine.StateSampleCount(); got > engine.maxSamples {
		t.Fatalf("sample count = %d, want <= %d", got, engine.maxSamples)
	}
}

func TestDetectionIgnoresMutableCurrentIdentity(t *testing.T) {
	t.Parallel()

	fields := map[string]any{
		"current_cgroup":  "/workloads/" + strings.Repeat("x", 1<<20),
		"current_cmdline": []string{"/usr/bin/curl", "--data", "secret"},
		"current_exe":     "/usr/bin/curl",
		"cgroup_id":       uint64(42),
		"program":         "worker",
	}
	key := makeGroupKey("fixed-key", []string{"cgroup", "executable"}, fields)
	if key == ([sha256.Size]byte{}) {
		t.Fatal("group key is the zero digest")
	}
	if len(key[:]) != sha256.Size {
		t.Fatalf("group key size = %d, want %d", len(key[:]), sha256.Size)
	}
	context := eventMatchContext{fields: fields}
	if !matches(policy.DetectionMatch{}, nil, &context) {
		t.Fatal("empty match did not match event")
	}
	if matches(policy.DetectionMatch{CommandGlobs: []string{"*--data*"}}, nil, &context) {
		t.Fatal("mutable current command line matched a security rule")
	}
	for name, match := range map[string]policy.DetectionMatch{
		"executable": {ExecutableGlobs: []string{"/usr/bin/*"}},
		"cgroup":     {CgroupPrefixes: []string{"/workloads"}},
		"service":    {Services: []string{"worker.service"}},
	} {
		if matches(match, nil, &eventMatchContext{fields: fields}) {
			t.Errorf("mutable current %s matched a security rule", name)
		}
	}
	changed := cloneFields(fields)
	changed["current_cgroup"] = "/other"
	changed["current_exe"] = "/bin/other"
	if changedKey := makeGroupKey("fixed-key", []string{"cgroup", "executable"}, changed); changedKey != key {
		t.Fatal("mutable current enrichment changed the event-time detection group")
	}
}

func TestPathDetectionsRequireKernelResolvedEventFields(t *testing.T) {
	t.Parallel()

	enabled := true
	engine, err := New([]policy.DetectionRule{{
		ID: "resolved-shared-memory", Enabled: &enabled, Severity: "warning",
		Events:  []string{"exec_would_block"},
		Match:   policy.DetectionMatch{ExecutableGlobs: []string{"/dev/shm/**"}},
		Message: "resolved shared-memory path",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	alerts := engine.Evaluate(Event{
		Timestamp: time.Unix(1, 0),
		Name:      "exec_would_block",
		Fields: map[string]any{
			"exe":            "/dev/shm/payload",
			"requested_path": "/dev/shm/payload",
			"current_exe":    "/usr/bin/old-image",
		},
	})
	if len(alerts) != 1 || alerts[0].RuleID != "resolved-shared-memory" {
		t.Fatalf("alerts = %#v, want shared-memory baseline alert", alerts)
	}

	for name, fields := range map[string]map[string]any{
		"exec syscall alias":  {"requested_path": "/dev/shm/payload", "current_exe": "/dev/shm/payload"},
		"absolute open alias": {"requested_path": "/etc/shadow"},
		"relative open alias": {"requested_path": "shadow"},
		"symlink open alias":  {"requested_path": "/tmp/shadow-link"},
	} {
		context := eventMatchContext{fields: fields}
		if matches(policy.DetectionMatch{ExecutableGlobs: []string{"/dev/shm/**"}}, nil, &context) {
			t.Errorf("%s matched executable_globs without a resolved exe", name)
		}
		if matches(policy.DetectionMatch{FilePathGlobs: []string{"/etc/shadow"}}, nil, &context) {
			t.Errorf("%s matched file_path_globs without a resolved path", name)
		}
	}
	resolved := eventMatchContext{fields: map[string]any{"path": "/etc/shadow"}}
	if !matches(policy.DetectionMatch{FilePathGlobs: []string{"/etc/shadow"}}, nil, &resolved) {
		t.Fatal("kernel-resolved file path did not match file_path_globs")
	}
}

func TestTruncatedCanonicalPathMatchesOnlyBoundedSubtreePatterns(t *testing.T) {
	t.Parallel()

	path := "/safe/" + strings.Repeat("x", 242)
	fields := map[string]any{
		"path":           path,
		"path_truncated": true,
	}
	context := eventMatchContext{fields: fields}
	if matches(policy.DetectionMatch{FilePathGlobs: []string{path}}, nil, &context) {
		t.Fatal("truncated canonical path matched an exact path selector")
	}
	if !matches(policy.DetectionMatch{FilePathGlobs: []string{"/safe/**"}}, nil, &context) {
		t.Fatal("truncated canonical path did not match a fully captured subtree stem")
	}
}

func TestMissingNumericIdentityDoesNotMatchZeroOrCollapseGroups(t *testing.T) {
	t.Parallel()

	context := eventMatchContext{fields: map[string]any{}}
	if matches(policy.DetectionMatch{UIDs: []uint32{0}}, nil, &context) {
		t.Fatal("missing kernel UID matched UID zero")
	}
	if matches(policy.DetectionMatch{Ports: []uint16{0}}, nil, &context) {
		t.Fatal("missing port matched port zero")
	}
	first := makeGroupKey("missing-cgroup", []string{"cgroup"}, map[string]any{
		"pid": uint32(10), "process_start_ticks": uint64(100), "program": "first",
	})
	second := makeGroupKey("missing-cgroup", []string{"cgroup"}, map[string]any{
		"pid": uint32(11), "process_start_ticks": uint64(101), "program": "second",
	})
	if first == second {
		t.Fatal("events without cgroup IDs collapsed into one threshold group")
	}
}

func TestInboundSSHBruteForceBaselineGroupsByPeerAndLocalPort(t *testing.T) {
	t.Parallel()
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	attempt := func(at int64, peer string, localPort uint16) []Alert {
		return engine.Evaluate(Event{
			Timestamp: time.Unix(at, 0),
			Name:      "connection",
			Fields: map[string]any{
				"event": "connection", "direction": "inbound", "socket_protocol": "tcp",
				"peer_address": peer, "peer_port": uint16(40000), "local_port": localPort,
			},
		})
	}
	for index := range int64(19) {
		if alerts := attempt(index+1, "198.51.100.7", 22); len(alerts) != 0 {
			t.Fatalf("attempt %d alerts = %#v, want none below threshold", index+1, alerts)
		}
		// Other peers and other local ports must not add to the group.
		if alerts := attempt(index+1, "198.51.100.8", 2222); len(alerts) != 0 {
			t.Fatalf("non-SSH local port alerts = %#v", alerts)
		}
	}
	if alerts := attempt(20, "203.0.113.9", 22); len(alerts) != 0 {
		t.Fatalf("different peer alerts = %#v, want none", alerts)
	}
	alerts := attempt(21, "198.51.100.7", 22)
	if len(alerts) != 1 || alerts[0].RuleID != "baseline.inbound-ssh-bruteforce" {
		t.Fatalf("alerts = %#v, want inbound SSH brute-force alert", alerts)
	}
	if alerts := attempt(22, "198.51.100.7", 22); len(alerts) != 0 {
		t.Fatalf("alerts during cooldown = %#v, want none", alerts)
	}
}

func TestLocalPortSelectorMatchesBindDenials(t *testing.T) {
	t.Parallel()

	enabled := true
	engine, err := New([]policy.DetectionRule{{
		ID: "privileged-bind", Enabled: &enabled, Severity: "warning",
		Events:  []string{"bind_blocked", "bind_would_block"},
		Match:   policy.DetectionMatch{LocalPorts: []uint16{22, 80}},
		Exclude: policy.DetectionMatch{Ports: []uint16{22}},
		Message: "bind to a privileged port",
	}}, []string{
		"baseline.cloud-metadata-access", "baseline.direct-email-egress",
		"baseline.inbound-ssh-bruteforce", "baseline.policy-denial-burst",
	})
	if err != nil {
		t.Fatal(err)
	}
	bind := func(port any) int {
		return len(engine.Evaluate(Event{
			Timestamp: time.Unix(1, 0), Name: "bind_blocked",
			Fields: map[string]any{"local_address": "0.0.0.0", "local_port": port},
		}))
	}
	if got := bind(uint16(80)); got != 1 {
		t.Fatalf("bind to 80 alerts = %d, want 1", got)
	}
	if got := bind(uint16(22)); got != 1 {
		t.Fatalf("bind to 22 alerts = %d, want 1; peer-port exclude must not read local_port", got)
	}
	if got := bind(uint16(8080)); got != 0 {
		t.Fatalf("bind to 8080 alerts = %d, want 0", got)
	}
	if got := bind(nil); got != 0 {
		t.Fatalf("bind without local port alerts = %d, want 0", got)
	}
}

func TestUnixPathSelectorMatchesLiteralSocketPaths(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		patterns  []string
		path      string
		truncated bool
		want      bool
	}{
		{name: "exact", patterns: []string{"/run/docker.sock"}, path: "/run/docker.sock", want: true},
		{name: "exact sibling", patterns: []string{"/run/docker.sock"}, path: "/run/docker.sock2", want: false},
		{name: "subtree", patterns: []string{"/run/containerd/**"}, path: "/run/containerd/containerd.sock", want: true},
		{name: "subtree root", patterns: []string{"/run/containerd/**"}, path: "/run/containerd", want: true},
		{name: "subtree prefix sibling", patterns: []string{"/run/containerd/**"}, path: "/run/containerd2/x.sock", want: false},
		{name: "abstract", patterns: []string{"@/tmp/.X11-unix/X0"}, path: "@/tmp/.X11-unix/X0", want: true},
		{name: "abstract metacharacters are literal", patterns: []string{"@agent[1]"}, path: "@agent1", want: false},
		{name: "abstract metacharacters exact", patterns: []string{"@agent[1]"}, path: "@agent[1]", want: true},
		{name: "truncated exact", patterns: []string{"/run/docker.sock"}, path: "/run/docker.sock", truncated: true, want: false},
		{name: "missing path", patterns: []string{"/run/docker.sock"}, path: "", want: false},
	} {
		fields := map[string]any{"unix_op": "connect"}
		if test.path != "" {
			fields["path"] = test.path
		}
		if test.truncated {
			fields["path_truncated"] = true
		}
		context := eventMatchContext{fields: fields}
		if got := matches(policy.DetectionMatch{UnixPathGlobs: test.patterns}, nil, &context); got != test.want {
			t.Errorf("%s: matches = %t, want %t", test.name, got, test.want)
		}
	}
}

func TestPeerGroupFieldUsesPeerAddress(t *testing.T) {
	t.Parallel()

	first := makeGroupKey("rule", []string{"peer"}, map[string]any{"peer_address": "198.51.100.7", "peer_port": uint16(1)})
	samePeer := makeGroupKey("rule", []string{"peer"}, map[string]any{"peer_address": "198.51.100.7", "peer_port": uint16(2)})
	otherPeer := makeGroupKey("rule", []string{"peer"}, map[string]any{"peer_address": "198.51.100.8", "peer_port": uint16(1)})
	if first != samePeer {
		t.Fatal("peer grouping depended on the ephemeral peer port")
	}
	if first == otherPeer {
		t.Fatal("peer grouping collapsed distinct peer addresses")
	}
}

func TestBaselineRulesPassPolicyValidation(t *testing.T) {
	t.Parallel()

	bundle := policy.Bundle{DetectionRules: BaselineRules()}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("baseline rules failed policy validation: %v", err)
	}
}
