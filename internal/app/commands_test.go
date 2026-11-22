package app

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/config"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/response"
)

func TestRequestReloadReturnsTheReloadOutcome(t *testing.T) {
	t.Parallel()

	reloads := make(chan reloadRequest, 1)
	go func() {
		request := <-reloads
		if request.trigger != "command" {
			t.Errorf("trigger = %q", request.trigger)
		}
		request.done <- errors.New("parse local policy: bad yaml")
	}()
	if err := requestReload(t.Context(), reloads, "command"); err == nil || !strings.Contains(err.Error(), "bad yaml") {
		t.Fatalf("requestReload = %v, want the reload's error", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := requestReload(ctx, make(chan reloadRequest), "command"); !errors.Is(err, context.Canceled) {
		t.Fatalf("requestReload on a stopped agent = %v", err)
	}
}

func TestCommandsNeverBlockTheManager(t *testing.T) {
	t.Parallel()

	responder := response.New(response.ModeDryRun, nil, nil, func(string, map[string]any) {}, response.Options{})
	handler := commandHandler{
		responder: responder,
		protected: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("198.51.100.10")}, nil },
	}
	if _, err := handler.Apply("c1", "block_peer", "::ffff:198.51.100.10", time.Hour); err == nil || !strings.Contains(err.Error(), "manager") {
		t.Fatalf("Apply on the manager's address = %v, want refusal", err)
	}
	detail, err := handler.Apply("c2", "block_peer", "203.0.113.7", time.Hour)
	if err != nil || !strings.HasPrefix(detail, "dry-run:") {
		t.Fatalf("dry-run Apply = %q, %v; want a dry-run note", detail, err)
	}
}

func TestManagerAddressesFromALiteralHost(t *testing.T) {
	t.Parallel()

	addresses, err := managerAddresses(config.Config{EventExportURL: "https://198.51.100.10:8443/api/v1/events"}, nil)()
	if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("198.51.100.10") {
		t.Fatalf("addresses = %v, %v", addresses, err)
	}
	// The connected peer is protected too, such as a proxy in front of the manager.
	proxy := netip.MustParseAddr("192.0.2.80")
	addresses, err = managerAddresses(config.Config{}, func() (netip.Addr, bool) { return proxy, true })()
	if err != nil || len(addresses) != 1 || addresses[0] != proxy {
		t.Fatalf("addresses with a connected peer = %v, %v", addresses, err)
	}
	// A name that cannot be resolved refuses the block rather than risking it.
	broken := managerAddresses(config.Config{EventExportURL: "https://manager.invalid/api/v1/events"}, nil)
	if _, err := broken(); err == nil {
		t.Fatal("unresolvable manager name gave no error")
	}
	handler := commandHandler{
		responder: response.New(response.ModeEnforce, nil, nil, func(string, map[string]any) {}, response.Options{}),
		protected: broken,
	}
	if _, err := handler.Apply("c3", "block_peer", "203.0.113.7", time.Hour); err == nil || !strings.Contains(err.Error(), "confirm") {
		t.Fatalf("Apply with an unconfirmed manager address = %v", err)
	}
}

func TestOlderPolicyLoadsNeverRollBackANewerOne(t *testing.T) {
	t.Parallel()

	var applier policyApplier
	applier.applied = 5
	// A bundle loaded before the one in force is skipped without touching anything.
	if err := applier.apply(nil, nil, nil, policyconfig.Bundle{}, policyconfig.LoadMetadata{Sequence: 4}); err != nil {
		t.Fatalf("apply of an older load = %v", err)
	}
	if applier.applied != 5 {
		t.Fatalf("applied sequence = %d, want 5", applier.applied)
	}
}

func TestAZonedManagerAddressIsStillProtected(t *testing.T) {
	t.Parallel()

	handler := commandHandler{
		responder: response.New(response.ModeDryRun, nil, nil, func(string, map[string]any) {}, response.Options{}),
		protected: func() ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}, nil },
	}
	if _, err := handler.Apply("c1", "block_peer", "fe80::1", time.Hour); err == nil || !strings.Contains(err.Error(), "manager") {
		t.Fatalf("Apply on the zoned manager's address = %v, want refusal", err)
	}
}
