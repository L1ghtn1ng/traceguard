package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	neturl "net/url"
	"strings"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/commands"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/response"
)

const (
	// commandErrorDedupeTTL keeps a manager outage from logging every retry.
	commandErrorDedupeTTL = 5 * time.Minute
	// reloadQueueWait and reloadResultWait bound how long a refresh_policy
	// command waits to be taken and then for the reload to finish.
	reloadQueueWait  = 30 * time.Second
	reloadResultWait = 90 * time.Second
	resolveTimeout   = 2 * time.Second
	// commandStateSuffix names the command journal after the response
	// state file, so the two can never be the same file. It remembers
	// command results across restarts so a redelivered command never runs
	// twice.
	commandStateSuffix = ".commands.json"
)

// commandHandler carries out manager commands.
type commandHandler struct {
	responder *response.Responder
	refresh   func() error
	// protected returns the manager's own addresses, which a command must
	// never block: that would cut off the channel that could lift it. An
	// error means they could not be confirmed.
	protected func() ([]netip.Addr, error)
}

func (h commandHandler) Apply(commandID, action, target string, duration time.Duration) (string, error) {
	if action == policy.ResponseBlockPeer && h.protected != nil {
		if address, err := netip.ParseAddr(strings.TrimSpace(target)); err == nil {
			// Compared without zones: the kernel block is keyed by address
			// alone, so fe80::1 blocks fe80::1%eth0 too.
			address = address.Unmap().WithZone("")
			managers, err := h.protected()
			if err != nil {
				return "", fmt.Errorf("refusing to block a peer: %w", err)
			}
			for _, manager := range managers {
				if manager.Unmap().WithZone("") == address {
					return "", errors.New("refusing to block the manager's own address")
				}
			}
		}
	}
	if err := h.responder.Apply(commandID, action, target, duration); err != nil {
		return "", err
	}
	if h.responder.Mode() == response.ModeDryRun {
		return "dry-run: recorded what this would do; nothing was changed (TRACEGUARD_RESPONSE_MODE=dry-run)", nil
	}
	return "", nil
}

func (h commandHandler) Lift(commandID, action, target string) error {
	return h.responder.Lift(commandID, action, target)
}

func (h commandHandler) RefreshPolicy() error {
	return h.refresh()
}

// managerAddresses returns the addresses a command must not block: the
// event export host, which commands share, resolved each time so an address
// change is followed, plus the address the poller is actually connected to
// (the manager, or a proxy in front of it). A host name that cannot be
// resolved is an error, so a block is refused rather than risked.
func managerAddresses(cfg config.Config, connected func() (netip.Addr, bool)) func() ([]netip.Addr, error) {
	parsed, err := neturl.Parse(strings.TrimSpace(cfg.EventExportURL))
	host := ""
	if err == nil {
		host = parsed.Hostname()
	}
	return func() ([]netip.Addr, error) {
		var addresses []netip.Addr
		if connected != nil {
			if peer, ok := connected(); ok {
				addresses = append(addresses, peer)
			}
		}
		if host == "" {
			return addresses, nil
		}
		if address, err := netip.ParseAddr(host); err == nil {
			return append(addresses, address), nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
		defer cancel()
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("cannot confirm the manager's address")
		}
		return append(addresses, resolved...), nil
	}
}

// requestReload asks the reload worker for a reload and waits for it to
// load and apply policy, so a refresh_policy result says what happened.
func requestReload(ctx context.Context, reloads chan<- reloadRequest, trigger string) error {
	done := make(chan error, 1)
	select {
	case reloads <- reloadRequest{trigger: trigger, done: done}:
	case <-time.After(reloadQueueWait):
		return errors.New("another policy reload is still running; try again")
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-time.After(reloadResultWait):
		return errors.New("the policy reload is still running; check the agent's policy records")
	case <-ctx.Done():
		return ctx.Err()
	}
}

// newCommandPoller builds the manager command poller, which reaches the
// event export host with the event export credentials.
func newCommandPoller(cfg config.Config, recorder *eventsink.Recorder, handler commands.Handler) (*commands.Poller, error) {
	client, authorization, err := eventsink.ExportClient(eventsink.Config{
		ExportAuthorization:     cfg.EventExportAuthorization,
		ExportAuthorizationFile: cfg.EventExportAuthorizationFile,
		ExportCAPath:            cfg.EventExportCAPath,
		ExportClientCert:        cfg.EventExportClientCert,
		ExportClientKey:         cfg.EventExportClientKey,
	})
	if err != nil {
		return nil, err
	}
	statePath := ""
	if cfg.ResponseStatePath != "" {
		statePath = cfg.ResponseStatePath + commandStateSuffix
	}
	return commands.New(commands.Config{
		URL: cfg.CommandURL, Client: client, Authorization: authorization, Actions: cfg.CommandActions,
		StatePath: statePath,
		Record: func(level, message string, fields map[string]any) {
			if level == "error" {
				recorder.ErrorDedup(message, nil, fields, commandErrorDedupeTTL)
				return
			}
			recorder.Info(message, fields)
		},
	}, handler)
}

// forwardReloads passes SIGHUP reload requests on to the shared reload
// channel, coalescing them while one is waiting.
func forwardReloads(ctx context.Context, from <-chan struct{}, to chan<- reloadRequest) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-from:
			if !ok {
				return
			}
			select {
			case to <- reloadRequest{trigger: "sighup"}:
			default:
			}
		}
	}
}
