package main

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestForwardReloadSignalsStopsAndForwards(t *testing.T) {
	t.Parallel()

	stop := make(chan struct{})
	signals := make(chan os.Signal, 1)
	reloads := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		forwardReloadSignals(stop, signals, reloads)
		close(done)
	}()

	signals <- syscall.SIGHUP
	select {
	case <-reloads:
	case <-time.After(time.Second):
		t.Fatal("SIGHUP was not forwarded")
	}

	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("signal forwarder did not stop")
	}
}

func TestStoppingFields(t *testing.T) {
	t.Parallel()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := stoppingFields(canceled, nil); got["reason"] != "signal" || got["event"] != "agent_stopping" {
		t.Fatalf("signal stop = %v", got)
	}
	if got := stoppingFields(context.Background(), errors.New("ring buffer closed")); got["reason"] != "error" || got["error"] != "ring buffer closed" {
		t.Fatalf("error stop = %v", got)
	}
	if got := stoppingFields(context.Background(), nil); got["reason"] != "exited" {
		t.Fatalf("plain exit = %v", got)
	}
}
