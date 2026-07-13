package main

import (
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
