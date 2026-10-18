package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/L1ghtn1ng/traceguard/internal/app"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/doctor"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/hardening"
	"github.com/L1ghtn1ng/traceguard/internal/logging"
	"github.com/L1ghtn1ng/traceguard/internal/replay"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
	"github.com/L1ghtn1ng/traceguard/internal/version"
)

func main() {
	os.Exit(run())
}

func run() (exitCode int) {
	hardening.Anchor()

	cfg, err := config.Parse()
	if err != nil {
		log.Printf("parse config: %v", err)
		return 1
	}
	if cfg.PrintVersion {
		fmt.Println(version.String())
		return 0
	}
	if cfg.Doctor {
		if err := doctor.Run(cfg, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if cfg.ReplayPath != "" {
		summary, err := replay.Run(replay.Config{ArchivePath: cfg.ReplayPath, PolicyPath: cfg.PolicyPath}, os.Stdout)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := replay.WriteSummary(summary, os.Stderr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if cfg.Unpin {
		if err := ebpf.Unpin(ebpf.DefaultPinPath); err != nil {
			log.Printf("remove eBPF pins: %v", err)
			return 1
		}
		return 0
	}
	if cfg.EmergencyAllow {
		// Remove persistent enforcement before opening listeners or remote sinks.
		// NewMonitor immediately rebuilds the requested observation hooks with an
		// empty policy, and re-pins that safe state when pinning remains enabled.
		if err := ebpf.Unpin(ebpf.DefaultPinPath); err != nil {
			log.Printf("clear pinned eBPF state for emergency allow: %v", err)
			return 1
		}
	}

	writer, err := logging.NewRotatingFile(cfg.LogPath, logging.Options{
		MaxSizeBytes: 1 << 30,
		MaxBackups:   5,
		FileMode:     0o640,
		DirMode:      0o750,
	})
	if err != nil {
		log.Printf("initialize logger: %v", err)
		return 1
	}
	defer func() {
		if closeErr := writer.Close(); closeErr != nil {
			log.Printf("close logger: %v", closeErr)
			exitCode = 1
		}
	}()

	logger, err := logging.NewLogger(writer, cfg.LogFormat)
	if err != nil {
		log.Printf("initialize structured logger: %v", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		// Restore default signal handling as soon as graceful shutdown starts so a
		// second SIGINT or SIGTERM can terminate a stuck shutdown.
		stop()
	}()
	reloadSignalCh := make(chan os.Signal, 1)
	reloadCh := make(chan struct{}, 1)
	signal.Notify(reloadSignalCh, syscall.SIGHUP)
	reloadForwardStop := make(chan struct{})
	defer func() {
		signal.Stop(reloadSignalCh)
		close(reloadForwardStop)
	}()
	go forwardReloadSignals(reloadForwardStop, reloadSignalCh, reloadCh)

	metrics := telemetry.NewRegistry()
	if err := metrics.StartServer(ctx, cfg.MetricsAddr, logger); err != nil {
		reportLoggerError(logger, "start metrics server", err)
		return 1
	}

	recorder, err := eventsink.NewRecorder(ctx, logger, metrics, eventsink.Config{
		ArchivePath:             cfg.EventArchivePath,
		BlockedPath:             filepath.Join(filepath.Dir(cfg.LogPath), "blocked.log"),
		DomainsPath:             filepath.Join(filepath.Dir(cfg.LogPath), "domains.log"),
		ExportURL:               cfg.EventExportURL,
		ExportAuthorization:     cfg.EventExportAuthorization,
		ExportAuthorizationFile: cfg.EventExportAuthorizationFile,
		ExportSpool:             cfg.EventExportSpool,
		ExportCAPath:            cfg.EventExportCAPath,
		ExportClientCert:        cfg.EventExportClientCert,
		ExportClientKey:         cfg.EventExportClientKey,
		SyslogURL:               cfg.EventSyslogURL,
		SyslogFacility:          cfg.EventSyslogFacility,
		SyslogTag:               cfg.EventSyslogTag,
		SyslogTimeout:           cfg.EventSyslogTimeout,
		SyslogCAPath:            cfg.EventSyslogCAPath,
	})
	if err != nil {
		reportLoggerError(logger, "initialize event recorder", err)
		return 1
	}
	defer func() {
		if closeErr := recorder.Close(); closeErr != nil {
			reportLoggerError(logger, "close event recorder", closeErr)
			exitCode = 1
		}
	}()

	if err := app.Run(ctx, cfg, recorder, metrics, reloadCh); err != nil {
		reportLoggerError(logger, "traceguard", err)
		return 1
	}
	return 0
}

func reportLoggerError(logger *logging.Logger, message string, err error) {
	if logErr := logger.Error(message, err, nil); logErr != nil {
		log.Printf("%s: %v (logging failed: %v)", message, err, logErr)
	}
}

func forwardReloadSignals(stop <-chan struct{}, signals <-chan os.Signal, reloadCh chan<- struct{}) {
	for {
		select {
		case <-stop:
			return
		case _, ok := <-signals:
			if !ok {
				return
			}
			select {
			case reloadCh <- struct{}{}:
			default:
			}
		}
	}
}
