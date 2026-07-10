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
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/hardening"
	"github.com/L1ghtn1ng/traceguard/internal/logging"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
	"github.com/L1ghtn1ng/traceguard/internal/version"
)

func main() {
	os.Exit(run())
}

func run() int {
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
	defer writer.Close()

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
	defer signal.Stop(reloadSignalCh)
	go func() {
		for range reloadSignalCh {
			select {
			case reloadCh <- struct{}{}:
			default:
			}
		}
	}()

	metrics := telemetry.NewRegistry()
	if err := metrics.StartServer(ctx, cfg.MetricsAddr, logger); err != nil {
		logger.Error("start metrics server", err, nil)
		return 1
	}

	recorder, err := eventsink.NewRecorder(ctx, logger, metrics, eventsink.Config{
		ArchivePath:         cfg.EventArchivePath,
		BlockedPath:         filepath.Join(filepath.Dir(cfg.LogPath), "blocked.log"),
		DomainsPath:         filepath.Join(filepath.Dir(cfg.LogPath), "domains.log"),
		ExportURL:           cfg.EventExportURL,
		ExportAuthorization: cfg.EventExportAuthorization,
		ExportSpool:         cfg.EventExportSpool,
		ExportCAPath:        cfg.EventExportCAPath,
		ExportClientCert:    cfg.EventExportClientCert,
		ExportClientKey:     cfg.EventExportClientKey,
		SyslogURL:           cfg.EventSyslogURL,
		SyslogFacility:      cfg.EventSyslogFacility,
		SyslogTag:           cfg.EventSyslogTag,
		SyslogTimeout:       cfg.EventSyslogTimeout,
		SyslogCAPath:        cfg.EventSyslogCAPath,
	})
	if err != nil {
		logger.Error("initialize event recorder", err, nil)
		return 1
	}
	defer recorder.Close()

	if err := app.Run(ctx, cfg, recorder, metrics, reloadCh); err != nil {
		logger.Error("traceguard", err, nil)
		return 1
	}
	return 0
}
