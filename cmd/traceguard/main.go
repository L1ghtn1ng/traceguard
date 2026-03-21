package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"traceguard/internal/app"
	"traceguard/internal/config"
	"traceguard/internal/doctor"
	"traceguard/internal/eventsink"
	"traceguard/internal/logging"
	"traceguard/internal/telemetry"
	"traceguard/internal/version"
)

func main() {
	cfg, err := config.Parse()
	if err != nil {
		log.Fatalf("parse config: %v", err)
	}
	if cfg.PrintVersion {
		fmt.Println(version.String())
		return
	}
	if cfg.Doctor {
		if err := doctor.Run(cfg, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	writer, err := logging.NewRotatingFile(cfg.LogPath, logging.Options{
		MaxSizeBytes: 1 << 30,
		MaxBackups:   5,
		FileMode:     0o640,
		DirMode:      0o750,
	})
	if err != nil {
		log.Fatalf("initialize logger: %v", err)
	}
	defer writer.Close()

	logger, err := logging.NewLogger(writer, cfg.LogFormat)
	if err != nil {
		log.Fatalf("initialize structured logger: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
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
		os.Exit(1)
	}

	recorder, err := eventsink.NewRecorder(ctx, logger, metrics, eventsink.Config{
		ArchivePath:      cfg.EventArchivePath,
		ExportURL:        cfg.EventExportURL,
		ExportAuthHeader: cfg.EventExportAuthHeader,
		ExportAuthToken:  cfg.EventExportAuthToken,
		ExportBatchSize:  cfg.EventExportBatchSize,
		ExportFlush:      cfg.EventExportFlush,
		ExportSpoolPath:  cfg.EventExportSpoolPath,
		ExportCAPath:     cfg.EventExportCAPath,
		ExportClientCert: cfg.EventExportClientCert,
		ExportClientKey:  cfg.EventExportClientKey,
		ExportGzip:       cfg.EventExportGzip,
	})
	if err != nil {
		logger.Error("initialize event recorder", err, nil)
		os.Exit(1)
	}
	defer recorder.Close()

	if err := app.Run(ctx, cfg, recorder, metrics, reloadCh); err != nil {
		logger.Error("traceguard", err, nil)
		os.Exit(1)
	}
}
