package app

import (
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/response"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

// newResponder builds the responder for the configured mode and undoes what
// an earlier run left active. Freezing needs TraceGuard's own cgroup so it can
// refuse to freeze itself; without it, freeze responses are skipped.
func newResponder(cfg config.Config, monitor *ebpf.Monitor, recorder *eventsink.Recorder, metrics *telemetry.Registry) *response.Responder {
	const procCgroup = "/proc/self/cgroup"
	var freezer response.Freezer
	if _, err := response.SelfCgroup(procCgroup); err != nil {
		if cfg.ResponseMode == response.ModeEnforce {
			recorder.Error("cgroup freeze responses unavailable", err, nil)
		}
	} else {
		freezer = response.NewCgroupFreezer(cfg.CgroupPath, procCgroup)
	}
	options := response.Options{StatePath: cfg.ResponseStatePath}
	bootID, err := response.BootID("/proc/sys/kernel/random/boot_id")
	if err != nil {
		// Without a boot ID a state file cannot be told apart from one
		// written before a reboot, when its cgroup IDs mean nothing.
		recorder.Error("response state disabled", err, nil)
		options.StatePath = ""
	}
	options.BootID = bootID
	responder := response.New(cfg.ResponseMode, monitor, freezer, func(message string, fields map[string]any) {
		action, _ := fields["action"].(string)
		metrics.IncResponseAction(action, message)
		recorder.Info(message, fields)
	}, options)
	responder.Recover()
	return responder
}

func publishResponseStats(responder *response.Responder, monitor *ebpf.Monitor, metrics *telemetry.Registry) {
	// The drop counters are zero when the map cannot be read.
	egress, ingress, _ := monitor.ResponsePeerDrops()
	metrics.SetResponseStats(responder.Active(), egress, ingress)
}
