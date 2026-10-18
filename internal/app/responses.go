package app

import (
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/response"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

// newResponder builds the responder for the configured mode. Freezing needs
// TraceGuard's own cgroup so it can refuse to freeze itself; without it,
// freeze responses are skipped.
func newResponder(cfg config.Config, monitor *ebpf.Monitor, recorder *eventsink.Recorder, metrics *telemetry.Registry) *response.Responder {
	var freezer response.Freezer
	if self, err := response.SelfCgroup("/proc/self/cgroup"); err != nil {
		if cfg.ResponseMode == response.ModeEnforce {
			recorder.Error("cgroup freeze responses unavailable", err, nil)
		}
	} else {
		freezer = response.NewCgroupFreezer(cfg.CgroupPath, self)
	}
	return response.New(cfg.ResponseMode, monitor, freezer, func(message string, fields map[string]any) {
		action, _ := fields["action"].(string)
		metrics.IncResponseAction(action, message)
		recorder.Info(message, fields)
	})
}

func publishResponseStats(responder *response.Responder, monitor *ebpf.Monitor, metrics *telemetry.Registry) {
	// The drop counters are zero when the map cannot be read.
	egress, ingress, _ := monitor.ResponsePeerDrops()
	metrics.SetResponseStats(responder.Active(), egress, ingress)
}
