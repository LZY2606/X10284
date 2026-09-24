package engine

import (
	"fmt"

	"github.com/example/mqtt-session-forensics/internal/model"
)

func (e *Engine) onDisconnect(p *model.RawPacket) {
	cr := e.conns[p.ConnectionID]
	if cr == nil {
		return
	}
	gr := e.gens[cr.genUID]
	gr.node.State = model.GenDisconnected
	gr.node.CloseAtNS = p.ObservedAt.EpochNS
	gr.node.Sources = append(gr.node.Sources, srcPkt(p, "observed_at"))

	// A generation gone away between PUBLISH and PUBCOMP leaves the handshake
	// reconstructable: record STUCK_INTERRUPTED but remember the last reached
	// QoS2 stage in the observations, so resume never restarts from scratch.
	for _, byDir := range gr.flows {
		for _, incs := range byDir {
			for _, f := range incs {
				if f.QoS == 2 && f.Phase != model.PhaseQ2Done {
					f.Interrupted = true
					f.Phase = model.PhaseStuck
					e.addDiag(model.SevWarning, "qos2_interrupted",
						fmt.Sprintf("%s disconnected mid QoS2 handshake (last packet %s)",
							f.UID, p.ID), f.UID, p.ID)
				}
			}
		}
	}
}
