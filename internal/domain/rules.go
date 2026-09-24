package domain

// RuleParams are tunable adjudication parameters. Revisions create a new
// immutable rule version; only dependent derived nodes are recomputed.
type RuleParams struct {
	// SessionExpiryMode controls endpoint semantics at disconnect/reconnect:
	// "exclusive" -> t_disconnect + expiry < t_reconnect required for resume
	// "inclusive" -> <= is accepted as a valid resume.
	// "candidates" -> an exact boundary keeps both legal outcomes.
	SessionExpiryMode string `json:"session_expiry_mode"`
	// TreatUnknownPacketAsError turns parse diagnostics into hard anomalies
	// instead of preserving the packet with a non-blocking diagnostic.
	TreatUnknownPacketAsError bool `json:"treat_unknown_packet_as_error"`
}

func DefaultRules() RuleParams {
	return RuleParams{
		SessionExpiryMode:         "exclusive",
		TreatUnknownPacketAsError: false,
	}
}

func (r RuleParams) Valid() string {
	switch r.SessionExpiryMode {
	case "exclusive", "inclusive", "candidates":
	default:
		return "session_expiry_mode must be exclusive|inclusive|candidates"
	}
	return ""
}
