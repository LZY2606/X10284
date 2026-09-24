package mqttwire

import "strings"

// TopicMatch reports whether topic matches filter per MQTT wildcard rules.
// Invalid filters return false plus a diagnostic.
func TopicMatch(filter, topic string) (bool, string) {
	fs := strings.Split(filter, "/")
	ts := strings.Split(topic, "/")
	for i, f := range fs {
		switch f {
		case "#":
			if i != len(fs)-1 {
				return false, "'#' must be the final level"
			}
			if i == 0 || len(ts) >= len(fs) {
				return true, ""
			}
			return false, ""
		case "+":
			if i >= len(ts) {
				return false, ""
			}
		default:
			if i >= len(ts) || ts[i] != f {
				return false, ""
			}
		}
	}
	return len(ts) == len(fs), ""
}
