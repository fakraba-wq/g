//go:build !windows

package main

import "context"

func systemEvidence(ctx context.Context, boot, activity bool) evidence {
	result := evidence{}
	for _, pair := range []struct {
		key       string
		requested bool
	}{{"boot", boot}, {"activity", activity}} {
		state, note := "not-requested", "Not authorized in this scan."
		if pair.requested {
			state = "unavailable"
			note = "Windows system metadata requires Windows."
		}
		result.Collection = append(result.Collection, collection{Key: pair.key, State: state, Note: note})
	}
	return result
}
