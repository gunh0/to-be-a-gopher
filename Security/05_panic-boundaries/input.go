// Package panics shows which input-driven panics net/http contains for you,
// which ones take the whole process down, and how to build recovery
// boundaries and panic-free parsing so a malformed request costs one request,
// not the service.
package panics

import (
	"encoding/json"
	"strings"
)

// BearerUnsafe extracts the token from "Bearer <token>". A header without a
// space ("Bearer", "Basic") yields a one-element slice and [1] panics with
// "index out of range" (CWE-248).
func BearerUnsafe(header string) string {
	return strings.Split(header, " ")[1]
}

// Bearer uses strings.Cut, which reports whether the separator was found
// instead of returning a shorter slice, and checks the scheme.
func Bearer(header string) (string, bool) {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

// RoleUnsafe reads a claim decoded into map[string]any. The single-value
// type assertion panics when the claim is missing (nil interface) or has
// another JSON type ({"role": 1} decodes as float64).
func RoleUnsafe(claims map[string]any) string {
	return claims["role"].(string)
}

// Role uses the comma-ok form, which never panics.
func Role(claims map[string]any) (string, bool) {
	role, ok := claims["role"].(string)
	return role, ok
}

// Event is a client-submitted audit event.
type Event struct {
	Action string            `json:"action"`
	Labels map[string]string `json:"labels"`
}

// DecodeEventUnsafe decodes an event and stamps a server-side label. If the
// client omits "labels" or sends null, Labels is a nil map and the write
// panics with "assignment to entry in nil map" (CWE-476).
func DecodeEventUnsafe(body []byte, host string) (Event, error) {
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		return Event{}, err
	}
	ev.Labels["received_by"] = host
	return ev, nil
}

// DecodeEvent initialises every map and pointer the server writes to,
// regardless of what the client sent.
func DecodeEvent(body []byte, host string) (Event, error) {
	var ev Event
	if err := json.Unmarshal(body, &ev); err != nil {
		return Event{}, err
	}
	if ev.Labels == nil {
		ev.Labels = make(map[string]string, 1)
	}
	ev.Labels["received_by"] = host
	return ev, nil
}
