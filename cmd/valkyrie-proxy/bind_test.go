package main

import "testing"

func TestDefaultBindHostIsLoopback(t *testing.T) {
	if defaultBindHost != "127.0.0.1" {
		t.Fatalf("defaultBindHost = %q, want 127.0.0.1 (unauthenticated endpoints must not bind all interfaces by default)", defaultBindHost)
	}
}

func TestResolveBindDefaults(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	cases := []struct {
		name     string
		vars     map[string]string
		wantHost string
		wantPort int
	}{
		{"empty falls back to loopback", nil, "127.0.0.1", defaultPort},
		{"host from env", map[string]string{"VALKYRIE_HOST": "0.0.0.0"}, "0.0.0.0", defaultPort},
		{"port from env", map[string]string{"VALKYRIE_PORT": "8443"}, "127.0.0.1", 8443},
		{"both from env", map[string]string{"VALKYRIE_HOST": "10.0.0.5", "VALKYRIE_PORT": "9100"}, "10.0.0.5", 9100},
		{"invalid port ignored", map[string]string{"VALKYRIE_PORT": "notaport"}, "127.0.0.1", defaultPort},
		{"non-positive port ignored", map[string]string{"VALKYRIE_PORT": "0"}, "127.0.0.1", defaultPort},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, port := resolveBindDefaults(env(c.vars))
			if host != c.wantHost || port != c.wantPort {
				t.Fatalf("resolveBindDefaults = (%q, %d), want (%q, %d)", host, port, c.wantHost, c.wantPort)
			}
		})
	}
}

func TestListenAddr(t *testing.T) {
	cases := []struct {
		host string
		port int
		want string
	}{
		{"127.0.0.1", 9001, "127.0.0.1:9001"},
		{"0.0.0.0", 9001, "0.0.0.0:9001"},
		{"::1", 9001, "[::1]:9001"},
	}
	for _, c := range cases {
		if got := listenAddr(c.host, c.port); got != c.want {
			t.Errorf("listenAddr(%q, %d) = %q, want %q", c.host, c.port, got, c.want)
		}
	}
}
