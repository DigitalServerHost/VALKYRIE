package main

import "testing"

func TestDefaultBindHostIsLoopback(t *testing.T) {
	if defaultBindHost != "127.0.0.1" {
		t.Fatalf("defaultBindHost = %q, want 127.0.0.1 (unauthenticated endpoints must not bind all interfaces by default)", defaultBindHost)
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
