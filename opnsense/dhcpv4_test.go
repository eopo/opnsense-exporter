package opnsense

import (
	"reflect"
	"testing"
)

func TestHostnameMapFromLeases(t *testing.T) {
	tests := []struct {
		name     string
		leases   []DHCPLease
		expected map[string]string
	}{
		{
			name:     "empty leases",
			leases:   []DHCPLease{},
			expected: map[string]string{},
		},
		{
			name: "kea leases with hostnames",
			leases: []DHCPLease{
				{Address: "192.168.1.10", Hostname: "host-a", Type: "kea"},
				{Address: "192.168.1.11", Hostname: "host-b", Type: "kea"},
			},
			expected: map[string]string{
				"192.168.1.10": "host-a",
				"192.168.1.11": "host-b",
			},
		},
		{
			name: "dnsmasq leases with hostnames",
			leases: []DHCPLease{
				{Address: "10.0.0.5", Hostname: "printer", Type: "dnsmasq"},
				{Address: "10.0.0.6", Hostname: "phone", Type: "dnsmasq"},
			},
			expected: map[string]string{
				"10.0.0.5": "printer",
				"10.0.0.6": "phone",
			},
		},
		{
			name: "leases with empty hostname are skipped",
			leases: []DHCPLease{
				{Address: "192.168.1.20", Hostname: "known-host", Type: "kea"},
				{Address: "192.168.1.21", Hostname: "", Type: "kea"},
			},
			expected: map[string]string{
				"192.168.1.20": "known-host",
			},
		},
		{
			name: "dnsmasq entry overwrites kea entry for same IP",
			leases: []DHCPLease{
				{Address: "192.168.1.30", Hostname: "kea-name", Type: "kea"},
				{Address: "192.168.1.30", Hostname: "dnsmasq-name", Type: "dnsmasq"},
			},
			expected: map[string]string{
				"192.168.1.30": "dnsmasq-name",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := hostnameMapFromLeases(tc.leases)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("hostnameMapFromLeases() = %v; want %v", result, tc.expected)
			}
		})
	}
}
