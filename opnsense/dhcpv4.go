package opnsense

import "strings"

type keaDHCPv4SearchResponse struct {
	Rows []struct {
		Address         string `json:"address"`
		HWAddr          string `json:"hwaddr"`
		Hostname        string `json:"hostname"`
		Type            string `json:"type"`
		State           string `json:"state"`
		If              string `json:"if"`
		IntfDescription string `json:"intf_description"`
		Descr           string `json:"descr"`
	} `json:"rows"`
	Total    int `json:"total"`
	RowCount int `json:"rowCount"`
	Current  int `json:"current"`
}

type dnsmasqDHCPSearchResponse struct {
	Rows []struct {
		Mac             string `json:"mac"`
		IP              string `json:"ip"`
		Hostname        string `json:"hostname"`
		If              string `json:"if"`
		IntfDescription string `json:"intf_description"`
		Starts          string `json:"starts"`
		Ends            string `json:"ends"`
	} `json:"rows"`
	Total    int `json:"total"`
	RowCount int `json:"rowCount"`
	Current  int `json:"current"`
}

// DHCPLease represents a single DHCP lease entry regardless of the backend.
type DHCPLease struct {
	Address         string
	Mac             string
	Hostname        string
	If              string
	IntfDescription string
	// Type indicates the DHCP backend: "kea" or "dnsmasq".
	Type  string
	State string
}

// DHCPLeases holds all DHCP leases returned by a fetch operation.
type DHCPLeases struct {
	Leases       []DHCPLease
	TotalEntries int
}

const fetchDHCPPayload = `{"current":1,"rowCount":-1,"sort":{},"searchPhrase":""}`

// FetchKEADHCPv4Leases fetches DHCP leases from the Kea DHCPv4 endpoint.
func (c *Client) FetchKEADHCPv4Leases() (DHCPLeases, *APICallError) {
	var resp keaDHCPv4SearchResponse
	var leases DHCPLeases

	path, ok := c.endpoints["dhcpv4"]
	if !ok {
		return leases, &APICallError{
			Endpoint:   "dhcpv4",
			Message:    "endpoint not found",
			StatusCode: 0,
		}
	}

	if err := c.do("POST", path, strings.NewReader(fetchDHCPPayload), &resp); err != nil {
		return leases, err
	}

	for _, row := range resp.Rows {
		leases.Leases = append(leases.Leases, DHCPLease{
			Address:         row.Address,
			Mac:             row.HWAddr,
			Hostname:        row.Hostname,
			If:              row.If,
			IntfDescription: row.IntfDescription,
			Type:            "kea",
			State:           row.State,
		})
	}

	leases.TotalEntries = resp.Total
	return leases, nil
}

// hostnameMapFromLeases builds a hostname map from a slice of DHCPLease entries,
// keyed by IP address. Leases without a hostname are skipped.
func hostnameMapFromLeases(leases []DHCPLease) map[string]string {
	m := make(map[string]string, len(leases))
	for _, l := range leases {
		if l.Hostname != "" {
			m[l.Address] = l.Hostname
		}
	}
	return m
}

// BuildDHCPHostnameMap builds a map of IP address to hostname by combining
// leases from all available DHCP backends (Kea and dnsmasq). It silently
// ignores failures from either backend so that a partial result is still
// usable. This is used to enrich ARP table entries with hostnames
// independently of which DHCP backend assigned the lease.
// When both backends return a hostname for the same IP address, the
// dnsmasq entry takes precedence (it is processed last).
func (c *Client) BuildDHCPHostnameMap() map[string]string {
	hostnameMap := make(map[string]string)

	if keaLeases, err := c.FetchKEADHCPv4Leases(); err == nil {
		for k, v := range hostnameMapFromLeases(keaLeases.Leases) {
			hostnameMap[k] = v
		}
	}

	if dnsmasqLeases, err := c.FetchDHCPDnsmasqLeases(); err == nil {
		for k, v := range hostnameMapFromLeases(dnsmasqLeases.Leases) {
			hostnameMap[k] = v
		}
	}

	return hostnameMap
}

// FetchDHCPDnsmasqLeases fetches DHCP leases from the dnsmasq endpoint.
func (c *Client) FetchDHCPDnsmasqLeases() (DHCPLeases, *APICallError) {
	var resp dnsmasqDHCPSearchResponse
	var leases DHCPLeases

	path, ok := c.endpoints["dhcpDnsmasq"]
	if !ok {
		return leases, &APICallError{
			Endpoint:   "dhcpDnsmasq",
			Message:    "endpoint not found",
			StatusCode: 0,
		}
	}

	if err := c.do("POST", path, strings.NewReader(fetchDHCPPayload), &resp); err != nil {
		return leases, err
	}

	for _, row := range resp.Rows {
		leases.Leases = append(leases.Leases, DHCPLease{
			Address:         row.IP,
			Mac:             row.Mac,
			Hostname:        row.Hostname,
			If:              row.If,
			IntfDescription: row.IntfDescription,
			Type:            "dnsmasq",
			State:           "active",
		})
	}

	leases.TotalEntries = resp.Total
	return leases, nil
}
