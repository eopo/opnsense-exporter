package collector

import (
	"log/slog"

	"github.com/AthennaMind/opnsense-exporter/opnsense"
	"github.com/prometheus/client_golang/prometheus"
)

type dhcpCollector struct {
	leases    *prometheus.Desc
	log       *slog.Logger
	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &dhcpCollector{
		subsystem: DHCPSubsystem,
	})
}

func (c *dhcpCollector) Name() string {
	return c.subsystem
}

func (c *dhcpCollector) Register(namespace, instance string, log *slog.Logger) {
	c.log = log
	c.instance = instance

	c.log.Debug("Registering collector", "collector", c.Name())

	c.leases = buildPrometheusDesc(c.subsystem, "lease",
		"DHCP lease entries by address, mac, hostname, interface description and type (kea or dnsmasq)",
		[]string{"address", "mac", "hostname", "interface_description", "type"},
	)
}

func (c *dhcpCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.leases
}

func (c *dhcpCollector) Update(client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	keaLeases, err := client.FetchKEADHCPv4Leases()
	if err != nil {
		c.log.Warn("failed to fetch Kea DHCPv4 leases; skipping",
			"collector", c.Name(),
			"err", err.Error(),
		)
	} else {
		for _, lease := range keaLeases.Leases {
			ch <- prometheus.MustNewConstMetric(
				c.leases,
				prometheus.GaugeValue,
				1,
				lease.Address,
				lease.Mac,
				lease.Hostname,
				lease.IntfDescription,
				lease.Type,
				c.instance,
			)
		}
	}

	dnsmasqLeases, dnsmasqErr := client.FetchDHCPDnsmasqLeases()
	if dnsmasqErr != nil {
		c.log.Warn("failed to fetch dnsmasq DHCP leases; skipping",
			"collector", c.Name(),
			"err", dnsmasqErr.Error(),
		)
	} else {
		for _, lease := range dnsmasqLeases.Leases {
			ch <- prometheus.MustNewConstMetric(
				c.leases,
				prometheus.GaugeValue,
				1,
				lease.Address,
				lease.Mac,
				lease.Hostname,
				lease.IntfDescription,
				lease.Type,
				c.instance,
			)
		}
	}

	// Return an error only when both backends fail.
	if err != nil && dnsmasqErr != nil {
		return err
	}
	return nil
}
