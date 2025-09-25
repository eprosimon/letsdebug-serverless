package letsdebug

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var (
	reservedNets []*net.IPNet
	dnsClient    *dns.Client
	once         sync.Once
)

func initDNS() {
	once.Do(func() {
		dnsClient = &dns.Client{
			Timeout: 10 * time.Second,
		}
	})
}

func lookup(name string, rrType uint16) ([]dns.RR, error) {
	result, err := lookupRaw(name, rrType)
	if err != nil {
		return nil, err
	}
	return result.Answer, nil
}

func lookupRaw(name string, rrType uint16) (*dns.Msg, error) {
	result, err := lookupWithTimeout(name, rrType, 60*time.Second)
	if err != nil {
		return nil, err
	}

	if result.Rcode == dns.RcodeServerFailure || result.Rcode == dns.RcodeRefused {
		return result, fmt.Errorf("DNS response for %s/%s did not have an acceptable response code: %s",
			name, dns.TypeToString[rrType], dns.RcodeToString[result.Rcode])
	}

	return result, nil
}

func lookupWithTimeout(name string, rrType uint16, timeout time.Duration) (*dns.Msg, error) {
	initDNS()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), rrType)
	m.RecursionDesired = true

	type dnsResponse struct {
		msg *dns.Msg
		err error
	}

	resultChan := make(chan dnsResponse, 1)

	go func() {
		// Try Google's DNS first
		msg, _, err := dnsClient.Exchange(m, "8.8.8.8:53")
		if err == nil && msg != nil {
			resultChan <- dnsResponse{msg, nil}
			return
		}

		// Fallback to Cloudflare's DNS
		msg, _, err = dnsClient.Exchange(m, "1.1.1.1:53")
		resultChan <- dnsResponse{msg, err}
	}()

	select {
	case res := <-resultChan:
		return res.msg, res.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("DNS lookup timeout for %s/%s", name, dns.TypeToString[rrType])
	}
}

// Utility functions
func normalizeFqdn(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	return strings.ToLower(name)
}

func isAddressReserved(ip net.IP) bool {
	for _, reserved := range reservedNets {
		if reserved.Contains(ip) {
			return true
		}
	}
	return false
}

func init() {
	// Initialize reserved networks
	reservedNets = []*net.IPNet{}
	reservedCIDRs := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10",
		"127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"255.255.255.255/32", "::/128", "::1/128",
		"64:ff9b::/96", "100::/64", "2001::/32", "2001:10::/28",
		"2001:20::/28", "2001:db8::/32", "2002::/16", "fc00::/7",
		"fe80::/10", "ff00::/8",
	}
	for _, cidr := range reservedCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		reservedNets = append(reservedNets, n)
	}
}
