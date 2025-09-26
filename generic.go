package letsdebug

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"

	"github.com/eggsampler/acme/v3"

	"fmt"

	"net/http"
	"net/url"

	"time"

	"encoding/json"

	"github.com/miekg/dns"
	"github.com/weppos/publicsuffix-go/net/publicsuffix"
	psl "github.com/weppos/publicsuffix-go/publicsuffix"
)

// validMethodChecker ensures that the provided authorization method is valid and supported.
type validMethodChecker struct{}

func (c validMethodChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if validMethods[method] {
		return nil, errNotApplicable
	}

	return []Problem{notValidMethod(method)}, nil
}

func notValidMethod(method ValidationMethod) Problem {
	var supportedMethods []string
	for k := range validMethods {
		supportedMethods = append(supportedMethods, string(k))
	}
	return Problem{
		Name:        "InvalidMethod",
		Explanation: fmt.Sprintf(`"%s" is not a supported validation method.`, method),
		Detail:      fmt.Sprintf("Supported methods: %s", strings.Join(supportedMethods, ", ")),
		Severity:    SeverityFatal,
	}
}

var dnsLabelCharacterRegexp = regexp.MustCompile("^[a-z0-9-]+$")

// validDomainChecker ensures that the FQDN is well-formed and is part of a public suffix.
type validDomainChecker struct{}

func (c validDomainChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	var probs []Problem

	domain = strings.TrimPrefix(domain, "*.")

	if len(domain) == 0 {
		probs = append(probs, invalidDomain(domain, "Domain is empty"))
		return probs, nil
	}

	for _, ch := range []byte(domain) {
		if ('a' > ch || ch > 'z') &&
			('A' > ch || ch > 'Z') &&
			('0' > ch || ch > '9') &&
			ch != '.' && ch != '-' {
			probs = append(probs, invalidDomain(domain, fmt.Sprintf("Invalid character present: %c", ch)))
			return probs, nil
		}
	}

	if len(domain) > 253 {
		probs = append(probs, invalidDomain(domain, "Domain too long"))
		return probs, nil
	}

	if ip := net.ParseIP(domain); ip != nil {
		probs = append(probs, invalidDomain(domain, "Domain is an IP address"))
		return probs, nil
	}

	if strings.HasSuffix(domain, ".") {
		probs = append(probs, invalidDomain(domain, "Domain must not end in a dot"))
		return probs, nil
	}

	labels := strings.Split(domain, ".")
	if len(labels) > 10 {
		probs = append(probs, invalidDomain(domain, "Domain has too many dot"))
		return probs, nil
	}
	if len(labels) < 2 {
		probs = append(probs, invalidDomain(domain, "Domain needs at least one dot"))
		return probs, nil
	}

	for _, label := range labels {
		if len(label) < 1 {
			probs = append(probs, invalidDomain(domain, "Domain can not have two dots in a row"))
			return probs, nil
		}
		if len(label) > 63 {
			probs = append(probs, invalidDomain(domain, "Domain has a label (component between dots) longer than 63 bytes"))
			return probs, nil
		}

		if !dnsLabelCharacterRegexp.MatchString(label) {
			probs = append(probs, invalidDomain(domain, "Domain contains an invalid character"))
			return probs, nil
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			probs = append(probs, invalidDomain(domain, "Domain contains an invalid label in a reserved format (R-LDH: '??--')"))
			return probs, nil
		}

		if len(label) >= 4 && label[2:4] == "--" {
			if label[0:2] != "xn" {
				probs = append(probs, invalidDomain(domain, "Domain contains an invalid label in a reserved format (R-LDH: '??--')"))
				return probs, nil
			}

			ulabel, err := idna.ToUnicode(label)
			if err != nil {
				probs = append(probs, invalidDomain(domain, "Domain contains malformed punycode"))
				return probs, nil
			}
			if !norm.NFC.IsNormalString(ulabel) {
				probs = append(probs, invalidDomain(domain, "Domain contains malformed punycode"))
				return probs, nil
			}
		}
	}

	rule := psl.DefaultList.Find(domain, &psl.FindOptions{IgnorePrivate: true, DefaultRule: nil})
	if rule == nil {
		probs = append(probs, invalidDomain(domain, "Domain doesn't end in a public TLD"))
		return probs, nil
	}

	if r := rule.Decompose(domain)[1]; r == "" {
		probs = append(probs, invalidDomain(domain, "Domain is a TLD"))
		return probs, nil
	} else {
		probs = append(probs, debugProblem("PublicSuffix", "The IANA public suffix is the TLD of the Registered Domain",
			fmt.Sprintf("The TLD for %s is: %s", domain, r)))
	}

	return probs, nil
}

// domainExistsChecker ensures that the registered domain actually exists
type domainExistsChecker struct{}

func (c domainExistsChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	var probs []Problem

	domainName, err := psl.Parse(domain)
	if err != nil {
		probs = append(probs, invalidDomain(domain, "Cannot find registered domain via publix suffix list"))
		return probs, nil
	}

	sld := domainName.SLD + "." + domainName.TLD

	soa, err := lookupRaw(sld, dns.TypeSOA)

	if err != nil {
		probs = append(probs, dnsLookupFailed(sld, "SOA", errors.Join(
			errors.New("domain existence could not be verified due to misbehaving nameserver"), err)))
		return probs, nil
	}

	if soa == nil {
		probs = append(probs, dnsLookupFailed(sld, "SOA", errors.New("domain existence problem: No DNS response received")))
		return probs, nil
	}

	if soa.Rcode == dns.RcodeNameError {
		probs = append(probs, invalidDomain(sld, "Domain does not exist in DNS - have you registered this domain name?"))
	}

	return probs, nil
}

// caaChecker ensures that any caa record on the domain, or up the domain tree, allow issuance for letsencrypt.org
type caaChecker struct{}

func (c caaChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	var probs []Problem

	wildcard := false
	if strings.HasPrefix(domain, "*.") {
		wildcard = true
		domain = domain[2:]
	}

	rrs, err := ctx.Lookup(domain, dns.TypeCAA)
	if err != nil {
		probs = append(probs, dnsLookupFailed(domain, "CAA", err))
		return probs, nil
	}

	// check any found caa records
	if len(rrs) > 0 {
		var issue []*dns.CAA
		var issuewild []*dns.CAA
		var criticalUnknown []*dns.CAA

		for _, rr := range rrs {
			caaRr, ok := rr.(*dns.CAA)
			if !ok {
				continue
			}

			switch caaRr.Tag {
			case "issue":
				issue = append(issue, caaRr)
			case "issuewild":
				issuewild = append(issuewild, caaRr)
			case "iodef":
				// iodef records are informational, continue processing
			default:
				if caaRr.Flag == 1 {
					criticalUnknown = append(criticalUnknown, caaRr)
				}
			}
		}

		probs = append(probs, debugProblem("CAA",
			"CAA records control authorization for certificate authorities to issue certificates for a domain",
			collateRecords(append(issue, issuewild...))))

		if len(criticalUnknown) > 0 {
			probs = append(probs, caaCriticalUnknown(domain, wildcard, criticalUnknown))
			return probs, nil
		}

		if len(issue) == 0 && !wildcard {
			return probs, nil
		}

		records := issue
		if wildcard && len(issuewild) > 0 {
			records = issuewild
		}

		for _, r := range records {
			if extractIssuerDomain(r.Value) == "letsencrypt.org" {
				return probs, nil
			}
		}

		probs = append(probs, caaIssuanceNotAllowed(domain, wildcard, records))
		return probs, nil
	}

	// recurse up to the public suffix domain until a caa record is found
	// a.b.c.com -> b.c.com -> c.com until
	if ps, _ := publicsuffix.PublicSuffix(domain); domain != ps && ps != "" {
		splitDomain := strings.SplitN(domain, ".", 2)

		parentProbs, err := c.Check(ctx, splitDomain[1], method)
		if err != nil {
			return nil, fmt.Errorf("error checking caa record on domain: %s, %v", splitDomain[1], err)
		}

		probs = append(probs, parentProbs...)
	}

	return probs, nil
}

func extractIssuerDomain(value string) string {
	// record can be:
	// issuedomain.tld; someparams
	return strings.Trim(strings.SplitN(value, ";", 2)[0], " \t")
}

func collateRecords(records []*dns.CAA) string {
	var s []string
	for _, r := range records {
		s = append(s, r.String())
	}
	return strings.Join(s, "\n")
}

func caaCriticalUnknown(domain string, wildcard bool, records []*dns.CAA) Problem {
	return Problem{
		Name: "CAACriticalUnknown",
		Explanation: fmt.Sprintf(`CAA record(s) exist on %s (wildcard=%t) that are marked as critical but are unknown to Let's Encrypt. `+
			`These record(s) as shown in the detail must be removed, or marked as non-critical, before a certificate can be issued by the Let's Encrypt CA.`, domain, wildcard),
		Detail:   collateRecords(records),
		Severity: SeverityFatal,
	}
}

func caaIssuanceNotAllowed(domain string, wildcard bool, records []*dns.CAA) Problem {
	return Problem{
		Name: "CAAIssuanceNotAllowed",
		Explanation: fmt.Sprintf(`No CAA record on %s (wildcard=%t) contains the issuance domain "letsencrypt.org". `+
			`You must either add an additional record to include "letsencrypt.org" or remove every existing CAA record. `+
			`A list of the CAA records are provided in the details.`, domain, wildcard),
		Detail:   collateRecords(records),
		Severity: SeverityFatal,
	}
}

func invalidDomain(domain, reason string) Problem {
	return Problem{
		Name:        "InvalidDomain",
		Explanation: fmt.Sprintf(`"%s" is not a valid domain name that Let's Encrypt would be able to issue a certificate for.`, domain),
		Detail:      reason,
		Severity:    SeverityFatal,
	}
}

// cloudflareChecker determines if the domain is using cloudflare, and whether a certificate has been provisioned by cloudflare yet.
type cloudflareChecker struct{}

func (c cloudflareChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if method == DNS01 {
		return nil, errNotApplicable
	}

	var probs []Problem

	domain = strings.TrimPrefix(domain, "*.")

	cl := http.Client{
		Timeout:   httpTimeout * time.Second,
		Transport: makeSingleShotHTTPTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Disasble redirects
			return http.ErrUseLastResponse
		},
	}
	resp, err := cl.Get("https://" + domain)
	if err == nil { // no tls error, cert must be issued
		// check if it's cloudflare
		if hasCloudflareHeader(resp.Header) {
			probs = append(probs, cloudflareCDN(domain, method))
		}

		return probs, nil
	}

	// attempt to connect over http with redirects disabled to check cloudflare header
	resp, err = cl.Get("http://" + domain)
	if err != nil {
		return probs, nil
	}

	if hasCloudflareHeader(resp.Header) {
		probs = append(probs, cloudflareCDN(domain, method))
		probs = append(probs, cloudflareSslNotProvisioned(domain))
	}

	return probs, nil
}

func hasCloudflareHeader(h http.Header) bool {
	return strings.Contains(strings.ToLower(h.Get("server")), "cloudflare")
}

func cloudflareCDN(domain string, method ValidationMethod) Problem {
	if method == TLSALPN01 {
		return Problem{
			Name: "CloudflareCDN",
			Explanation: fmt.Sprintf(`The domain %s is being served through Cloudflare CDN, `+
				`which supports the HTTP & HTTPS protocols only. It is impossible to obtain a `+
				`certificate using the TLS-ALPN-01 challenge with the Cloudflare CDN proxy enabled.`, domain),
			Severity: SeverityFatal,
		}

	}
	return Problem{
		Name: "CloudflareCDN",
		Explanation: fmt.Sprintf(`The domain %s is being served through Cloudflare CDN. Any Let's Encrypt certificate installed on the `+
			`origin server will only encrypt traffic between the server and Cloudflare. It is strongly recommended that the SSL option 'Full SSL (strict)' `+
			`be enabled.`, domain),
		Detail:   "https://support.cloudflare.com/hc/en-us/articles/200170416-What-do-the-SSL-options-mean-",
		Severity: SeverityWarning,
	}
}

func cloudflareSslNotProvisioned(domain string) Problem {
	return Problem{
		Name:        "CloudflareSSLNotProvisioned",
		Explanation: fmt.Sprintf(`The domain %s is being served through Cloudflare CDN and a certificate has not yet been provisioned yet by Cloudflare.`, domain),
		Detail:      "https://support.cloudflare.com/hc/en-us/articles/203045244-How-long-does-it-take-for-Cloudflare-s-SSL-to-activate-",
		Severity:    SeverityWarning,
	}
}

// statusioChecker ensures there is no reported operational problem with the Let's Encrypt service via the status.io public api.
type statusioChecker struct{}

// statusioSignificantStatuses denotes which statuses warrant raising a warning.
// 100 (operational) and 200 (undocumented but assume "Planned Maintenance") should not be included.
// https://kb.status.io/developers/status-codes/
var statusioSignificantStatuses = map[int]bool{
	300: true, // Degraded Performance
	400: true, // Partial Service Disruption
	500: true, // Service Disruption
	600: true, // Security Event
}

func (c statusioChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	var probs []Problem

	resp, err := http.Get("https://api.status.io/1.0/status/55957a99e800baa4470002da")
	if err != nil {
		// some connectivity errors with status.io is probably not worth reporting
		return probs, nil
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but don't fail the request
			_ = err // explicitly ignore the error
		}
	}()

	apiResp := struct {
		Result struct {
			StatusOverall struct {
				Updated    time.Time `json:"updated"`
				Status     string    `json:"status"`
				StatusCode int       `json:"status_code"`
			} `json:"status_overall"`
		} `json:"result"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return probs, fmt.Errorf("error decoding status.io api response: %v", err)
	}

	if statusioSignificantStatuses[apiResp.Result.StatusOverall.StatusCode] {
		probs = append(probs, statusioNotOperational(apiResp.Result.StatusOverall.Status, apiResp.Result.StatusOverall.Updated))
	}

	probs = append(probs, debugProblem("StatusIO", "The current status.io status for Let's Encrypt",
		fmt.Sprintf("%v", apiResp.Result.StatusOverall.Status)))

	return probs, nil
}

func statusioNotOperational(status string, updated time.Time) Problem {
	return Problem{
		Name: "StatusNotOperational",
		Explanation: fmt.Sprintf(`The current status as reported by the Let's Encrypt status page is %s as at %v. `+
			`Depending on the reported problem, this may affect certificate issuance. For more information, please visit the status page.`, status, updated),
		Detail:   "https://letsencrypt.status.io/",
		Severity: SeverityWarning,
	}
}

// acmeStagingChecker tries to create an authorization on
// Let's Encrypt's staging server and parse the error urn
// to see if there's anything interesting reported.
type acmeStagingChecker struct {
	client   acme.Client
	account  acme.Account
	clientMu sync.Mutex
}

func ConfigureAcmeClient() acme.OptionFunc {
	return func(client *acme.Client) error {
		// Give the ACME CA more time to complete challenges
		client.PollTimeout = time.Minute * 3
		return nil
	}
}

func (c *acmeStagingChecker) buildAcmeClient() error {
	cl, err := acme.NewClient("https://acme-staging-v02.api.letsencrypt.org/directory", ConfigureAcmeClient())
	if err != nil {
		return err
	}

	regrPath := os.Getenv("LETSDEBUG_ACMESTAGING_ACCOUNTFILE")
	if regrPath == "" {
		regrPath = "acme-account.json"
	}
	buf, err := os.ReadFile(regrPath)
	if err != nil {
		return err
	}

	var out struct {
		PEM string `json:"pem"`
		URL string `json:"url"`
	}
	if err := json.Unmarshal(buf, &out); err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(out.PEM))
	pk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	c.account = acme.Account{PrivateKey: pk, URL: out.URL}
	c.client = cl

	return nil
}

func (c *acmeStagingChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if os.Getenv("LETSDEBUG_DISABLE_ACMESTAGING") != "" {
		return nil, errNotApplicable
	}

	c.clientMu.Lock()
	if c.account.PrivateKey == nil {
		if err := c.buildAcmeClient(); err != nil {
			c.clientMu.Unlock()
			return []Problem{
				internalProblem(fmt.Sprintf("Couldn't setup Let's Encrypt staging checker, skipping: %v", err), SeverityWarning),
			}, nil
		}
	}
	c.clientMu.Unlock()

	probs := []Problem{}

	order, err := c.client.NewOrder(c.account, []acme.Identifier{{Type: "dns", Value: domain}})
	if err != nil {
		if p, _ := translateAcmeError(domain, err); p.Name != "" {
			probs = append(probs, p)
		}
		probs = append(probs, debugProblem("LetsEncryptStaging", "Order creation error", err.Error()))
		return probs, nil
	}

	// A real ACME client would now set up some challenges (by placing files, configuring webservers, talking to DNS).
	// This takes a short while. However, we can technically query the ACME server right away. But, that may cause races
	// within Let's Encrypts code, because our subsequent requests could end up hitting a replica which hasn't synced the
	// new authz URLs yet. So, wait a moment to simulate a real ACME client doing work.
	time.Sleep(3 * time.Second)

	var wg sync.WaitGroup
	wg.Add(len(order.Authorizations))
	var probsMu sync.Mutex

	unhandledError := func(err error) {
		probsMu.Lock()
		defer probsMu.Unlock()

		probs = append(probs, internalProblem("An unknown problem occurred while performing a test "+
			"authorization against the Let's Encrypt staging service: "+err.Error(), SeverityWarning))
	}

	authzFailures := []string{}

	for _, authzURL := range order.Authorizations {
		go func(authzURL string) {
			defer wg.Done()

			authz, err := c.client.FetchAuthorization(c.account, authzURL)
			if err != nil {
				unhandledError(err)
				return
			}

			chal, ok := authz.ChallengeMap[string(method)]
			if !ok {
				unhandledError(fmt.Errorf("missing challenge method (want %v): %v", method, authz.ChallengeMap))
				return
			}

			if _, err := c.client.UpdateChallenge(c.account, chal); err != nil {
				probsMu.Lock()
				if p, _ := translateAcmeError(domain, err); p.Name != "" {
					probs = append(probs, p)
				}
				authzFailures = append(authzFailures, err.Error())
				probsMu.Unlock()
			}
		}(authzURL)
	}

	wg.Wait()

	if len(authzFailures) > 0 {
		probs = append(probs, debugProblem("LetsEncryptStaging",
			fmt.Sprintf("Challenge update failures for %s in order %s", domain, order.URL),
			strings.Join(authzFailures, "\n")))
	} else {
		probs = append(probs, debugProblem("LetsEncryptStaging", "Order for "+domain, order.URL))
	}

	return probs, nil
}

func translateAcmeError(domain string, err error) (problem Problem, stagingBroken bool) {
	var acmeErr acme.Problem
	if errors.As(err, &acmeErr) {
		urn := strings.TrimPrefix(acmeErr.Type, "urn:ietf:params:acme:error:")
		switch urn {
		case "rejectedIdentifier", "unknownHost", "rateLimited", "caa", "dns", "connection":
			// Boulder can send error:dns when _acme-challenge is NXDOMAIN, which is
			// equivalent to unauthorized
			if strings.Contains(acmeErr.Detail, "NXDOMAIN looking up TXT") {
				return Problem{}, false
			}
			return letsencryptProblem(domain, acmeErr.Detail, SeverityError), false
		// When something bad is happening on staging
		case "serverInternal":
			return letsencryptProblem(domain,
				fmt.Sprintf(`There may be internal issues on the staging service: %v`, acmeErr.Detail), SeverityWarning), true
		// Unauthorized is what we expect, except for these exceptions that we should handle:
		// - When VA OR RA is checking Google Safe Browsing (groan)
		case "unauthorized":
			if strings.Contains(acmeErr.Detail, "considered an unsafe domain") {
				return letsencryptProblem(domain, acmeErr.Detail, SeverityError), false
			}
			return Problem{}, false
		default:
			return Problem{}, false
		}
	}
	return internalProblem(fmt.Sprintf("An unknown issue occurred when performing a test authorization "+
		"against the Let's Encrypt staging service: %v", err), SeverityWarning), true
}

func letsencryptProblem(domain, detail string, severity SeverityLevel) Problem {
	return Problem{
		Name: "IssueFromLetsEncrypt",
		Explanation: fmt.Sprintf(`A test authorization for %s to the Let's Encrypt staging service has revealed `+
			`issues that may prevent any certificate for this domain being issued.`, domain),
		Detail:   detail,
		Severity: severity,
	}
}

// ofacSanctionChecker checks whether a Registered Domain is present on the the XML sanctions list
// (https://www.treasury.gov/ofac/downloads/sdn.xml).
// It is disabled by default, and must be enabled with the environment variable LETSDEBUG_ENABLE_OFAC=1
type ofacSanctionChecker struct {
	muRefresh sync.RWMutex
	domains   map[string]struct{}
}

func (c *ofacSanctionChecker) Check(ctx *scanContext, domain string, method ValidationMethod) ([]Problem, error) {
	if os.Getenv("LETSDEBUG_ENABLE_OFAC") != "1" {
		return nil, errNotApplicable
	}
	c.muRefresh.RLock()
	defer c.muRefresh.RUnlock()

	rd, _ := publicsuffix.EffectiveTLDPlusOne(domain)
	for sanctionedRD := range c.domains {
		if rd != sanctionedRD {
			continue
		}

		return []Problem{{
			Name: "SanctionedDomain",
			Explanation: fmt.Sprintf("The Registered Domain %s was found on the United States' OFAC "+
				"Specially Designated Nationals and Blocked Persons (SDN) List. Let's Encrypt are unable to issue certificates "+
				"for sanctioned entities. Search on https://sanctionssearch.ofac.treas.gov/ for futher details.", sanctionedRD),
			Severity: SeverityError,
		}}, nil
	}

	return nil, nil
}

func (c *ofacSanctionChecker) setup() {
	if os.Getenv("LETSDEBUG_ENABLE_OFAC") != "1" {
		return
	}
	c.domains = map[string]struct{}{}
	go func() {
		for {
			if err := c.poll(); err != nil {
				fmt.Printf("OFAC SDN poller failed: %v\n", err)
			}
			time.Sleep(24 * time.Hour)
		}
	}()
}

func (c *ofacSanctionChecker) poll() error {
	req, _ := http.NewRequest(http.MethodGet, "https://www.treasury.gov/ofac/downloads/sdn.xml", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	req.Header.Set("User-Agent", "Let's Debug (https://letsdebug.net)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but don't fail the request
			_ = err // explicitly ignore the error
		}
	}()

	dec := xml.NewDecoder(resp.Body)

	registeredDomains := map[string]struct{}{}
	isID := false
	for {
		tok, _ := dec.Token()
		if tok == nil {
			break
		}

		switch el := tok.(type) {
		case xml.StartElement:
			if el.Name.Local == "id" {
				isID = true
				break
			}
			if el.Name.Local == "idType" {
				next, _ := dec.Token()
				if next == nil {
					break
				}
				raw, ok := next.(xml.CharData)
				if !ok {
					break
				}
				if string(raw) != "Website" {
					isID = false
					break
				}
				break
			}
			if el.Name.Local == "idNumber" && isID {
				next, _ := dec.Token()
				if next == nil {
					break
				}
				raw, ok := next.(xml.CharData)
				if !ok {
					break
				}
				if rd := c.extractRegisteredDomain(string(raw)); rd != "" {
					registeredDomains[rd] = struct{}{}
				}
			}
		case xml.EndElement:
			if el.Name.Local == "id" {
				isID = false
				break
			}
		}
	}

	c.muRefresh.Lock()
	defer c.muRefresh.Unlock()

	c.domains = registeredDomains

	return nil
}

func (c *ofacSanctionChecker) extractRegisteredDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	if len(d) == 0 {
		return ""
	}
	// If there's a protocol or path, then we need to parse the URL and extract the host
	if strings.Contains(d, "/") {
		u, err := url.Parse(d)
		if err != nil {
			return ""
		}
		d = u.Host
	}
	d, _ = publicsuffix.EffectiveTLDPlusOne(d)
	return d
}
