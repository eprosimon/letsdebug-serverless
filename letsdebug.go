// Package letsdebug provides an library, web API and CLI to provide diagnostic
// information for why a particular (FQDN, ACME Validation Method) pair *may* fail
// when attempting to issue an SSL Certificate from Let's Encrypt (https://letsencrypt.org).
//
// The usage cannot be generalized to other ACME providers, as the policies checked by this package
// are specific to Let's Encrypt, rather than being mandated by the ACME protocol.
//
// This package relies on libunbound.
package letsdebug

import (
	"fmt"
	"os"
	"reflect"
	"time"
)

// Options provide additional configuration to the various checkers
type Options struct {
	// HTTPRequestPath alters the /.well-known/acme-challenge/letsdebug-test to
	// /acme-challenge/acme-challenge/{{ HTTPRequestPath }}
	HTTPRequestPath string
	// HTTPExpectResponse causes the HTTP checker to require the remote server to
	// respond with specific content. If the content does not match, then the test
	// will fail with severity Error.
	HTTPExpectResponse string
	// SkipDomainValidation skips the validDomainChecker when the domain has already
	// been validated by the caller (e.g., domain_assist package)
	SkipDomainValidation bool
}

// Check calls CheckWithOptions with default options
func Check(domain string, method ValidationMethod) (probs []Problem, retErr error) {
	return CheckWithOptions(domain, method, Options{})
}

// CheckWithOptions will run each checker against the domain and validation method provided.
// It is expected that this method may take a long time to execute, and may not be cancelled.
func CheckWithOptions(domain string, method ValidationMethod, opts Options) (probs []Problem, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("panic: %v", r)
		}
	}()

	ctx := newScanContext()
	if opts.HTTPRequestPath != "" {
		ctx.httpRequestPath = opts.HTTPRequestPath
	}
	if opts.HTTPExpectResponse != "" {
		ctx.httpExpectResponse = opts.HTTPExpectResponse
	}

	domain = normalizeFqdn(domain)

	// Get the appropriate checkers based on options
	checkersToRun := getCheckersForOptions(opts)

	for _, checker := range checkersToRun {
		t := reflect.TypeOf(checker)
		debug("[*] + %v\n", t)
		start := time.Now()
		checkerProbs, err := checker.Check(ctx, domain, method)
		debug("[*] - %v in %v\n", t, time.Since(start))
		if err == nil {
			if len(checkerProbs) > 0 {
				probs = append(probs, checkerProbs...)
			}
			// dont continue checking when a fatal error occurs
			if hasFatalProblem(probs) {
				break
			}
		} else if err != errNotApplicable {
			return nil, err
		}
	}
	return probs, nil
}

// containsValidDomainChecker checks if a checker contains validDomainChecker
func containsValidDomainChecker(c checker) bool {
	// Use reflection to check if this is an asyncCheckerBlock
	if block, ok := c.(asyncCheckerBlock); ok {
		// Check each checker in the block
		for _, subChecker := range block {
			// Use reflection to get the type name and check if it's validDomainChecker
			checkerType := reflect.TypeOf(subChecker)
			if checkerType != nil && checkerType.Name() == "validDomainChecker" {
				return true
			}
		}
	}
	return false
}

// getCheckersForOptions returns the appropriate checkers based on the provided options
func getCheckersForOptions(opts Options) []checker {
	if !opts.SkipDomainValidation {
		// Return all checkers if domain validation is not skipped
		return checkers
	}

	// When skipping domain validation, skip checkers that contain validDomainChecker
	// and other validation-related checkers that are redundant when the domain is already validated
	var modifiedCheckers []checker

	for _, checker := range checkers {
		// Skip checkers that contain validDomainChecker
		if containsValidDomainChecker(checker) {
			debug("[*] Skipping checker containing validDomainChecker\n")
			continue
		}
		// Keep all other checkers
		modifiedCheckers = append(modifiedCheckers, checker)
	}

	return modifiedCheckers
}

var isDebug *bool

func debug(format string, args ...interface{}) {
	if isDebug == nil {
		d := os.Getenv("LETSDEBUG_DEBUG") != ""
		isDebug = &d
	}
	if !(*isDebug) {
		return
	}
	fmt.Fprintf(os.Stderr, format, args...)
}
