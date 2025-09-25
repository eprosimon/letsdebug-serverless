package letsdebug

import (
	"testing"
)

func TestCoreDebugFunctionality(t *testing.T) {
	testCases := []struct {
		name             string
		domain           string
		method           ValidationMethod
		expectedProbs    []string // Problem names we expect to see
		notExpectedProbs []string // Problem names we should not see
	}{
		{
			name:   "Invalid domain",
			domain: "not-a-valid-domain",
			method: HTTP01,
			expectedProbs: []string{
				"InvalidDomain",
			},
		},
		{
			name:   "Wildcard with HTTP validation",
			domain: "*.vercel-ns.testing.thesimons.email",
			method: HTTP01,
			expectedProbs: []string{
				"MethodNotSuitable",
			},
		},
		{
			name:   "Valid domain wrong method",
			domain: "example.com",
			method: "invalid-method",
			expectedProbs: []string{
				"InvalidMethod",
			},
		},
		{
			name:   "Reserved IP address",
			domain: "reserved.testing.thesimons.email",
			method: HTTP01,
			expectedProbs: []string{
				"ReservedAddress",
			},
		},
		{
			name:   "Valid domain DNS01",
			domain: "example.com",
			method: DNS01,
			notExpectedProbs: []string{
				"StatusNotOperational",
				"SanctionedDomain",
			},
		},
	}

	for _, tc := range testCases {
		tc := tc // Capture range variable to avoid data race in parallel tests
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			probs, err := Check(tc.domain, tc.method)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Check for expected problems
			for _, expected := range tc.expectedProbs {
				found := false
				for _, prob := range probs {
					if prob.Name == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected to find problem %q but didn't. Got problems: %v",
						expected, problemNames(probs))
				}
			}

			// Check that unexpected problems aren't present
			for _, notExpected := range tc.notExpectedProbs {
				for _, prob := range probs {
					if prob.Name == notExpected {
						t.Errorf("found unexpected problem %q", notExpected)
					}
				}
			}
		})
	}
}

// Helper function to extract problem names for better error messages
func problemNames(probs []Problem) []string {
	var names []string
	for _, p := range probs {
		names = append(names, p.Name)
	}
	return names
}
