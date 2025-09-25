package letsdebug

import (
	"strings"
	"testing"
)

func TestSkipDomainValidation(t *testing.T) {
	// Test with a valid domain
	domain := "example.com"
	method := HTTP01

	var problemsWithoutSkip []Problem
	var problemsWithSkip []Problem

	// Test without skipping domain validation (should run all checkers)
	t.Run("WithoutSkipDomainValidation", func(t *testing.T) {
		opts := Options{
			SkipDomainValidation: false,
		}

		problems, err := CheckWithOptions(domain, method, opts)
		if err != nil {
			t.Fatalf("CheckWithOptions failed: %v", err)
		}

		// Store problems for comparison
		problemsWithoutSkip = problems
		t.Logf("Without skip: Found %d problems", len(problems))
	})

	// Test with skipping domain validation (should skip first asyncCheckerBlock)
	t.Run("WithSkipDomainValidation", func(t *testing.T) {
		opts := Options{
			SkipDomainValidation: true,
		}

		problems, err := CheckWithOptions(domain, method, opts)
		if err != nil {
			t.Fatalf("CheckWithOptions failed: %v", err)
		}

		// Store problems for comparison
		problemsWithSkip = problems
		t.Logf("With skip: Found %d problems", len(problems))
	})

	// Assert that skipping domain validation results in fewer problems
	if len(problemsWithSkip) >= len(problemsWithoutSkip) {
		t.Errorf("Expected fewer problems when skipping domain validation, got %d (with skip) >= %d (without skip)",
			len(problemsWithSkip), len(problemsWithoutSkip))
	}

	// Assert that no domain validation problems are present when skipping
	for _, problem := range problemsWithSkip {
		if problem.Name == "InvalidDomain" {
			t.Errorf("Found domain validation problem when SkipDomainValidation=true: %s - %s",
				problem.Name, problem.Explanation)
		}
		// Check for specific domain validation problems from validDomainChecker
		// These are the specific problems that should be skipped
		if problem.Name == "InvalidDomain" ||
			(strings.Contains(strings.ToLower(problem.Explanation), "not a valid domain name") &&
				strings.Contains(strings.ToLower(problem.Explanation), "let's encrypt")) {
			t.Errorf("Found domain validation problem when SkipDomainValidation=true: %s - %s",
				problem.Name, problem.Explanation)
		}
	}
}

func TestGetCheckersForOptions(t *testing.T) {
	// Test that getCheckersForOptions returns different results based on SkipDomainValidation
	t.Run("WithoutSkipDomainValidation", func(t *testing.T) {
		opts := Options{
			SkipDomainValidation: false,
		}

		checkers := getCheckersForOptions(opts)
		// Should return all original checkers (3 asyncCheckerBlocks)
		expectedCount := 3
		if len(checkers) != expectedCount {
			t.Errorf("Expected %d checkers, got %d", expectedCount, len(checkers))
		}
	})

	t.Run("WithSkipDomainValidation", func(t *testing.T) {
		opts := Options{
			SkipDomainValidation: true,
		}

		checkers := getCheckersForOptions(opts)
		// Should have one fewer checker (the first asyncCheckerBlock is skipped)
		expectedCount := 2
		if len(checkers) != expectedCount {
			t.Errorf("Expected %d checkers (one less than original), got %d", expectedCount, len(checkers))
		}
	})
}
