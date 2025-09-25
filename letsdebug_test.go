package letsdebug

import "testing"

func TestCheck(t *testing.T) {
	// Save original checkers
	originalCheckers := checkers

	// check success condition
	checkers = []checker{
		checkerSucceedWithProblem{},
		checkerSucceedWithProblem{},
		checkerSucceedEmpty{},
	}
	probs, err := Check("", "")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(probs) != 2 {
		t.Fatalf("expected 2 problems, got: %d", len(probs))
	}

	// check fail condition
	checkers = []checker{
		checkerFail{},
	}
	if _, err := Check("", ""); err == nil {
		t.Fatal("expected error, got none")
	}

	// check panic recovery
	checkers = []checker{
		checkerPanic{},
	}
	if _, err := Check("", ""); err == nil {
		t.Fatal("expected error, got none")
	}

	// Restore original checkers
	checkers = originalCheckers
}
