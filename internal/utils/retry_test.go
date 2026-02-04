package utils

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetry_RetriesUntilDone(t *testing.T) {
	ctx := context.Background()
	count := 0

	opts := RetryOptions{
		Attempts:  5,
		BaseDelay: 1 * time.Millisecond,
		MaxDelay:  1 * time.Millisecond,
		Sleep:     func(time.Duration) {},
	}

	val, err := Retry[int](ctx, opts, func(context.Context) (int, bool, error) {
		count++
		if count < 3 {
			return 0, true, nil
		}
		return 42, false, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != 42 {
		t.Fatalf("expected 42, got %d", val)
	}
	if count != 3 {
		t.Fatalf("expected 3 attempts, got %d", count)
	}
}

func TestRetry_ExhaustionReturnsError(t *testing.T) {
	ctx := context.Background()
	count := 0

	opts := RetryOptions{
		Attempts:  3,
		BaseDelay: 1 * time.Millisecond,
		MaxDelay:  1 * time.Millisecond,
		Sleep:     func(time.Duration) {},
		ExceededError: func(attempts int, lastErr error) error {
			return errors.New("exhausted")
		},
	}

	_, err := Retry[string](ctx, opts, func(context.Context) (string, bool, error) {
		count++
		return "", true, nil
	})

	if err == nil || err.Error() != "exhausted" {
		t.Fatalf("expected exhaustion error, got %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 attempts, got %d", count)
	}
}
