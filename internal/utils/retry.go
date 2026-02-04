package utils

import (
	"context"
	"fmt"
	"time"
)

type RetryOptions struct {
	Attempts  int
	BaseDelay time.Duration
	MaxDelay  time.Duration

	// Sleep defaults to time.Sleep. Useful for tests.
	Sleep func(time.Duration)

	// OnRetry is called before sleeping between attempts.
	// attempt is 1-based (i.e., the first retry is attempt=1).
	OnRetry func(attempt int, nextDelay time.Duration, lastErr error)

	// ExceededError allows customizing the error when retries are exhausted.
	ExceededError func(attempts int, lastErr error) error
}

func (o RetryOptions) withDefaults() RetryOptions {
	if o.Attempts <= 0 {
		o.Attempts = 1
	}
	if o.BaseDelay <= 0 {
		o.BaseDelay = 1 * time.Second
	}
	if o.MaxDelay <= 0 {
		o.MaxDelay = 8 * time.Second
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	if o.ExceededError == nil {
		o.ExceededError = func(attempts int, lastErr error) error {
			if lastErr != nil {
				return fmt.Errorf("retries exhausted after %d attempt(s): %w", attempts, lastErr)
			}
			return fmt.Errorf("retries exhausted after %d attempt(s)", attempts)
		}
	}
	return o
}

// Retry calls fn up to opts.Attempts times.
//
// fn should return:
//   - value: the latest value
//   - retry: whether to try again
//   - err: an error to return if retry is false, or the last error seen
//
// If retry is true and attempts are exhausted, Retry returns opts.ExceededError.
func Retry[T any](ctx context.Context, opts RetryOptions, fn func(context.Context) (value T, retry bool, err error)) (T, error) {
	opts = opts.withDefaults()

	var lastValue T
	var lastErr error

	for i := 0; i < opts.Attempts; i++ {
		value, retry, err := fn(ctx)
		lastValue = value
		lastErr = err

		if !retry {
			return value, err
		}
		if i == opts.Attempts-1 {
			return lastValue, opts.ExceededError(opts.Attempts, lastErr)
		}

		delay := opts.BaseDelay << i
		if delay > opts.MaxDelay {
			delay = opts.MaxDelay
		}

		if opts.OnRetry != nil {
			opts.OnRetry(i+1, delay, lastErr)
		}
		opts.Sleep(delay)

		select {
		case <-ctx.Done():
			return lastValue, ctx.Err()
		default:
		}
	}

	return lastValue, opts.ExceededError(opts.Attempts, lastErr)
}
