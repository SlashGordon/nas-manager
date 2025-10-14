package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client wraps http.Client with convenience methods
type Client struct {
	*http.Client
}

// DefaultClient with 30s timeout
var DefaultClient = NewClient(30 * time.Second)

// NewClient creates a new HTTP client with default timeout
func NewClient(timeout time.Duration) *Client {
	return &Client{
		Client: &http.Client{
			Timeout: timeout,
		},
	}
}

// GetScanner performs a GET request using the default client
func GetScanner(ctx context.Context, url string) (*bufio.Scanner, func(), error) {
	return DefaultClient.GetScanner(ctx, url)
}

// Get performs a GET request and returns the response
func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// GetBody performs a GET request and returns the response body as io.ReadCloser
func (c *Client) GetBody(ctx context.Context, url string) (io.ReadCloser, error) {
	resp, err := c.Get(ctx, url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, &Error{StatusCode: resp.StatusCode, URL: url}
	}
	return resp.Body, nil
}

// GetScanner performs a GET request and returns a scanner for line-by-line reading
func (c *Client) GetScanner(ctx context.Context, url string) (*bufio.Scanner, func(), error) {
	body, err := c.GetBody(ctx, url)
	if err != nil {
		return nil, nil, err
	}
	return bufio.NewScanner(body), func() { body.Close() }, nil
}

// Error represents an HTTP error
type Error struct {
	StatusCode int
	URL        string
}

func (e *Error) Error() string {
	return fmt.Sprintf("HTTP %d for %s", e.StatusCode, e.URL)
}
