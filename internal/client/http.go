package client

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultTimeout = 15 * time.Second

// HTTPClient wraps the shared transport configuration.
type HTTPClient struct {
	baseURL *url.URL
	client  *http.Client
}

// NewHTTPClient creates a simple HTTP client for switch communication.
func NewHTTPClient(host string, timeoutSeconds int64) (*HTTPClient, error) {
	normalizedHost := strings.TrimSpace(host)
	if normalizedHost == "" {
		return nil, fmt.Errorf("host must not be empty")
	}
	if !strings.HasPrefix(normalizedHost, "http://") && !strings.HasPrefix(normalizedHost, "https://") {
		normalizedHost = "http://" + normalizedHost
	}

	baseURL, err := url.Parse(normalizedHost)
	if err != nil {
		return nil, fmt.Errorf("parse host: %w", err)
	}

	timeout := defaultTimeout
	if timeoutSeconds > 0 {
		timeout = time.Duration(timeoutSeconds) * time.Second
	}

	return &HTTPClient{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// NewRequest builds a request against the switch base URL.
func (c *HTTPClient) NewRequest(ctx context.Context, method, endpoint string) (*http.Request, error) {
	requestURL, err := c.baseURL.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint %q: %w", endpoint, err)
	}

	req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	return req, nil
}

// Do executes the request.
func (c *HTTPClient) Do(req *http.Request) (*http.Response, error) {
	return c.client.Do(req)
}
