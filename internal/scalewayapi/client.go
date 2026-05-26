package scalewayapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.scaleway.com"

type Client struct {
	SecretKey string
	BaseURL   string
	HTTP      *http.Client
}

func NewClient(secretKey string) *Client {
	return &Client{
		SecretKey: secretKey,
		BaseURL:   defaultBaseURL,
		HTTP:      &http.Client{Timeout: 30 * time.Second},
	}
}

type APIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Status  int
	Body    string
}

func (e *APIError) Error() string {
	if e.Type != "" {
		return fmt.Sprintf("%s: %s", e.Type, e.Message)
	}
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, truncate(e.Body, 256))
}

func (c *Client) Do(method, path string, body any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}

	url := strings.TrimRight(c.BaseURL, "/") + path
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("X-Auth-Token", c.SecretKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr APIError
		_ = json.Unmarshal(respBody, &apiErr)
		apiErr.Status = resp.StatusCode
		apiErr.Body = string(respBody)
		if apiErr.Message == "" {
			apiErr.Message = truncate(string(respBody), 512)
		}
		return &apiErr
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("解析响应失败: %w, body=%s", err, truncate(string(respBody), 512))
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
