package netcupapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const defaultAPIBase = "https://www.servercontrolpanel.de/scp-core/api/v1"

type Client struct {
	refreshToken string
	accessToken  string
	baseURL      string
	http         *http.Client

	mu          sync.Mutex
	cachedToken string
	tokenExpiry time.Time
}

func NewClient(refreshToken, accessToken, baseURL string) *Client {
	if baseURL == "" {
		baseURL = defaultAPIBase
	}
	return &Client{
		refreshToken: strings.TrimSpace(refreshToken),
		accessToken:  strings.TrimSpace(accessToken),
		baseURL:      strings.TrimRight(baseURL, "/"),
		http:         &http.Client{Timeout: 60 * time.Second},
	}
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Status  int
	Body    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		if e.Code != "" {
			return fmt.Sprintf("%s: %s", e.Code, e.Message)
		}
		return e.Message
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, truncate(e.Body, 256))
}

func (c *Client) bearer() (string, error) {
	if c.accessToken != "" {
		return c.accessToken, nil
	}
	if c.refreshToken == "" {
		return "", fmt.Errorf("需要 refresh_token 或 access_token")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.cachedToken, nil
	}
	token, err := refreshAccessToken(c.refreshToken)
	if err != nil {
		return "", err
	}
	c.cachedToken = token
	c.tokenExpiry = time.Now().Add(4 * time.Minute)
	return token, nil
}

func (c *Client) CurrentUserID() (int, error) {
	token, err := c.bearer()
	if err != nil {
		return 0, err
	}
	return fetchCurrentUserID(token)
}

func (c *Client) Do(method, path string, body any, out any) error {
	token, err := c.bearer()
	if err != nil {
		return err
	}

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}

	url := c.baseURL + path
	if !strings.HasPrefix(path, "/") {
		url = c.baseURL + "/" + path
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
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
