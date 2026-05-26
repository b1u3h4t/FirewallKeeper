package hetznerrobot

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultBaseURL = "https://robot-ws.your-server.de"

type Client struct {
	User     string
	Password string
	BaseURL  string
	HTTP     *http.Client
}

func NewClient(user, password, baseURL string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Client{
		User:     user,
		Password: password,
		BaseURL:  strings.TrimRight(baseURL, "/"),
		HTTP:     &http.Client{Timeout: 60 * time.Second},
	}
}

type APIError struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
	HTTP    int
	Body    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("HTTP %d: %s", e.HTTP, truncate(e.Body, 256))
}

type errorEnvelope struct {
	Error APIError `json:"error"`
}

func (c *Client) Do(method, path string, form url.Values, out any) error {
	var bodyReader io.Reader
	if form != nil {
		bodyReader = strings.NewReader(form.Encode())
	}

	reqURL := c.BaseURL + path
	req, err := http.NewRequest(method, reqURL, bodyReader)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.User, c.Password)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
		var env errorEnvelope
		_ = json.Unmarshal(respBody, &env)
		apiErr := env.Error
		apiErr.HTTP = resp.StatusCode
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
