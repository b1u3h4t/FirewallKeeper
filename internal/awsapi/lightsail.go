package awsapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const lightsailTargetPrefix = "Lightsail_20161128."

type PortInfo struct {
	FromPort int      `json:"fromPort"`
	ToPort   int      `json:"toPort"`
	Protocol string   `json:"protocol"`
	CIDRs    []string `json:"cidrs,omitempty"`
}

type InstancePortState struct {
	FromPort int      `json:"fromPort"`
	ToPort   int      `json:"toPort"`
	Protocol string   `json:"protocol"`
	CIDRs    []string `json:"cidrs"`
	State    string   `json:"state"`
}

type LightsailClient struct {
	accessKey    string
	secretKey    string
	region       string
	host         string
	http         *http.Client
}

func NewLightsail(accessKey, secretKey, region string) *LightsailClient {
	region = strings.TrimSpace(region)
	if region == "" {
		region = "us-east-1"
	}
	return &LightsailClient{
		accessKey: accessKey,
		secretKey: secretKey,
		region:    region,
		host:      "lightsail." + region + ".amazonaws.com",
		http:      &http.Client{Timeout: 30 * time.Second},
	}
}

type APIError struct {
	Code    string `json:"__type"`
	Message string `json:"message"`
	Status  int
	Body    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, truncate(e.Body, 256))
}

func (c *LightsailClient) invoke(target string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, "https://"+c.host+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Host = c.host
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", lightsailTargetPrefix+target)

	if err := signRequest(req, c.accessKey, c.secretKey, c.region, "lightsail", body); err != nil {
		return err
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
			return fmt.Errorf("解析响应失败: %w", err)
		}
	}
	return nil
}

func (c *LightsailClient) GetPortStates(instanceName string) ([]InstancePortState, error) {
	var resp struct {
		PortStates []InstancePortState `json:"portStates"`
	}
	err := c.invoke("GetInstancePortStates", map[string]string{
		"instanceName": instanceName,
	}, &resp)
	return resp.PortStates, err
}

func (c *LightsailClient) OpenPort(instanceName string, info PortInfo) error {
	return c.invoke("OpenInstancePublicPorts", map[string]any{
		"instanceName": instanceName,
		"portInfo":     info,
	}, &struct{}{})
}

func (c *LightsailClient) ClosePort(instanceName string, info PortInfo) error {
	return c.invoke("CloseInstancePublicPorts", map[string]any{
		"instanceName": instanceName,
		"portInfo":     info,
	}, &struct{}{})
}

func (c *LightsailClient) PortExists(states []InstancePortState, proto string, port int, cidr string) bool {
	proto = normalizeProtocol(proto)
	for _, s := range states {
		if !strings.EqualFold(s.Protocol, proto) {
			continue
		}
		if s.FromPort != port || s.ToPort != port {
			continue
		}
		for _, ip := range s.CIDRs {
			if normalizeCIDR(ip) == normalizeCIDR(cidr) {
				return true
			}
		}
	}
	return false
}

func ParsePort(port string) (int, error) {
	port = strings.TrimSpace(port)
	if port == "" {
		return 0, fmt.Errorf("empty port")
	}
	if strings.Contains(port, "-") {
		parts := strings.SplitN(port, "-", 2)
		return strconv.Atoi(strings.TrimSpace(parts[0]))
	}
	return strconv.Atoi(port)
}

func normalizeProtocol(p string) string {
	return strings.ToLower(strings.TrimSpace(p))
}

func normalizeCIDR(s string) string {
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
