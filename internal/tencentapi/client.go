package tencentapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	SecretID  string
	SecretKey string
	Region    string
	Service   string
	Host      string
	Version   string
	HTTP      *http.Client
}

func NewClient(secretID, secretKey, region, service, host, version string) *Client {
	return &Client{
		SecretID:  secretID,
		SecretKey: secretKey,
		Region:    region,
		Service:   service,
		Host:      host,
		Version:   version,
		HTTP:      &http.Client{Timeout: 30 * time.Second},
	}
}

type APIError struct {
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

type responseEnvelope struct {
	Response struct {
		Error *APIError `json:"Error"`
	} `json:"Response"`
}

func (c *Client) Do(action string, payload any) error {
	return c.DoInto(action, payload, nil)
}

// DoInto 发起 API 请求；out 非 nil 时将整个响应 JSON 反序列化到 out。
func (c *Client) DoInto(action string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	ts := time.Now().Unix()
	auth, err := c.sign(action, string(body), ts)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, "https://"+c.Host, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", c.Host)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", c.Version)
	req.Header.Set("X-TC-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-TC-Region", c.Region)
	req.Header.Set("Authorization", auth)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}

	var envelope responseEnvelope
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return fmt.Errorf("解析响应失败: %w, body=%s", err, truncate(string(respBody), 512))
	}
	if envelope.Response.Error != nil {
		return envelope.Response.Error
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 512))
	}
	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("解析响应失败: %w, body=%s", err, truncate(string(respBody), 512))
		}
	}
	return nil
}

func (c *Client) sign(action, payload string, timestamp int64) (string, error) {
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	credentialScope := date + "/" + c.Service + "/tc3_request"

	hashedPayload := sha256Hex(payload)
	canonicalHeaders := "content-type:application/json; charset=utf-8\n" +
		"host:" + c.Host + "\n"
	signedHeaders := "content-type;host"
	canonicalRequest := strings.Join([]string{
		"POST",
		"/",
		"",
		canonicalHeaders,
		signedHeaders,
		hashedPayload,
	}, "\n")

	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256",
		fmt.Sprintf("%d", timestamp),
		credentialScope,
		sha256Hex(canonicalRequest),
	}, "\n")

	secretDate := hmacSHA256([]byte("TC3"+c.SecretKey), date)
	secretService := hmacSHA256(secretDate, c.Service)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	return fmt.Sprintf(
		"TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.SecretID, credentialScope, signedHeaders, signature,
	), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
