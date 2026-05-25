package aliyunapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const apiVersion = "2020-06-01"

type Client struct {
	AccessKeyID     string
	AccessKeySecret string
	Region          string
	Endpoint        string
	HTTP            *http.Client
}

func NewClient(accessKeyID, accessKeySecret, region, endpoint string) *Client {
	if endpoint == "" {
		endpoint = "https://swas." + region + ".aliyuncs.com"
	}
	if !strings.HasPrefix(endpoint, "http") {
		endpoint = "https://" + endpoint
	}
	return &Client{
		AccessKeyID:     accessKeyID,
		AccessKeySecret: accessKeySecret,
		Region:          region,
		Endpoint:        strings.TrimRight(endpoint, "/"),
		HTTP:            &http.Client{Timeout: 30 * time.Second},
	}
}

type APIError struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (c *Client) Do(action string, params map[string]string) (map[string]any, error) {
	if params == nil {
		params = make(map[string]string)
	}
	params["Action"] = action
	params["Version"] = apiVersion
	params["Format"] = "JSON"
	params["RegionId"] = c.Region
	params["AccessKeyId"] = c.AccessKeyID
	params["SignatureMethod"] = "HMAC-SHA1"
	params["SignatureVersion"] = "1.0"
	params["SignatureNonce"] = randomNonce()
	params["Timestamp"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")

	signature, err := signRPC(params, c.AccessKeySecret)
	if err != nil {
		return nil, err
	}
	params["Signature"] = signature

	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}

	req, err := http.NewRequest(http.MethodPost, c.Endpoint+"/", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w, body=%s", err, truncate(string(body), 512))
	}

	if code, _ := parsed["Code"].(string); code != "" {
		msg, _ := parsed["Message"].(string)
		return nil, &APIError{Code: code, Message: msg}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 512))
	}
	return parsed, nil
}

func signRPC(params map[string]string, secret string) (string, error) {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k != "Signature" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var canonical strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonical.WriteByte('&')
		}
		canonical.WriteString(percentEncode(k))
		canonical.WriteByte('=')
		canonical.WriteString(percentEncode(params[k]))
	}

	stringToSign := "POST&" + percentEncode("/") + "&" + percentEncode(canonical.String())
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func percentEncode(s string) string {
	enc := url.QueryEscape(s)
	enc = strings.ReplaceAll(enc, "+", "%20")
	enc = strings.ReplaceAll(enc, "*", "%2A")
	enc = strings.ReplaceAll(enc, "%7E", "~")
	return enc
}

func randomNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
