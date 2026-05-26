package volcapi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://open.volcengineapi.com"
	vpcVersion     = "2020-04-01"
	vpcService     = "vpc"
)

type Client struct {
	AccessKeyID     string
	AccessKeySecret string
	Region          string
	BaseURL         string
	Service         string
	HTTP            *http.Client
}

func NewVPCClient(accessKeyID, accessKeySecret, region, endpoint string) *Client {
	if endpoint == "" {
		endpoint = defaultBaseURL
	}
	if region == "" {
		region = "cn-beijing"
	}
	return &Client{
		AccessKeyID:     accessKeyID,
		AccessKeySecret: accessKeySecret,
		Region:          region,
		BaseURL:         strings.TrimRight(endpoint, "/"),
		Service:         vpcService,
		HTTP:            &http.Client{Timeout: 30 * time.Second},
	}
}

type APIError struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
	Status  int
	Body    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, truncate(e.Body, 256))
}

type errorEnvelope struct {
	ResponseMetadata struct {
		Error *APIError `json:"Error"`
	} `json:"ResponseMetadata"`
}

func (c *Client) Do(action string, params map[string]string) (map[string]any, error) {
	if params == nil {
		params = make(map[string]string)
	}
	params["Action"] = action
	params["Version"] = vpcVersion

	query := url.Values{}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		query.Set(k, params[k])
	}

	body := []byte{}
	reqURL := c.BaseURL + "/?" + strings.Replace(query.Encode(), "+", "%20", -1)
	req, err := http.NewRequest(http.MethodGet, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	if err := signRequest(req, c.AccessKeyID, c.AccessKeySecret, c.Region, c.Service, body); err != nil {
		return nil, err
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var parsed map[string]any
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w, body=%s", err, truncate(string(respBody), 512))
	}

	var env errorEnvelope
	_ = json.Unmarshal(respBody, &env)
	if env.ResponseMetadata.Error != nil {
		apiErr := *env.ResponseMetadata.Error
		apiErr.Status = resp.StatusCode
		apiErr.Body = string(respBody)
		return nil, &apiErr
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			Status:  resp.StatusCode,
			Message: truncate(string(respBody), 512),
			Body:    string(respBody),
		}
	}
	return parsed, nil
}

func signRequest(req *http.Request, accessKey, secretKey, region, service string, body []byte) error {
	now := time.Now().UTC()
	date := now.Format("20060102T150405Z")
	authDate := date[:8]

	req.Header.Set("X-Date", date)
	payloadHash := sha256Hex(body)
	req.Header.Set("X-Content-Sha256", payloadHash)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	queryString := strings.Replace(req.URL.RawQuery, "+", "%20", -1)
	signedHeaders := []string{"content-type", "host", "x-content-sha256", "x-date"}
	var headerList []string
	for _, h := range signedHeaders {
		var v string
		switch h {
		case "host":
			v = req.Host
		default:
			v = strings.TrimSpace(req.Header.Get(http.CanonicalHeaderKey(h)))
		}
		headerList = append(headerList, h+":"+v)
	}
	headerString := strings.Join(headerList, "\n")

	canonicalString := strings.Join([]string{
		req.Method,
		"/",
		queryString,
		headerString + "\n",
		strings.Join(signedHeaders, ";"),
		payloadHash,
	}, "\n")

	hashedCanonical := sha256Hex([]byte(canonicalString))
	credentialScope := authDate + "/" + region + "/" + service + "/request"
	signString := strings.Join([]string{
		"HMAC-SHA256",
		date,
		credentialScope,
		hashedCanonical,
	}, "\n")

	signedKey := getSignedKey(secretKey, authDate, region, service)
	signature := hex.EncodeToString(hmacSHA256(signedKey, signString))

	auth := "HMAC-SHA256" +
		" Credential=" + accessKey + "/" + credentialScope +
		", SignedHeaders=" + strings.Join(signedHeaders, ";") +
		", Signature=" + signature
	req.Header.Set("Authorization", auth)
	return nil
}

func getSignedKey(secretKey, date, region, service string) []byte {
	kDate := hmacSHA256([]byte(secretKey), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "request")
}

func hmacSHA256(key []byte, content string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(content))
	return mac.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
