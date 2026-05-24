package ip

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var ipv4RE = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b`)

func FetchPublicIPv4(urls []string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	var errs []string

	for _, url := range urls {
		ip, err := fetchOne(client, url)
		if err == nil {
			return ip, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", url, err))
	}
	return "", fmt.Errorf("无法获取公网 IPv4:\n  %s", strings.Join(errs, "\n  "))
}

func fetchOne(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}

	match := ipv4RE.FindString(strings.TrimSpace(string(body)))
	if match == "" {
		return "", fmt.Errorf("响应中未找到 IPv4")
	}
	return match, nil
}

func ToCIDR(ip string) string {
	if strings.Contains(ip, "/") {
		return ip
	}
	return ip + "/32"
}
