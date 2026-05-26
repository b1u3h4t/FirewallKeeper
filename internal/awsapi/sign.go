package awsapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

func signRequest(req *http.Request, accessKey, secretKey, region, service string, payload []byte) error {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := amzDate[:8]

	req.Header.Set("X-Amz-Date", amzDate)
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	}

	payloadHash := sha256Hex(payload)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signedHeaders := []string{"content-type", "host", "x-amz-content-sha256", "x-amz-date"}
	if req.Header.Get("X-Amz-Target") != "" {
		signedHeaders = append(signedHeaders, "x-amz-target")
	}
	sort.Strings(signedHeaders)

	canonicalHeaders, signedHeaderNames := buildCanonicalHeaders(req, signedHeaders)
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.Path,
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaderNames,
		payloadHash,
	}, "\n")

	credentialScope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := getSigningKey(secretKey, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaderNames, signature,
	)
	req.Header.Set("Authorization", auth)
	return nil
}

func buildCanonicalHeaders(req *http.Request, signed []string) (string, string) {
	sort.Strings(signed)
	var lines []string
	for _, h := range signed {
		var v string
		switch h {
		case "host":
			v = req.Host
		default:
			v = strings.TrimSpace(req.Header.Get(http.CanonicalHeaderKey(h)))
		}
		lines = append(lines, h+":"+v)
	}
	return strings.Join(lines, "\n") + "\n", strings.Join(signed, ";")
}

func getSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, msg string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(msg))
	return mac.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
