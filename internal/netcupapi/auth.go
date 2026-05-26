package netcupapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	authURL    = "https://www.servercontrolpanel.de/realms/scp/protocol/openid-connect"
	clientID   = "scp"
	userInfoURL = authURL + "/userinfo"
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

func refreshAccessToken(refreshToken string) (string, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequest(http.MethodPost, authURL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token refresh failed: HTTP %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", err
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("token refresh: empty access_token")
	}
	return tr.AccessToken, nil
}

func fetchCurrentUserID(accessToken string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, userInfoURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("userinfo failed: HTTP %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	var info struct {
		Sub string `json:"sub"`
		ID  int    `json:"id"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return 0, err
	}
	if info.ID != 0 {
		return info.ID, nil
	}
	// sub 有时为数字字符串
	if info.Sub != "" {
		var id int
		if _, err := fmt.Sscanf(info.Sub, "%d", &id); err == nil && id > 0 {
			return id, nil
		}
	}
	return 0, fmt.Errorf("userinfo: missing user id")
}
