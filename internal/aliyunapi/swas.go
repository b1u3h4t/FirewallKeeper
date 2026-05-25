package aliyunapi

import (
	"fmt"
	"strconv"
	"strings"
)

type FirewallRule struct {
	RuleID       string
	RuleProtocol string
	Port         string
	SourceCidrIP string
	Remark       string
}

type SWASClient struct {
	api        *Client
	instanceID string
}

func NewSWAS(accessKeyID, accessKeySecret, region, endpoint, instanceID string) *SWASClient {
	return &SWASClient{
		api:        NewClient(accessKeyID, accessKeySecret, region, endpoint),
		instanceID: instanceID,
	}
}

func (c *SWASClient) CreateRules(protocol, port, sourceCIDR, remark string) error {
	params := map[string]string{
		"InstanceId":              c.instanceID,
		"FirewallRules.1.RuleProtocol": protocol,
		"FirewallRules.1.Port":         formatPort(port),
		"FirewallRules.1.SourceCidrIp": sourceCIDR,
	}
	if remark != "" {
		params["FirewallRules.1.Remark"] = remark
	}
	_, err := c.api.Do("CreateFirewallRules", params)
	return err
}

func (c *SWASClient) DeleteRulesByMatch(protocol, port, sourceCIDR string) error {
	rules, err := c.listAllFirewallRules()
	if err != nil {
		return err
	}

	wantPort := normalizePort(port)
	var ruleIDs []string
	for _, r := range rules {
		if !portEqual(normalizePort(r.Port), wantPort) {
			continue
		}
		if !strings.EqualFold(r.RuleProtocol, protocol) {
			continue
		}
		if r.SourceCidrIP != sourceCIDR {
			continue
		}
		ruleIDs = append(ruleIDs, r.RuleID)
	}

	if len(ruleIDs) == 0 {
		return &APIError{Code: "RuleNotFound", Message: "no matching firewall rule"}
	}

	params := map[string]string{
		"InstanceId": c.instanceID,
		"ClientToken": randomNonce(),
	}
	for i, id := range ruleIDs {
		params["RuleIds."+strconv.Itoa(i+1)] = id
	}
	_, err = c.api.Do("DeleteFirewallRules", params)
	return err
}

func (c *SWASClient) listAllFirewallRules() ([]FirewallRule, error) {
	var all []FirewallRule
	page := 1
	const pageSize = 50

	for {
		params := map[string]string{
			"InstanceId": c.instanceID,
			"PageNumber": strconv.Itoa(page),
			"PageSize":   strconv.Itoa(pageSize),
		}
		resp, err := c.api.Do("ListFirewallRules", params)
		if err != nil {
			return nil, err
		}

		rules := parseFirewallRules(resp)
		all = append(all, rules...)

		total := intFromAny(resp["TotalCount"])
		if len(all) >= total || len(rules) < pageSize {
			break
		}
		page++
	}
	return all, nil
}

func parseFirewallRules(resp map[string]any) []FirewallRule {
	raw, ok := resp["FirewallRules"].([]any)
	if !ok {
		return nil
	}
	var out []FirewallRule
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, FirewallRule{
			RuleID:       stringFromAny(m["RuleId"]),
			RuleProtocol: stringFromAny(m["RuleProtocol"]),
			Port:         stringFromAny(m["Port"]),
			SourceCidrIP: stringFromAny(m["SourceCidrIp"]),
			Remark:       stringFromAny(m["Remark"]),
		})
	}
	return out
}

// formatPort 将 "22" 转为 SWAS 要求的 "22/22"。
func formatPort(port string) string {
	port = strings.TrimSpace(port)
	if port == "" {
		return port
	}
	if strings.Contains(port, "/") {
		return port
	}
	if strings.Contains(port, ",") || strings.Contains(port, "-") {
		return port
	}
	return port + "/" + port
}

func normalizePort(port string) string {
	port = strings.TrimSpace(port)
	if strings.Contains(port, "/") {
		parts := strings.SplitN(port, "/", 2)
		if len(parts) == 2 && parts[0] == parts[1] {
			return parts[0]
		}
	}
	return port
}

func portEqual(a, b string) bool {
	return normalizePort(a) == normalizePort(b) || a == b
}

func stringFromAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	default:
		return fmt.Sprint(v)
	}
}

func intFromAny(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, _ := strconv.Atoi(t)
		return n
	default:
		return 0
	}
}
