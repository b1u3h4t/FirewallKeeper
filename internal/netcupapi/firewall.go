package netcupapi

import (
	"fmt"
	"strconv"
	"strings"
)

// Rule Netcup SCP 防火墙规则（参见 SCP OpenAPI FirewallRule）。
type Rule struct {
	Description        string   `json:"description,omitempty"`
	Direction          string   `json:"direction"`
	Protocol           string   `json:"protocol"`
	Action             string   `json:"action"`
	Sources            []string `json:"sources,omitempty"`
	SourcePorts        *string  `json:"sourcePorts"`
	Destinations       []string `json:"destinations,omitempty"`
	DestinationPorts   *string  `json:"destinationPorts"`
}

type FirewallPolicy struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Rules       []Rule `json:"rules"`
}

type FirewallPolicyClient struct {
	api      *Client
	userID   int
	policyID int
}

func NewFirewallPolicy(refreshToken, accessToken, baseURL string, userID, policyID int) *FirewallPolicyClient {
	return &FirewallPolicyClient{
		api:      NewClient(refreshToken, accessToken, baseURL),
		userID:   userID,
		policyID: policyID,
	}
}

func (c *FirewallPolicyClient) path() string {
	return fmt.Sprintf("/users/%d/firewall-policies/%d", c.userID, c.policyID)
}

func (c *FirewallPolicyClient) Get() (*FirewallPolicy, error) {
	var policy FirewallPolicy
	if err := c.api.Do("GET", c.path(), nil, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func (c *FirewallPolicyClient) Update(policy *FirewallPolicy) error {
	body := map[string]any{
		"name":  policy.Name,
		"rules": policy.Rules,
	}
	if policy.Description != "" {
		body["description"] = policy.Description
	}
	return c.api.Do("PUT", c.path(), body, nil)
}

// UpsertIngress 在策略中追加入站 ACCEPT 规则（保留其余规则）。
func (c *FirewallPolicyClient) UpsertIngress(proto, port, cidr, desc string) error {
	policy, err := c.Get()
	if err != nil {
		return err
	}
	proto = normalizeProtocol(proto)
	portStr := formatPort(port)

	if ruleExists(policy.Rules, proto, portStr, cidr) {
		return nil
	}

	policy.Rules = append(policy.Rules, Rule{
		Description:      desc,
		Direction:        "INGRESS",
		Protocol:         proto,
		Action:           "ACCEPT",
		Sources:          []string{cidr},
		DestinationPorts: portPtr(portStr),
	})
	return c.Update(policy)
}

// RemoveIngress 删除匹配的入站规则（按 description 前缀 + IP + 端口）。
func (c *FirewallPolicyClient) RemoveIngress(proto, port, cidr, descPrefix string) error {
	policy, err := c.Get()
	if err != nil {
		return err
	}
	proto = normalizeProtocol(proto)
	portStr := formatPort(port)

	var kept []Rule
	for _, r := range policy.Rules {
		if ruleMatchesManaged(r, descPrefix, proto, portStr, cidr) {
			continue
		}
		kept = append(kept, r)
	}
	if len(kept) == len(policy.Rules) {
		return &APIError{Status: 404, Message: "no matching firewall rule", Code: "not_found"}
	}
	policy.Rules = kept
	return c.Update(policy)
}

// ReapplyServerFirewall 在服务器网卡上重新应用防火墙（可选）。
func ReapplyServerFirewall(c *Client, serverID int, mac string) error {
	path := fmt.Sprintf("/servers/%d/interfaces/%s/firewall:reapply", serverID, mac)
	return c.Do("POST", path, nil, nil)
}

// FirstInterfaceMAC 返回服务器第一个网卡 MAC。
func FirstInterfaceMAC(c *Client, serverID int) (string, error) {
	path := fmt.Sprintf("/servers/%d/interfaces?loadRdns=false", serverID)
	var ifaces []struct {
		MAC string `json:"mac"`
	}
	if err := c.Do("GET", path, nil, &ifaces); err != nil {
		return "", err
	}
	if len(ifaces) == 0 {
		return "", fmt.Errorf("服务器 %d 无网卡接口", serverID)
	}
	return ifaces[0].MAC, nil
}

func portPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func formatPort(port string) string {
	port = strings.TrimSpace(port)
	if port == "" {
		return ""
	}
	return port
}

func normalizeProtocol(p string) string {
	p = strings.TrimSpace(strings.ToUpper(p))
	switch p {
	case "TCP", "UDP", "ICMP", "ICMPV6":
		if p == "ICMPV6" {
			return "ICMPv6"
		}
		return p
	default:
		return "TCP"
	}
}

func ruleExists(rules []Rule, proto, port, cidr string) bool {
	for _, r := range rules {
		if ruleMatches(r, proto, port, cidr) {
			return true
		}
	}
	return false
}

func ruleMatches(r Rule, proto, port, cidr string) bool {
	if !strings.EqualFold(r.Direction, "INGRESS") || !strings.EqualFold(r.Action, "ACCEPT") {
		return false
	}
	if !strings.EqualFold(r.Protocol, proto) {
		return false
	}
	if !portEqual(r.DestinationPorts, port) {
		return false
	}
	return sourceContains(r.Sources, cidr)
}

func ruleMatchesManaged(r Rule, descPrefix, proto, port, cidr string) bool {
	if descPrefix != "" && !strings.HasPrefix(r.Description, descPrefix) {
		return false
	}
	return ruleMatches(r, proto, port, cidr)
}

func portEqual(dst *string, want string) bool {
	if dst == nil && want == "" {
		return true
	}
	if dst == nil {
		return false
	}
	return *dst == want
}

func sourceContains(sources []string, cidr string) bool {
	cidr = strings.TrimSpace(cidr)
	for _, s := range sources {
		if strings.TrimSpace(s) == cidr {
			return true
		}
	}
	return false
}

// ParseIntID 解析 server_id / policy_id / user_id。
func ParseIntID(s, field string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty %s", field)
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("无效 %s %q: %w", field, s, err)
	}
	return n, nil
}
