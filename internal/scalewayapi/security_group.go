package scalewayapi

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Rule struct {
	ID           string  `json:"id"`
	Protocol     string  `json:"protocol"`
	Direction    string  `json:"direction"`
	Action       string  `json:"action"`
	IPRange      string  `json:"ip_range"`
	DestPortFrom *uint32 `json:"dest_port_from"`
	DestPortTo   *uint32 `json:"dest_port_to"`
}

type SecurityGroupClient struct {
	api             *Client
	zone            string
	securityGroupID string
}

func NewSecurityGroup(secretKey, zone, securityGroupID string) *SecurityGroupClient {
	return &SecurityGroupClient{
		api:             NewClient(secretKey),
		zone:            zone,
		securityGroupID: securityGroupID,
	}
}

func (c *SecurityGroupClient) rulesPath() string {
	return fmt.Sprintf("/instance/v1/zones/%s/security_groups/%s/rules", c.zone, c.securityGroupID)
}

type createRuleBody struct {
	Protocol     string `json:"protocol"`
	Direction    string `json:"direction"`
	Action       string `json:"action"`
	IPRange      string `json:"ip_range"`
	DestPortFrom uint32 `json:"dest_port_from,omitempty"`
	DestPortTo   uint32 `json:"dest_port_to,omitempty"`
}

type createRuleResponse struct {
	Rule Rule `json:"rule"`
}

type listRulesResponse struct {
	Rules []Rule `json:"rules"`
}

// CreateInboundAccept 添加入站 accept 规则。
func (c *SecurityGroupClient) CreateInboundAccept(protocol string, port uint32, ipRange string) error {
	body := createRuleBody{
		Protocol:  normalizeProtocol(protocol),
		Direction: "inbound",
		Action:    "accept",
		IPRange:   ipRange,
	}
	if port > 0 {
		body.DestPortFrom = port
		body.DestPortTo = port
	}

	var resp createRuleResponse
	return c.api.Do("POST", c.rulesPath(), body, &resp)
}

// ListRules 列出安全组全部规则（自动分页）。
func (c *SecurityGroupClient) ListRules() ([]Rule, error) {
	var all []Rule
	page := 1
	const perPage = 100

	for {
		path := fmt.Sprintf("%s?per_page=%d&page=%d", c.rulesPath(), perPage, page)
		var resp listRulesResponse
		if err := c.api.Do("GET", path, nil, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.Rules...)
		if len(resp.Rules) < perPage {
			break
		}
		page++
	}
	return all, nil
}

// DeleteRule 按规则 ID 删除。
func (c *SecurityGroupClient) DeleteRule(ruleID string) error {
	path := c.rulesPath() + "/" + ruleID
	return c.api.Do("DELETE", path, nil, nil)
}

// DeleteInboundByMatch 删除匹配的入站规则。
func (c *SecurityGroupClient) DeleteInboundByMatch(protocol string, port uint32, ipRange string) error {
	rules, err := c.ListRules()
	if err != nil {
		return err
	}

	proto := normalizeProtocol(protocol)
	var ids []string
	for _, r := range rules {
		if !strings.EqualFold(r.Direction, "inbound") {
			continue
		}
		if !strings.EqualFold(r.Action, "accept") {
			continue
		}
		if !strings.EqualFold(r.Protocol, proto) {
			continue
		}
		if normalizeCIDR(r.IPRange) != normalizeCIDR(ipRange) {
			continue
		}
		if !portMatches(r.DestPortFrom, r.DestPortTo, port) {
			continue
		}
		ids = append(ids, r.ID)
	}

	if len(ids) == 0 {
		return &APIError{Type: "not_found", Message: "no matching security group rule", Status: 404}
	}

	for _, id := range ids {
		if err := c.DeleteRule(id); err != nil {
			return err
		}
	}
	return nil
}

// RuleExists 检查是否已有相同入站 accept 规则。
func (c *SecurityGroupClient) RuleExists(protocol string, port uint32, ipRange string) (bool, error) {
	rules, err := c.ListRules()
	if err != nil {
		return false, err
	}
	proto := normalizeProtocol(protocol)
	for _, r := range rules {
		if !strings.EqualFold(r.Direction, "inbound") ||
			!strings.EqualFold(r.Action, "accept") ||
			!strings.EqualFold(r.Protocol, proto) {
			continue
		}
		if normalizeCIDR(r.IPRange) != normalizeCIDR(ipRange) {
			continue
		}
		if portMatches(r.DestPortFrom, r.DestPortTo, port) {
			return true, nil
		}
	}
	return false, nil
}

func normalizeProtocol(p string) string {
	p = strings.TrimSpace(strings.ToUpper(p))
	switch p {
	case "TCP", "UDP", "ICMP", "ANY":
		return p
	default:
		return "TCP"
	}
}

func normalizeCIDR(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if strings.Contains(s, "/") {
		_, ipNet, err := net.ParseCIDR(s)
		if err == nil {
			return ipNet.String()
		}
		return s
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32"
		}
		return ip.String() + "/128"
	}
	return s
}

func portMatches(from, to *uint32, want uint32) bool {
	if want == 0 {
		return from == nil && to == nil
	}
	if from == nil && to == nil {
		return false
	}
	f, t := uint32(0), uint32(0)
	if from != nil {
		f = *from
	}
	if to != nil {
		t = *to
	}
	if t == 0 && f != 0 {
		t = f
	}
	return want >= f && want <= t
}

// ParsePort 将配置端口字符串解析为单端口；范围端口取起始端口用于匹配删除。
func ParsePort(port string) (uint32, error) {
	port = strings.TrimSpace(port)
	if port == "" {
		return 0, nil
	}
	if strings.Contains(port, "-") {
		parts := strings.SplitN(port, "-", 2)
		n, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
		return uint32(n), err
	}
	if strings.Contains(port, "/") {
		parts := strings.SplitN(port, "/", 2)
		n, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
		return uint32(n), err
	}
	n, err := strconv.ParseUint(port, 10, 32)
	return uint32(n), err
}
