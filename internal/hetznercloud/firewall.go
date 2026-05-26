package hetznercloud

import (
	"fmt"
	"strconv"
	"strings"
)

// Rule Hetzner Cloud 防火墙规则。
type Rule struct {
	Description    string   `json:"description,omitempty"`
	Direction      string   `json:"direction"`
	Protocol       string   `json:"protocol"`
	Port           string   `json:"port,omitempty"`
	SourceIPs      []string `json:"source_ips,omitempty"`
	DestinationIPs []string `json:"destination_ips,omitempty"`
}

type Firewall struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

type FirewallClient struct {
	api        *Client
	firewallID int64
}

func NewFirewall(token, firewallID, endpoint string) (*FirewallClient, error) {
	id, err := strconv.ParseInt(strings.TrimSpace(firewallID), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("无效 firewall_id %q: %w", firewallID, err)
	}
	client := NewClient(token)
	if endpoint != "" {
		client.BaseURL = strings.TrimRight(endpoint, "/")
	}
	return &FirewallClient{
		api:        client,
		firewallID: id,
	}, nil
}

func (c *FirewallClient) path() string {
	return fmt.Sprintf("/firewalls/%d", c.firewallID)
}

func (c *FirewallClient) Get() (*Firewall, error) {
	var resp struct {
		Firewall Firewall `json:"firewall"`
	}
	if err := c.api.Do("GET", c.path(), nil, &resp); err != nil {
		return nil, err
	}
	return &resp.Firewall, nil
}

func (c *FirewallClient) SetRules(rules []Rule) error {
	body := map[string]any{"rules": rules}
	path := c.path() + "/actions/set_rules"
	return c.api.Do("POST", path, body, nil)
}

func normalizeProtocol(p string) string {
	p = strings.TrimSpace(strings.ToLower(p))
	switch p {
	case "tcp", "udp", "icmp", "esp", "gre":
		return p
	default:
		return "tcp"
	}
}

func ruleMatchesInbound(r Rule, proto, port, cidr string) bool {
	if !strings.EqualFold(r.Direction, "in") {
		return false
	}
	if !strings.EqualFold(r.Protocol, proto) {
		return false
	}
	if port != "" && r.Port != "" && r.Port != port {
		return false
	}
	for _, ip := range r.SourceIPs {
		if normalizeCIDR(ip) == normalizeCIDR(cidr) {
			return true
		}
	}
	return false
}

func normalizeCIDR(s string) string {
	return strings.TrimSpace(s)
}

// UpsertInbound 在保留现有规则的前提下，添加入站白名单规则。
func (c *FirewallClient) UpsertInbound(proto, port, cidr, desc string) error {
	fw, err := c.Get()
	if err != nil {
		return err
	}
	proto = normalizeProtocol(proto)
	rules := fw.Rules

	if ruleExists(rules, proto, port, cidr) {
		return nil
	}

	rules = append(rules, Rule{
		Description: desc,
		Direction:   "in",
		Protocol:    proto,
		Port:        port,
		SourceIPs:   []string{cidr},
	})
	return c.SetRules(rules)
}

// RemoveInbound 删除由本工具托管的、匹配旧 IP 的入站规则。
func (c *FirewallClient) RemoveInbound(proto, port, cidr, descPrefix string) error {
	fw, err := c.Get()
	if err != nil {
		return err
	}
	proto = normalizeProtocol(proto)
	rules := removeManagedInbound(fw.Rules, descPrefix, proto, port, cidr)
	return c.SetRules(rules)
}

func removeManagedInbound(rules []Rule, descPrefix, proto, port, cidr string) []Rule {
	var out []Rule
	for _, r := range rules {
		if isManagedRule(r, descPrefix) && ruleMatchesInbound(r, proto, port, cidr) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func isManagedRule(r Rule, descPrefix string) bool {
	return descPrefix != "" && strings.HasPrefix(r.Description, descPrefix)
}

func ruleExists(rules []Rule, proto, port, cidr string) bool {
	for _, r := range rules {
		if ruleMatchesInbound(r, proto, port, cidr) {
			return true
		}
	}
	return false
}
