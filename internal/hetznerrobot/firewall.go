package hetznerrobot

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type InputRule struct {
	Name      string  `json:"name"`
	IPVersion string  `json:"ip_version"`
	SrcIP     *string `json:"src_ip"`
	DstIP     *string `json:"dst_ip"`
	DstPort   *string `json:"dst_port"`
	SrcPort   *string `json:"src_port"`
	Protocol  *string `json:"protocol"`
	TCPFlags  *string `json:"tcp_flags"`
	Action    string  `json:"action"`
}

type OutputRule struct {
	Name      string  `json:"name"`
	IPVersion *string `json:"ip_version"`
	SrcIP     *string `json:"src_ip"`
	DstIP     *string `json:"dst_ip"`
	DstPort   *string `json:"dst_port"`
	SrcPort   *string `json:"src_port"`
	Protocol  *string `json:"protocol"`
	TCPFlags  *string `json:"tcp_flags"`
	Action    string  `json:"action"`
}

type Rules struct {
	Input  []InputRule  `json:"input"`
	Output []OutputRule `json:"output"`
}

type Firewall struct {
	ServerIP      string `json:"server_ip"`
	ServerNumber  int    `json:"server_number"`
	Status        string `json:"status"`
	FilterIPv6    bool   `json:"filter_ipv6"`
	WhitelistHOS  bool   `json:"whitelist_hos"`
	Port          string `json:"port"`
	Rules         Rules  `json:"rules"`
}

type FirewallClient struct {
	api          *Client
	serverNumber string
}

func NewFirewall(user, password, baseURL, serverNumber string) *FirewallClient {
	return &FirewallClient{
		api:          NewClient(user, password, baseURL),
		serverNumber: strings.TrimSpace(serverNumber),
	}
}

func (c *FirewallClient) path() string {
	return "/firewall/" + c.serverNumber
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

func (c *FirewallClient) Apply(fw *Firewall) error {
	form := buildForm(fw)
	return c.api.Do("POST", c.path(), form, nil)
}

func buildForm(fw *Firewall) url.Values {
	form := url.Values{}
	form.Set("status", "active")
	if fw.Status == "disabled" {
		form.Set("status", "disabled")
	}
	form.Set("filter_ipv6", strconv.FormatBool(fw.FilterIPv6))
	form.Set("whitelist_hos", strconv.FormatBool(fw.WhitelistHOS))

	for i, r := range fw.Rules.Input {
		prefix := fmt.Sprintf("rules[input][%d]", i)
		setInputRule(form, prefix, r)
	}
	for i, r := range fw.Rules.Output {
		prefix := fmt.Sprintf("rules[output][%d]", i)
		setOutputRule(form, prefix, r)
	}
	return form
}

func setInputRule(form url.Values, prefix string, r InputRule) {
	form.Set(prefix+"[name]", r.Name)
	if r.IPVersion != "" {
		form.Set(prefix+"[ip_version]", r.IPVersion)
	}
	if r.SrcIP != nil && *r.SrcIP != "" {
		form.Set(prefix+"[src_ip]", *r.SrcIP)
	}
	if r.DstIP != nil && *r.DstIP != "" {
		form.Set(prefix+"[dst_ip]", *r.DstIP)
	}
	if r.DstPort != nil && *r.DstPort != "" {
		form.Set(prefix+"[dst_port]", *r.DstPort)
	}
	if r.SrcPort != nil && *r.SrcPort != "" {
		form.Set(prefix+"[src_port]", *r.SrcPort)
	}
	if r.Protocol != nil && *r.Protocol != "" {
		form.Set(prefix+"[protocol]", *r.Protocol)
	}
	if r.TCPFlags != nil && *r.TCPFlags != "" {
		form.Set(prefix+"[tcp_flags]", *r.TCPFlags)
	}
	form.Set(prefix+"[action]", r.Action)
}

func setOutputRule(form url.Values, prefix string, r OutputRule) {
	form.Set(prefix+"[name]", r.Name)
	if r.IPVersion != nil && *r.IPVersion != "" {
		form.Set(prefix+"[ip_version]", *r.IPVersion)
	}
	if r.SrcIP != nil && *r.SrcIP != "" {
		form.Set(prefix+"[src_ip]", *r.SrcIP)
	}
	if r.DstIP != nil && *r.DstIP != "" {
		form.Set(prefix+"[dst_ip]", *r.DstIP)
	}
	if r.DstPort != nil && *r.DstPort != "" {
		form.Set(prefix+"[dst_port]", *r.DstPort)
	}
	if r.SrcPort != nil && *r.SrcPort != "" {
		form.Set(prefix+"[src_port]", *r.SrcPort)
	}
	if r.Protocol != nil && *r.Protocol != "" {
		form.Set(prefix+"[protocol]", *r.Protocol)
	}
	if r.TCPFlags != nil && *r.TCPFlags != "" {
		form.Set(prefix+"[tcp_flags]", *r.TCPFlags)
	}
	form.Set(prefix+"[action]", r.Action)
}

func normalizeProtocol(p string) string {
	p = strings.TrimSpace(strings.ToLower(p))
	switch p {
	case "tcp", "udp", "icmp", "gre", "esp":
		return p
	default:
		return "tcp"
	}
}

func inputRuleMatches(r InputRule, ruleName, proto, port, cidr string) bool {
	if ruleName != "" && r.Name != ruleName {
		return false
	}
	if r.SrcIP == nil || normalizeCIDR(*r.SrcIP) != normalizeCIDR(cidr) {
		return false
	}
	if r.DstPort == nil || *r.DstPort != port {
		return false
	}
	if r.Protocol != nil && *r.Protocol != "" && !strings.EqualFold(*r.Protocol, proto) {
		return false
	}
	return strings.EqualFold(r.Action, "accept")
}

func normalizeCIDR(s string) string {
	return strings.TrimSpace(s)
}

// UpsertInbound 添加入站白名单规则（保留其他规则）。
func (c *FirewallClient) UpsertInbound(proto, port, cidr, ruleName string) error {
	fw, err := c.Get()
	if err != nil {
		return err
	}
	proto = normalizeProtocol(proto)

	for _, r := range fw.Rules.Input {
		if inputRuleMatches(r, ruleName, proto, port, cidr) {
			return nil
		}
	}

	protoPtr := proto
	portPtr := port
	fw.Rules.Input = append(fw.Rules.Input, InputRule{
		Name:      ruleName,
		IPVersion: "ipv4",
		SrcIP:     &cidr,
		DstPort:   &portPtr,
		Protocol:  &protoPtr,
		Action:    "accept",
	})
	if fw.Status == "" || fw.Status == "disabled" {
		fw.Status = "active"
	}
	return c.Apply(fw)
}

func inputRuleMatchesManaged(r InputRule, namePrefix, proto, port, cidr string) bool {
	if namePrefix != "" && !strings.HasPrefix(r.Name, namePrefix) {
		return false
	}
	return inputRuleMatches(r, "", proto, port, cidr)
}

// RemoveInbound 删除匹配的托管入站规则（按 description 前缀 + IP + 端口）。
func (c *FirewallClient) RemoveInbound(proto, port, cidr, namePrefix string) error {
	fw, err := c.Get()
	if err != nil {
		return err
	}
	proto = normalizeProtocol(proto)

	var kept []InputRule
	for _, r := range fw.Rules.Input {
		if inputRuleMatchesManaged(r, namePrefix, proto, port, cidr) {
			continue
		}
		kept = append(kept, r)
	}
	fw.Rules.Input = kept
	return c.Apply(fw)
}
