package tencentapi

const (
	lighthouseHost    = "lighthouse.tencentcloudapi.com"
	lighthouseVersion = "2020-03-24"
)

type FirewallRule struct {
	Protocol                string `json:"Protocol"`
	Port                    string `json:"Port"`
	CidrBlock               string `json:"CidrBlock"`
	Action                  string `json:"Action"`
	FirewallRuleDescription string `json:"FirewallRuleDescription,omitempty"`
}

type LighthouseClient struct {
	api        *Client
	instanceID string
}

func NewLighthouse(secretID, secretKey, region, instanceID string) *LighthouseClient {
	return &LighthouseClient{
		api: NewClient(
			secretID, secretKey, region,
			"lighthouse", lighthouseHost, lighthouseVersion,
		),
		instanceID: instanceID,
	}
}

func (c *LighthouseClient) CreateRules(rules []FirewallRule) error {
	return c.api.Do("CreateFirewallRules", map[string]any{
		"InstanceId":    c.instanceID,
		"FirewallRules": rules,
	})
}

func (c *LighthouseClient) DeleteRules(rules []FirewallRule) error {
	return c.api.Do("DeleteFirewallRules", map[string]any{
		"InstanceId":    c.instanceID,
		"FirewallRules": rules,
	})
}
