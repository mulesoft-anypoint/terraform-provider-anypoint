package anypoint

import (
	"context"
	"io"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/mulesoft-anypoint/anypoint-client-go/private_space"
)

func preparePrivateSpaceResourceSchema() map[string]*schema.Schema {
	ps_schema := cloneSchema(PRIVATE_SPACE_SCHEMA)
	ps_schema["last_updated"] = &schema.Schema{
		Type:        schema.TypeString,
		Computed:    true,
		Description: "The last time this resource has been updated locally.",
	}
	ps_schema["name"] = &schema.Schema{
		Type:        schema.TypeString,
		Required:    true,
		ForceNew:    true,
		Description: "The name of the private space.",
	}
	ps_schema["org_id"] = &schema.Schema{
		Type:        schema.TypeString,
		Required:    true,
		ForceNew:    true,
		Description: "The ID of the organization to which the private space belongs.",
	}
	ps_schema["network_region"] = &schema.Schema{
		Type:     schema.TypeString,
		Required: true,
		ForceNew: true,
		ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice(
			[]string{
				"us-east-1", "us-east-2", "us-west-2", "ca-central-1", "eu-west-1", "eu-west-2",
				"ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "eu-central-1",
			},
			false,
		)),
		Description: "The network region of the private space.",
	}
	ps_schema["network_cidr_block"] = &schema.Schema{
		Type:             schema.TypeString,
		Required:         true,
		ForceNew:         true,
		ValidateDiagFunc: validation.ToDiagFunc(validation.IsCIDR),
		Description:      "The CIDR block of the network.",
	}
	ps_schema["environments_type"] = &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Default:  "sandbox",
		ValidateDiagFunc: validation.ToDiagFunc(
			validation.StringInSlice([]string{"all", "sandbox", "production"}, false),
		),
		Description: "The type of associated environments. Valid values are 'all', 'sandbox', 'production'. Default is 'sandbox'",
	}
	ps_schema["environments_business_groups"] = &schema.Schema{
		Type:        schema.TypeList,
		Optional:    true,
		Default:     []string{"all"},
		Description: "Business groups associated with the associated environments. Valid values are 'all' or business units uuids. Default is 'all'",
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
	}
	ps_schema["network_internal_dns_servers"] = &schema.Schema{
		Type:        schema.TypeList,
		Optional:    true,
		Description: "List of DNS servers. Values should be valid IP addresses (v4 or v6)",
		Elem: &schema.Schema{
			Type:             schema.TypeString,
			ValidateDiagFunc: validation.ToDiagFunc(validation.IsIPAddress),
		},
	}
	ps_schema["network_internal_dns_special_domains"] = &schema.Schema{
		Type:        schema.TypeList,
		Optional:    true,
		Description: "List of domains to be used for internal DNS resolution.",
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
	}
	ps_schema["network_reserved_cidrs"] = &schema.Schema{
		Type:        schema.TypeList,
		Optional:    true,
		Description: "Reserved CIDR blocks.",
		Elem: &schema.Schema{
			Type:             schema.TypeString,
			ValidateDiagFunc: validation.ToDiagFunc(validation.IsCIDR),
		},
	}
	ps_schema["firewall_rules"] = &schema.Schema{
		Type:        schema.TypeList,
		Optional:    true,
		Description: "Firewall rules for the private space.",
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"cidr_block": {
					Type:             schema.TypeString,
					Required:         true,
					ValidateDiagFunc: validation.ToDiagFunc(validation.IsCIDR),
					Description:      "The CIDR block for the firewall rule.",
				},
				"protocol": {
					Type:     schema.TypeString,
					Required: true,
					ValidateDiagFunc: validation.ToDiagFunc(
						validation.StringInSlice([]string{"tcp", "udp", "icmp"}, false),
					),
					Description: "Specifies the network protocol used in the firewall rule. Valid options are 'tcp', 'udp', or 'icmp'.",
				},
				"from_port": {
					Type:             schema.TypeInt,
					Required:         true,
					ValidateDiagFunc: validation.ToDiagFunc(validation.IsPortNumberOrZero),
					Description:      "The starting port for the firewall rule.",
				},
				"to_port": {
					Type:             schema.TypeInt,
					Required:         true,
					ValidateDiagFunc: validation.ToDiagFunc(validation.IsPortNumberOrZero),
					Description:      "The ending port for the firewall rule.",
				},
				"type": {
					Type:     schema.TypeString,
					Required: true,
					ValidateDiagFunc: validation.ToDiagFunc(
						validation.StringInSlice([]string{"inbound", "outbound"}, false),
					),
					Description: "The type of the firewall rule. Valid values are 'inbound' for incoming traffic and 'outbound' for outgoing traffic.",
				},
			},
		},
	}
	ps_schema["enable_iam_role"] = &schema.Schema{
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: "Indicates whether IAM roles are enabled for the private space. Default is false.",
	}
	ps_schema["enable_egress"] = &schema.Schema{
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: "Indicates whether egress is enabled for the private space. Default is false.",
	}
	ps_schema["enable_network_isolation"] = &schema.Schema{
		Type:        schema.TypeBool,
		Optional:    true,
		Default:     false,
		Description: "Indicates whether network isolation is enabled for the private space. Default is true.",
	}
	return ps_schema
}

func resourcePrivateSpace() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourcePrivateSpaceCreate,
		ReadContext:   resourcePrivateSpaceRead,
		UpdateContext: resourcePrivateSpaceUpdate,
		DeleteContext: resourcePrivateSpaceDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Description: `
		Manages a ` + "`" + `private space` + "`" + ` in your business group.
		`,
		Schema: preparePrivateSpaceResourceSchema(),
	}
}

func resourcePrivateSpaceCreate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	authctx := getPrivateSpaceAuthCtx(ctx, &pco)
	body := newPrivateSpaceBody(d)
	//request
	res, httpr, err := pco.privatespaceclient.DefaultApi.CreatePrivateSpace(authctx, orgid).PrivateSpacePostBody(*body).Execute()
	if err != nil {
		var details string
		if httpr != nil && httpr.StatusCode >= 400 {
			defer httpr.Body.Close()
			b, _ := io.ReadAll(httpr.Body)
			details = string(b)
		} else {
			details = err.Error()
		}
		diags := append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to Create Private Space " + res.GetId() + " for org " + orgid,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	d.SetId(res.GetId())
	return resourcePrivateSpaceRead(ctx, d, m)
}

func resourcePrivateSpaceRead(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	id := d.Id()
	if isComposedResourceId(id) {
		orgid, id = decomposePrivateSpaceId(d)
	}
	authctx := getPrivateSpaceAuthCtx(ctx, &pco)
	//request
	res, httpr, err := pco.privatespaceclient.DefaultApi.GetPrivateSpace(authctx, orgid, id).Execute()
	if err != nil {
		var details string
		if httpr != nil && httpr.StatusCode >= 400 {
			defer httpr.Body.Close()
			b, _ := io.ReadAll(httpr.Body)
			details = string(b)
		} else {
			details = err.Error()
		}
		diags := append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to Read Private Space " + id + " for org " + orgid,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	//process data
	private_space := flattenPrivateSpaceData(res)
	//save in data source schema
	if err := setPrivateSpaceAttributesToResourceData(d, private_space); err != nil {
		diags := append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to set data for Private Space " + id + " in org " + orgid,
			Detail:   err.Error(),
		})
		return diags
	}
	d.SetId(id)
	d.Set("org_id", orgid)
	return diags
}

func resourcePrivateSpaceUpdate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	//check if there are changes
	if d.HasChanges(updatablePrivateSpaceAttributes()...) {
		pco := m.(ProviderConfOutput)
		orgid := d.Get("org_id").(string)
		id := d.Id()
		authctx := getPrivateSpaceAuthCtx(ctx, &pco)
		body := newPrivateSpacePatchBody(d)
		//request
		_, httpr, err := pco.privatespaceclient.DefaultApi.UpdatePrivateSpace(authctx, orgid, id).PrivateSpacePatchBody(*body).Execute()
		if err != nil {
			var details string
			if httpr != nil && httpr.StatusCode >= 400 {
				defer httpr.Body.Close()
				b, _ := io.ReadAll(httpr.Body)
				details = string(b)
			} else {
				details = err.Error()
			}
			diags := append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to Update Private Space " + id + " for org " + orgid,
				Detail:   details,
			})
			return diags
		}
		defer httpr.Body.Close()
		d.Set("last_updated", time.Now().Format(time.RFC850))
		return resourcePrivateSpaceRead(ctx, d, m)
	}

	return diags
}

func resourcePrivateSpaceDelete(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	authctx := getPrivateSpaceAuthCtx(ctx, &pco)
	//request
	httpr, err := pco.privatespaceclient.DefaultApi.DeletePrivateSpace(authctx, orgid, d.Id()).Execute()
	if err != nil {
		var details string
		if httpr != nil && httpr.StatusCode >= 400 {
			defer httpr.Body.Close()
			b, _ := io.ReadAll(httpr.Body)
			details = string(b)
		} else {
			details = err.Error()
		}
		diags := append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to Delete Private Space for org " + orgid,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	d.SetId("")
	return diags
}

func newPrivateSpaceBody(d *schema.ResourceData) *private_space.PrivateSpacePostBody {
	body := private_space.NewPrivateSpacePostBody()
	body.SetName(d.Get("name").(string))
	environments := private_space.NewPrivateSpaceAssociatedEnvironments()
	network := private_space.NewPrivateSpaceNetworkEditable()
	networkDnsServers := private_space.NewPrivateSpaceNetworkEditableInternalDns()
	if envType := d.Get("environments_type").(string); envType != "" {
		environments.SetType(envType)
	}
	if envBusinessGroups := d.Get("environments_business_groups").([]any); len(envBusinessGroups) > 0 {
		var businessGroups []string
		for _, group := range envBusinessGroups {
			businessGroups = append(businessGroups, group.(string))
		}
		environments.SetBusinessGroups(businessGroups)
	}
	if networkRegion := d.Get("network_region").(string); networkRegion != "" {
		network.SetRegion(networkRegion)
	}
	if networkCIDRBlock := d.Get("network_cidr_block").(string); networkCIDRBlock != "" {
		network.SetCidrBlock(networkCIDRBlock)
	}
	if networkInternalDNSServers := d.Get("network_internal_dns_servers").([]any); len(networkInternalDNSServers) > 0 {
		var dnsServers []string
		for _, server := range networkInternalDNSServers {
			dnsServers = append(dnsServers, server.(string))
		}
		networkDnsServers.SetDnsServers(dnsServers)
		network.SetInternalDns(*networkDnsServers)
	}
	if networkInternalDNSSpecialDomains := d.Get("network_internal_dns_special_domains").([]any); len(networkInternalDNSSpecialDomains) > 0 {
		var specialDomains []string
		for _, domain := range networkInternalDNSSpecialDomains {
			specialDomains = append(specialDomains, domain.(string))
		}
		networkDnsServers.SetSpecialDomains(specialDomains)
		network.SetInternalDns(*networkDnsServers)
	}
	if networkReservedCIDRs := d.Get("network_reserved_cidrs").([]any); len(networkReservedCIDRs) > 0 {
		var reservedCIDRs []string
		for _, cidr := range networkReservedCIDRs {
			reservedCIDRs = append(reservedCIDRs, cidr.(string))
		}
		network.SetReservedCidrs(reservedCIDRs)
	}
	if firewall := d.Get("firewall_rules").([]any); len(firewall) > 0 {
		var rules []private_space.FirewallRule
		for _, rule := range firewall {
			firewallRule := rule.(map[string]any)
			firewallRuleBody := private_space.NewFirewallRule()
			firewallRuleBody.SetCidrBlock(firewallRule["cidr_block"].(string))
			firewallRuleBody.SetProtocol(firewallRule["protocol"].(string))
			firewallRuleBody.SetFromPort(int32(firewallRule["from_port"].(int)))
			firewallRuleBody.SetToPort(int32(firewallRule["to_port"].(int)))
			firewallRuleBody.SetType(firewallRule["type"].(string))
			rules = append(rules, *firewallRuleBody)
		}
		if rules != nil {
			body.SetFirewallRules(rules)
		}
	}
	body.SetEnvironments(*environments)
	body.SetNetwork(*network)
	return body
}

func newPrivateSpacePatchBody(d *schema.ResourceData) *private_space.PrivateSpacePatchBody {
	body := private_space.NewPrivateSpacePatchBody()
	environments := private_space.NewPrivateSpaceAssociatedEnvironments()
	network := private_space.NewPrivateSpaceNetworkEditable()
	networkDnsServers := private_space.NewPrivateSpaceNetworkEditableInternalDns()
	if environments_type := d.Get("environments_type").(string); environments_type != "" {
		environments.SetType(environments_type)
	}
	if environments_business_groups := d.Get("environments_business_groups").([]any); len(environments_business_groups) > 0 {
		var businessGroups []string
		for _, group := range environments_business_groups {
			businessGroups = append(businessGroups, group.(string))
		}
		environments.SetBusinessGroups(businessGroups)
	}
	if network_region := d.Get("network_region").(string); network_region != "" {
		network.SetRegion(network_region)
	}
	if network_cidr_block := d.Get("network_cidr_block").(string); network_cidr_block != "" {
		network.SetCidrBlock(network_cidr_block)
	}
	if network_internal_dns_servers := d.Get("network_internal_dns_servers").([]any); len(network_internal_dns_servers) > 0 {
		var dnsServers []string
		for _, server := range network_internal_dns_servers {
			dnsServers = append(dnsServers, server.(string))
		}
		networkDnsServers.SetDnsServers(dnsServers)
		network.SetInternalDns(*networkDnsServers)
	}
	if network_internal_dns_special_domains := d.Get("network_internal_dns_special_domains").([]any); len(network_internal_dns_special_domains) > 0 {
		var specialDomains []string
		for _, domain := range network_internal_dns_special_domains {
			specialDomains = append(specialDomains, domain.(string))
		}
		networkDnsServers.SetSpecialDomains(specialDomains)
		network.SetInternalDns(*networkDnsServers)
	}
	if network_reserved_cidrs := d.Get("network_reserved_cidrs").([]any); len(network_reserved_cidrs) > 0 {
		var reservedCIDRs []string
		for _, cidr := range network_reserved_cidrs {
			reservedCIDRs = append(reservedCIDRs, cidr.(string))
		}
		network.SetReservedCidrs(reservedCIDRs)
	}
	if firewall := d.Get("firewall_rules").([]any); len(firewall) > 0 {
		var rules []private_space.FirewallRule
		for _, rule := range firewall {
			firewallRule := rule.(map[string]any)
			firewallRuleBody := private_space.NewFirewallRule()
			firewallRuleBody.SetCidrBlock(firewallRule["cidr_block"].(string))
			firewallRuleBody.SetProtocol(firewallRule["protocol"].(string))
			firewallRuleBody.SetFromPort(int32(firewallRule["from_port"].(int)))
			firewallRuleBody.SetToPort(int32(firewallRule["to_port"].(int)))
			firewallRuleBody.SetType(firewallRule["type"].(string))
			rules = append(rules, *firewallRuleBody)
		}
		if rules != nil {
			body.SetFirewallRules(rules)
		}
	}
	body.SetEnvironments(*environments)
	body.SetNetwork(*network)
	return body
}

func updatablePrivateSpaceAttributes() []string {
	return []string{
		"environments_type",
		"environments_business_groups",
		"network_internal_dns_servers",
		"network_internal_dns_special_domains",
		"network_reserved_cidrs",
		"firewall_rules",
		"enable_iam_role",
		"enable_egress",
		"enable_network_isolation",
	}
}

func getPrivateSpaceAuthCtx(ctx context.Context, pco *ProviderConfOutput) context.Context {
	tmp := context.WithValue(ctx, private_space.ContextAccessToken, pco.access_token)
	return context.WithValue(tmp, private_space.ContextServerIndex, pco.server_index)
}

func decomposePrivateSpaceId(d *schema.ResourceData) (string, string) {
	s := DecomposeResourceId(d.Id())
	return s[0], s[1]
}
