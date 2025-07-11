package anypoint

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/mulesoft-anypoint/anypoint-client-go/ame_binding"
)

func resourceAMEBinding() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceAMEBindingCreate,
		ReadContext:   resourceAMEBindingRead,
		UpdateContext: resourceAMEBindingUpdate,
		DeleteContext: resourceAMEBindingDelete,
		Description: `
		Creates an ` + "`" + `Anypoint MQ Exchange Binding` + "`" + ` in your ` + "`" + `region` + "`" + `.
		`,
		Schema: map[string]*schema.Schema{
			"last_updated": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The last time this resource has been updated locally.",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The unique id of this Anypoint MQ Exchange generated by the provider composed of {orgId}/{envId}/{regionId}/{queueId}.",
			},
			"exchange_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The unique id of this Anypoint MQ Exchange.",
			},
			"queue_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The unique id of this Anypoint MQ Queue.",
			},
			"org_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The organization id where the Anypoint MQ Exchange is defined.",
			},
			"env_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The environment id where the Anypoint MQ Exchange is defined.",
			},
			"region_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The region id where the Anypoint MQ Exchange is defined. Refer to Anypoint Platform official documentation for the list of available regions",
				ValidateDiagFunc: validation.ToDiagFunc(
					validation.StringInSlice(
						[]string{
							"us-east-1", "us-east-2", "us-west-2", "ca-central-1", "eu-west-1", "eu-west-2",
							"ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "eu-central-1",
						},
						false,
					),
				),
			},
			"rule_str_compare": {
				Type:          schema.TypeSet,
				Optional:      true,
				Description:   "This rule is to be used when your source attribute is a STRING and you want to use EQUAL or PREFIX comparisons",
				MaxItems:      1,
				ConflictsWith: []string{"rule_str_state", "rule_str_set", "rule_num_compare", "rule_num_state", "rule_num_set"},

				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"property_name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The property name subject of the rule",
						},
						"property_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"STRING"}, false)),
							Description:      "The propety type. Only STRING is supported for this specific rule.",
						},
						"matcher_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"EQ", "PREFIX"}, false)),
							Description:      "The operation to perform on the property. Only 'EQ' (equal) and 'PREFIX' values are supported for this specific rule",
						},
						"value": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The value against which the operation will be performed.",
						},
					},
				},
			},
			"rule_str_state": {
				Type:          schema.TypeSet,
				Optional:      true,
				Description:   "This rule is to be used when your source attribute is a STRING and you want to check the property's existence",
				MaxItems:      1,
				ConflictsWith: []string{"rule_str_compare", "rule_str_set", "rule_num_compare", "rule_num_state", "rule_num_set"},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"property_name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The property name subject of the rule",
						},
						"property_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"STRING"}, false)),
							Description:      "The propety type. Only STRING is supported for this specific rule.",
						},
						"matcher_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"EXISTS"}, false)),
							Description:      "The operation to perform on the property. Only 'EXISTS' value is supported for this specific rule",
						},
						"value": {
							Type:        schema.TypeBool,
							Required:    true,
							Description: "The value against which the operation will be performed.",
						},
					},
				},
			},
			"rule_str_set": {
				Type:          schema.TypeSet,
				Optional:      true,
				Description:   "This rule is to be used when your source attribute is a STRING and you want to check of the property is included or excluded from a set of STRING values",
				MaxItems:      1,
				ConflictsWith: []string{"rule_str_compare", "rule_str_state", "rule_num_compare", "rule_num_state", "rule_num_set"},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"property_name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The property name subject of the rule",
						},
						"property_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"STRING"}, false)),
							Description:      "The propety type. Only STRING is supported for this specific rule.",
						},
						"matcher_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"ANY_OF", "NONE_OF"}, false)),
							Description:      "The operation to perform on the property. Only 'ANY_OF' and 'NONE_OF' values are supported for this specific rule",
						},
						"value": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "The value against which the operation will be performed.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"rule_num_compare": {
				Type:          schema.TypeSet,
				Optional:      true,
				Description:   "This rule is to be used when your source attribute is a NUMERIC and you want to compare is to another NUMERIC value",
				MaxItems:      1,
				ConflictsWith: []string{"rule_str_compare", "rule_str_state", "rule_str_set", "rule_num_state", "rule_num_set"},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"property_name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The property name subject of the rule",
						},
						"property_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"NUMERIC"}, false)),
							Description:      "The propety type. Only NUMERIC is supported for this specific rule.",
						},
						"matcher_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"EQ", "LT", "LE", "GT", "GE"}, false)),
							Description: `
							The operation to perform on the property.
							Only 'EQ' (equal), 'LT'(less than), 'LE' (less or equal), 'GT' (greater than) and 'GE' (greater or equal)
							values are supported for this specific rule.
							`,
						},
						"value": {
							Type:        schema.TypeFloat,
							Required:    true,
							Description: "The value against which the operation will be performed.",
						},
					},
				},
			},
			"rule_num_state": {
				Type:          schema.TypeSet,
				Optional:      true,
				Description:   "This rule is to be used when your source attribute is a NUMERIC and you want to check the property's existence",
				MaxItems:      1,
				ConflictsWith: []string{"rule_str_compare", "rule_str_state", "rule_str_set", "rule_num_compare", "rule_num_set"},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"property_name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The property name subject of the rule",
						},
						"property_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"NUMERIC"}, false)),
							Description:      "The propety type. Only NUMERIC is supported for this specific rule.",
						},
						"matcher_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"EXISTS"}, false)),
							Description:      "The operation to perform on the property. Only 'EXISTS' value is supported for this specific rule",
						},
						"value": {
							Type:        schema.TypeBool,
							Required:    true,
							Description: "The value against which the operation will be performed.",
						},
					},
				},
			},
			"rule_num_set": {
				Type:          schema.TypeSet,
				Optional:      true,
				Description:   "This rule is to be used when your source attribute is a NUMERIC and you want to check of the property is included or excluded from a set of NUMERIC values",
				MaxItems:      1,
				ConflictsWith: []string{"rule_str_compare", "rule_str_state", "rule_str_set", "rule_num_compare", "rule_num_state"},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"property_name": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "The property name subject of the rule",
						},
						"property_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"NUMERIC"}, false)),
							Description:      "The propety type. Only NUMERIC is supported for this specific rule.",
						},
						"matcher_type": {
							Type:             schema.TypeString,
							Required:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice([]string{"RANGE", "NONE_OF"}, false)),
							Description:      "The operation to perform on the property. Only 'RANGE' and 'NONE_OF' values are supported for this specific rule",
						},
						"value": {
							Type:        schema.TypeList,
							Required:    true,
							Description: "The value against which the operation will be performed.",
							Elem: &schema.Schema{
								Type: schema.TypeFloat,
							},
						},
					},
				},
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func resourceAMEBindingCreate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	regionid := d.Get("region_id").(string)
	exchangeid := d.Get("exchange_id").(string)
	queueid := d.Get("queue_id").(string)
	authctx := getAMEBindingAuthCtx(ctx, &pco)

	//request resource creation
	_, httpr, err := pco.amebindingclient.DefaultApi.CreateAMEBinding(authctx, orgid, envid, regionid, exchangeid, queueid).Execute()
	if err != nil {
		var details string
		if httpr != nil && httpr.StatusCode >= 400 {
			b, _ := io.ReadAll(httpr.Body)
			details = string(b)
		} else {
			details = err.Error()
		}
		diags := append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to create AME Binding " + exchangeid + " " + queueid,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()

	d.SetId(ComposeResourceId([]string{orgid, envid, regionid, exchangeid, queueid}))

	// create rules if any
	diags = append(diags, resourceAMEBindingRulesCreate(ctx, d, m)...)
	if diags.HasError() {
		return diags
	}

	return resourceAMEBindingRead(ctx, d, m)
}

func resourceAMEBindingRead(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	regionid := d.Get("region_id").(string)
	exchangeid := d.Get("exchange_id").(string)
	queueid := d.Get("queue_id").(string)
	id := d.Id()
	if isComposedResourceId(id) {
		orgid, envid, regionid, exchangeid, queueid, diags = decomposeAMEBindingId(d)
	}
	if diags.HasError() {
		return diags
	}
	authctx := getAMEBindingAuthCtx(ctx, &pco)
	//request resource
	res, httpr, err := pco.amebindingclient.DefaultApi.GetAMEBinding(authctx, orgid, envid, regionid, exchangeid, queueid).Inclusion("ALL").Execute()
	if err != nil {
		var details string
		if httpr != nil && httpr.StatusCode >= 400 {
			defer httpr.Body.Close()
			b, _ := io.ReadAll(httpr.Body)
			details = string(b)
		} else {
			details = err.Error()
		}
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to get AME Binding " + id,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	// setting resource id components for import purposes
	d.Set("org_id", orgid)
	d.Set("env_id", envid)
	d.Set("region_id", regionid)
	d.Set("exchange_id", exchangeid)
	d.Set("queue_id", queueid)
	d.SetId(ComposeResourceId([]string{orgid, envid, regionid, exchangeid, queueid}))
	//setting rules
	rules := parseAMERBindingRules(res)
	setAMEBindingRulesAttributesToResourceData(d, rules)
	return diags
}

// Updates Binding by updating the rules (only updatable )
func resourceAMEBindingUpdate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	//Updates the rules only if any change
	if d.HasChanges(getAMEBindingRulesWatchAttributes()...) {
		rules := extractAMEBindingRules(d)
		if rules == nil {
			if diags := resourceAMEBindingRulesDelete(ctx, d, m); diags.HasError() {
				return diags
			}
		} else {
			if diags := resourceAMEBindingRulesCreate(ctx, d, m); diags.HasError() {
				return diags
			}
		}
		d.Set("last_updated", time.Now().Format(time.RFC850))
		return resourceAMEBindingRead(ctx, d, m)
	}
	return diags
}

func resourceAMEBindingDelete(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	regionid := d.Get("region_id").(string)
	exchangeid := d.Get("exchange_id").(string)
	queueid := d.Get("queue_id").(string)
	authctx := getAMEBindingAuthCtx(ctx, &pco)
	//perform request
	httpr, err := pco.amebindingclient.DefaultApi.DeleteAMEBinding(authctx, orgid, envid, regionid, exchangeid, queueid).Execute()
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
			Summary:  "Unable to delete AME Binding " + d.Id(),
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	// d.SetId("") is automatically called assuming delete returns no errors, but
	// it is added here for explicitness.
	d.SetId("")

	return diags
}

func decomposeAMEBindingId(d *schema.ResourceData, separator ...string) (string, string, string, string, string, diag.Diagnostics) {
	var diags diag.Diagnostics
	s := DecomposeResourceId(d.Id(), separator...)
	if len(s) != 5 {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Invalid AME Binding ID format",
			Detail:   fmt.Sprintf("Expected ORG_ID/ENV_ID/REGION_ID/EXCHANGE_ID/QUEUE_ID, got %s", d.Id()),
		})
		return "", "", "", "", "", diags
	}
	return s[0], s[1], s[2], s[3], s[4], diags
}

func resourceAMEBindingRulesCreate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	regionid := d.Get("region_id").(string)
	exchangeid := d.Get("exchange_id").(string)
	queueid := d.Get("queue_id").(string)
	authctx := getAMEBindingAuthCtx(ctx, &pco)
	body := newAMEBindingRuleBody(d)
	if body == nil {
		return diags
	}
	//request resource creation
	_, httpr, err := pco.amebindingclient.DefaultApi.CreateAMEBindingRule(authctx, orgid, envid, regionid, exchangeid, queueid).AMEBindingRuleBody(*body).Execute()
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
			Summary:  "Unable to create AME Binding (" + exchangeid + ", " + queueid + ") Rules",
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	return diags
}

func resourceAMEBindingRulesDelete(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	regionid := d.Get("region_id").(string)
	exchangeid := d.Get("exchange_id").(string)
	queueid := d.Get("queue_id").(string)
	authctx := getAMEBindingAuthCtx(ctx, &pco)
	//request resource creation
	httpr, err := pco.amebindingclient.DefaultApi.DeleteAMEBindingRule(authctx, orgid, envid, regionid, exchangeid, queueid).Execute()
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
			Summary:  "Unable to delete AME Binding Rule " + d.Id(),
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()

	return diags
}

func newAMEBindingRuleBody(d *schema.ResourceData) *ame_binding.AMEBindingRuleBody {
	rules := extractAMEBindingRules(d)

	if rules == nil {
		return nil
	}

	body := ame_binding.NewAMEBindingRuleBody()
	list := make([]map[string]any, len(rules))

	for i, rule := range rules {
		content := rule.(map[string]any)
		item := make(map[string]any)
		item["propertyName"] = content["property_name"]
		item["propertyType"] = content["property_type"]
		item["matcherType"] = content["matcher_type"]
		item["value"] = content["value"]
		list[i] = item
	}
	body.SetRoutingRules(list)

	return body
}

func extractAMEBindingRules(d *schema.ResourceData) []any {
	var rules []any

	if rule_str_compare := d.Get("rule_str_compare").(*schema.Set); rule_str_compare.Len() > 0 {
		rules = rule_str_compare.List()
	} else if rule_str_state := d.Get("rule_str_state").(*schema.Set); rule_str_state.Len() > 0 {
		rules = rule_str_state.List()
	} else if rule_str_set := d.Get("rule_str_set").(*schema.Set); rule_str_set.Len() > 0 {
		rules = rule_str_set.List()
	} else if rule_num_compare := d.Get("rule_num_compare").(*schema.Set); rule_num_compare.Len() > 0 {
		rules = rule_num_compare.List()
	} else if rule_num_state := d.Get("rule_num_state").(*schema.Set); rule_num_state.Len() > 0 {
		rules = rule_num_state.List()
	} else if rule_num_set := d.Get("rule_num_set").(*schema.Set); rule_num_set.Len() > 0 {
		rules = rule_num_set.List()
	} else {
		rules = nil
	}
	return rules
}

// sets the binding rules to the correct type
func setAMEBindingRulesAttributesToResourceData(d *schema.ResourceData, rules []map[string]any) {
	if isRuleStrCompare(rules) {
		d.Set("rule_str_compare", rules)
	} else if isRuleStrState(rules) {
		d.Set("rule_str_state", rules)
	} else if isRuleStrSet(rules) {
		d.Set("rule_str_set", rules)
	} else if isRuleNumCompare(rules) {
		d.Set("rule_num_compare", rules)
	} else if isRuleNumState(rules) {
		d.Set("rule_num_state", rules)
	} else if isRuleNumSet(rules) {
		d.Set("rule_num_set", rules)
	}
}

func isRuleStrCompare(rules []map[string]any) bool {
	if len(rules) > 0 {
		rule := rules[0]
		return rule["propertyType"] == "STRING" && (rule["matcherType"] == "EQ" || rule["matcherType"] == "PREFIX")
	}
	return false
}
func isRuleStrState(rules []map[string]any) bool {
	if len(rules) > 0 {
		rule := rules[0]
		return rule["propertyType"] == "STRING" && rule["matcherType"] == "EXISTS"
	}
	return false
}
func isRuleStrSet(rules []map[string]any) bool {
	if len(rules) > 0 {
		rule := rules[0]
		return rule["propertyType"] == "STRING" && (rule["matcherType"] == "ANY_OF" || rule["matcherType"] == "NONE_OF")
	}
	return false
}
func isRuleNumCompare(rules []map[string]any) bool {
	if len(rules) > 0 {
		rule := rules[0]
		return rule["propertyType"] == "NUMERIC" &&
			(rule["matcherType"] == "EQ" || rule["matcherType"] == "LT" || rule["matcherType"] == "LE" || rule["matcherType"] == "GT" || rule["matcherType"] == "GE")
	}
	return false
}
func isRuleNumState(rules []map[string]any) bool {
	if len(rules) > 0 {
		rule := rules[0]
		return rule["propertyType"] == "NUMERIC" && rule["matcherType"] == "EXISTS"
	}
	return false
}
func isRuleNumSet(rules []map[string]any) bool {
	if len(rules) > 0 {
		rule := rules[0]
		return rule["propertyType"] == "NUMERIC" && (rule["matcherType"] == "RANGE" || rule["matcherType"] == "NONE_OF")
	}
	return false
}

func parseAMERBindingRules(data ame_binding.ExchangeBindingWithRules) []map[string]any {
	var rules []map[string]any
	if val, ok := data.GetRulesOk(); ok {
		rules = *val
	} else {
		return rules
	}
	result := make([]map[string]any, len(rules))

	for i, rule := range rules {
		item := make(map[string]any)
		item["property_name"] = rule["propertyName"]
		item["property_type"] = rule["propertyType"]
		item["matcher_type"] = rule["matcherType"]
		item["value"] = rule["value"]

		result[i] = item
	}

	return result
}

func getAMEBindingRulesWatchAttributes() []string {
	attributes := [...]string{
		"rule_str_compare", "rule_str_state", "rule_str_set", "rule_num_compare", "rule_num_state", "rule_num_set",
	}
	return attributes[:]
}

/*
 * Returns authentication context (includes authorization header)
 */
func getAMEBindingAuthCtx(ctx context.Context, pco *ProviderConfOutput) context.Context {
	tmp := context.WithValue(ctx, ame_binding.ContextAccessToken, pco.access_token)
	return context.WithValue(tmp, ame_binding.ContextServerIndex, pco.server_index)
}
