package anypoint

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/mulesoft-anypoint/anypoint-client-go/apim_policy"
)

// resourceApimInstancePolicy is the generic API Manager policy resource. It
// supersedes the typed `_custom` / `_basic_auth` / `_client_id_enforcement` /
// `_jwt_validation` / `_message_logging` / `_rate_limiting` resources and adds
// plan-time validation of `configuration_data` against the policy's published
// JSON Schema.
func resourceApimInstancePolicy() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceApimInstancePolicyCreate,
		ReadContext:   resourceApimInstancePolicyRead,
		UpdateContext: resourceApimInstancePolicyUpdate,
		DeleteContext: resourceApimInstancePolicyDelete,
		CustomizeDiff: resourceApimInstancePolicyCustomizeDiff,
		Description: "Creates and manages an API Manager instance policy of any type. " +
			"Replaces `anypoint_apim_policy_custom` and the per-policy-template resources. " +
			"Validates the supplied `configuration_data` against the policy template's " +
			"published JSON Schema at plan time, so configuration errors surface before " +
			"`terraform apply` instead of as opaque HTTP 400s from the API.",
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
				Description: "The policy's unique id.",
			},
			"apim_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The api manager instance id where the api instance is defined.",
			},
			"org_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The organization id where the api instance is defined.",
			},
			"env_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The environment id where the api instance is defined.",
			},
			"audit": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "The instance's auditing data.",
			},
			"master_organization_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The master organization id.",
			},
			"configuration_data": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Policy configuration data as a JSON object encoded with `jsonencode()`. Validated against the policy template's published JSON Schema at plan time when the template exposes one.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringIsJSON),
			},
			"policy_template_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The policy template id.",
			},
			"order": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The policy order.",
			},
			"disabled": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether the policy is disabled.",
			},
			"pointcut_data": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Method & resource conditions controlling where the policy applies. Ignored for outbound policies.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"method_regex": {
							Type:        schema.TypeSet,
							Required:    true,
							Description: "List of HTTP methods.",
							Elem: &schema.Schema{
								Type: schema.TypeString,
								ValidateDiagFunc: validation.ToDiagFunc(
									validation.StringInSlice(
										[]string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"},
										false,
									),
								),
							},
						},
						"uri_template_regex": {
							Type:        schema.TypeString,
							Required:    true,
							Description: "URI template regex.",
						},
					},
				},
			},
			"asset_group_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Exchange asset group id for the policy template.",
			},
			"asset_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Exchange asset id for the policy template.",
			},
			"asset_version": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Exchange asset version for the policy template. Changing this value upgrades the policy in place (no resource replacement).",
			},
			"injection_point": {
				Type:         schema.TypeString,
				Optional:     true,
				ForceNew:     true,
				Default:      "inbound",
				ValidateFunc: validation.StringInSlice([]string{"inbound", "outbound"}, false),
				Description:  "Where the policy is applied. `inbound` (default) creates via `POST .../policies`; `outbound` creates via `POST .../xapi/v1/.../policies/outbound-policies` and requires `upstream_id`. Required for credential-injection and LLM-provider policies that are outbound-only.",
			},
			"upstream_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "Identifier of the upstream this outbound policy is bound to. Required when `injection_point = \"outbound\"`. Reference an `anypoint_apim_instance_upstream.<x>.id`.",
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

// resourceApimInstancePolicyCustomizeDiff performs plan-time validation of the
// declared `configuration_data` against the policy template's JSON Schema and
// of `upstream_id` against the `injection_point` selection.
func resourceApimInstancePolicyCustomizeDiff(ctx context.Context, d *schema.ResourceDiff, m any) error {
	if m == nil {
		// Provider not configured (e.g. `terraform validate` without inputs). Skip.
		return nil
	}
	pco, ok := m.(ProviderConfOutput)
	if !ok {
		return nil
	}

	injectionPoint, _ := d.Get("injection_point").(string)
	upstreamId, _ := d.Get("upstream_id").(string)
	if injectionPoint == "outbound" && upstreamId == "" {
		// upstream_id may legitimately be Computed during create flow when the user
		// references it from another resource; only error when the diff has a
		// final empty value at apply time.
		if !d.NewValueKnown("upstream_id") {
			// unknown — defer
		} else {
			return fmt.Errorf("upstream_id is required when injection_point = \"outbound\"")
		}
	}
	if injectionPoint == "inbound" && upstreamId != "" {
		return fmt.Errorf("upstream_id must be empty when injection_point = \"inbound\"")
	}

	orgId, _ := d.Get("org_id").(string)
	assetGroupId, _ := d.Get("asset_group_id").(string)
	assetId, _ := d.Get("asset_id").(string)
	assetVersion, _ := d.Get("asset_version").(string)
	configJSON, _ := d.Get("configuration_data").(string)
	if orgId == "" || assetGroupId == "" || assetId == "" || assetVersion == "" {
		// Insufficient inputs to fetch the template — defer to apply-time errors.
		return nil
	}
	if !d.NewValueKnown("configuration_data") || !d.NewValueKnown("asset_version") {
		// Wait until values are resolvable.
		return nil
	}
	entry, diags := loadPolicyTemplateCached(ctx, &pco, orgId, assetGroupId, assetId, assetVersion)
	if diags.HasError() {
		// Surface upstream fetch issues at plan time so users see why validation
		// was skipped instead of silently allowing a known-bad config through.
		return diagToError(diags)
	}
	if entry == nil || entry.Schema == nil {
		// Legacy template with no schema — nothing to validate.
		return nil
	}
	assetCoord := assetGroupId + "/" + assetId + "/" + assetVersion
	if vdiags := validateConfigAgainstSchema(configJSON, entry.Schema, assetCoord); vdiags.HasError() {
		return diagToError(vdiags)
	}
	return nil
}

func resourceApimInstancePolicyCreate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	apimid := d.Get("apim_id").(string)
	authctx := getApimPolicyAuthCtx(ctx, &pco)
	api := pco.apimpolicyclient.DefaultAPI
	var id int32
	var httpr *http.Response
	if d.Get("injection_point").(string) == "outbound" {
		upstreamId := d.Get("upstream_id").(string)
		if upstreamId == "" {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Missing upstream_id for outbound policy on api " + apimid,
				Detail:   "When injection_point = \"outbound\", upstream_id is required and must reference an existing api instance upstream id.",
			})
			return diags
		}
		apimIdInt, err := strconv.Atoi(apimid)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Invalid apim_id for outbound policy",
				Detail:   "apim_id must be the numeric api instance id, got: " + apimid,
			})
			return diags
		}
		body, err := newApimPolicyOutboundBody(d, int32(apimIdInt), upstreamId)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to parse policy configuration for api " + apimid,
				Detail:   err.Error(),
			})
			return diags
		}
		res, hr, err := api.PostApimOutboundPolicy(authctx, orgid, envid, apimid).ApimOutboundPolicyBody(*body).Execute()
		httpr = hr
		if err != nil {
			details := extractAPIErrorDetail(err, httpr)
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to create outbound policy for api " + apimid,
				Detail:   details,
			})
			return diags
		}
		if len(res) == 0 {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Empty response creating outbound policy for api " + apimid,
				Detail:   "API returned an empty policy array — expected at least one record per upstream id.",
			})
			return diags
		}
		id = res[0].GetId()
	} else {
		body, err := newApimPolicyInboundBody(d)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to parse policy configuration for api " + apimid,
				Detail:   err.Error(),
			})
			return diags
		}
		res, hr, err := api.PostApimPolicy(authctx, orgid, envid, apimid).ApimPolicyBody(*body).Execute()
		httpr = hr
		if err != nil {
			details := extractAPIErrorDetail(err, httpr)
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to create policy for api " + apimid,
				Detail:   details,
			})
			return diags
		}
		id = res.GetId()
	}
	defer httpr.Body.Close()
	d.SetId(strconv.Itoa(int(id)))
	diags = append(diags, resourceApimInstancePolicyRead(ctx, d, m)...)
	if d.Get("disabled").(bool) {
		diags = append(diags, disableApimInstancePolicy(ctx, d, m)...)
		diags = append(diags, resourceApimInstancePolicyRead(ctx, d, m)...)
	}
	return diags
}

func resourceApimInstancePolicyRead(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	apimid := d.Get("apim_id").(string)
	id := d.Get("id").(string)
	if isComposedResourceId(id) {
		var derr diag.Diagnostics
		orgid, envid, apimid, id, derr = decomposeApimPolicyId(d)
		if derr.HasError() {
			return derr
		}
	}
	authctx := getApimPolicyAuthCtx(ctx, &pco)
	api := pco.apimpolicyclient.DefaultAPI
	res, httpr, err := api.GetApimPolicy(authctx, orgid, envid, apimid, id).Execute()
	if err != nil {
		if httpr != nil && httpr.StatusCode == http.StatusNotFound {
			d.SetId("")
			return nil
		}
		details := extractAPIErrorDetail(err, httpr)
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to read policy " + id + " for api " + apimid,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	data := flattenApimInstancePolicy(res)
	if cfg, err := flattenApimPolicyMergedCfg(d, res); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to parse configuration data of policy " + id + " for api " + apimid,
			Detail:   err.Error(),
		})
		return diags
	} else {
		data["configuration_data"] = cfg
	}
	if err := setApimInstancePolicyAttributesToResourceData(d, data); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to set api policy " + id + " details attributes",
			Detail:   err.Error(),
		})
		return diags
	}
	d.SetId(id)
	d.Set("apim_id", apimid)
	d.Set("env_id", envid)
	d.Set("org_id", orgid)
	return diags
}

func resourceApimInstancePolicyUpdate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	// Capture planned disabled value before any Read can overwrite state with API-returned value.
	plannedDisabled := d.Get("disabled").(bool)
	if d.HasChanges("configuration_data", "pointcut_data", "asset_version") {
		pco := m.(ProviderConfOutput)
		orgid := d.Get("org_id").(string)
		envid := d.Get("env_id").(string)
		apimid := d.Get("apim_id").(string)
		id := d.Get("id").(string)
		authctx := getApimPolicyAuthCtx(ctx, &pco)
		body, err := newApimPolicyPatchBody(d)
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to parse policy configuration for api " + apimid,
				Detail:   err.Error(),
			})
			return diags
		}
		api := pco.apimpolicyclient.DefaultAPI
		_, httpr, err := api.PatchApimPolicy(authctx, orgid, envid, apimid, id).Body(body).Execute()
		if err != nil {
			details := extractAPIErrorDetail(err, httpr)
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to update policy for api " + apimid,
				Detail:   details,
			})
			return diags
		}
		defer httpr.Body.Close()
		diags = append(diags, resourceApimInstancePolicyRead(ctx, d, m)...)
	}
	if d.HasChange("disabled") {
		if plannedDisabled {
			diags = append(diags, disableApimInstancePolicy(ctx, d, m)...)
		} else {
			diags = append(diags, enableApimInstancePolicy(ctx, d, m)...)
		}
		diags = append(diags, resourceApimInstancePolicyRead(ctx, d, m)...)
	}
	return diags
}

func resourceApimInstancePolicyDelete(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	apimid := d.Get("apim_id").(string)
	id := d.Get("id").(string)
	authctx := getApimPolicyAuthCtx(ctx, &pco)
	api := pco.apimpolicyclient.DefaultAPI
	httpr, err := api.DeleteApimPolicy(authctx, orgid, envid, apimid, id).Execute()
	if err != nil {
		details := extractAPIErrorDetail(err, httpr)
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to delete policy " + id + " for api " + apimid,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	d.SetId("")
	return diags
}

func enableApimInstancePolicy(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	apimid := d.Get("apim_id").(string)
	id := d.Get("id").(string)
	authctx := getApimPolicyAuthCtx(ctx, &pco)
	api := pco.apimpolicyclient.DefaultAPI
	_, httpr, err := api.EnableApimPolicy(authctx, orgid, envid, apimid, id).Execute()
	if err != nil {
		details := extractAPIErrorDetail(err, httpr)
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to enable policy " + id + " for api " + apimid,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	return diags
}

func disableApimInstancePolicy(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	apimid := d.Get("apim_id").(string)
	id := d.Get("id").(string)
	authctx := getApimPolicyAuthCtx(ctx, &pco)
	api := pco.apimpolicyclient.DefaultAPI
	_, httpr, err := api.DisableApimPolicy(authctx, orgid, envid, apimid, id).Execute()
	if err != nil {
		details := extractAPIErrorDetail(err, httpr)
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to disable policy " + id + " for api " + apimid,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	return diags
}

// flattenApimPolicyMergedCfg merges the API-returned configurationData over the
// declared one and marshals the merged map. Same fallback shape as
// flattenApimPolicyCustomCfg — keeps sensitive fields (clientId / clientSecret
// on credential-injection policies) from drifting out of state on Read.
func flattenApimPolicyMergedCfg(d *schema.ResourceData, policy *apim_policy.ApimPolicy) (string, error) {
	data := policy.GetConfigurationData()
	dst := make(map[string]any)
	if raw, ok := d.Get("configuration_data").(string); ok && raw != "" {
		if err := json.Unmarshal([]byte(raw), &dst); err != nil {
			return "", fmt.Errorf("configuration_data expected to be a valid JSON Object. %s", err.Error())
		}
	}
	maps.Copy(dst, data)
	b, err := json.Marshal(dst)
	if err != nil {
		return "", fmt.Errorf("unable to marshal merged configuration_data. %s", err.Error())
	}
	return string(b), nil
}

func newApimPolicyInboundBody(d *schema.ResourceData) (*apim_policy.ApimPolicyBody, error) {
	body := apim_policy.NewApimPolicyBody()
	if val, ok := d.GetOk("configuration_data"); ok {
		var cfg map[string]any
		if err := json.Unmarshal([]byte(val.(string)), &cfg); err != nil {
			return nil, fmt.Errorf("configuration_data expected to be a valid JSON Object. %s", err.Error())
		}
		body.SetConfigurationData(cfg)
	}
	if val, ok := d.GetOk("pointcut_data"); ok {
		body.SetPointcutData(newApimPolicyPointcutDataBody(val.([]any)))
	}
	if val, ok := d.GetOk("asset_group_id"); ok {
		body.SetGroupId(val.(string))
	}
	if val, ok := d.GetOk("asset_id"); ok {
		body.SetAssetId(val.(string))
	}
	if val, ok := d.GetOk("asset_version"); ok {
		body.SetAssetVersion(val.(string))
	}
	return body, nil
}

func newApimPolicyOutboundBody(d *schema.ResourceData, apiVersionId int32, upstreamId string) (*apim_policy.ApimOutboundPolicyBody, error) {
	body := apim_policy.NewApimOutboundPolicyBodyWithDefaults()
	if val, ok := d.GetOk("configuration_data"); ok {
		var cfg map[string]any
		if err := json.Unmarshal([]byte(val.(string)), &cfg); err != nil {
			return nil, fmt.Errorf("configuration_data expected to be a valid JSON Object. %s", err.Error())
		}
		body.SetConfigurationData(cfg)
	}
	body.SetApiVersionId(apiVersionId)
	if val, ok := d.GetOk("asset_group_id"); ok {
		body.SetGroupId(val.(string))
	}
	if val, ok := d.GetOk("asset_id"); ok {
		body.SetAssetId(val.(string))
	}
	if val, ok := d.GetOk("asset_version"); ok {
		body.SetAssetVersion(val.(string))
	}
	body.SetUpstreamIds([]string{upstreamId})
	return body, nil
}

func newApimPolicyPatchBody(d *schema.ResourceData) (map[string]any, error) {
	body := make(map[string]any)
	if val, ok := d.GetOk("configuration_data"); ok {
		var cfg map[string]any
		if err := json.Unmarshal([]byte(val.(string)), &cfg); err != nil {
			return nil, fmt.Errorf("configuration_data expected to be a valid JSON Object. %s", err.Error())
		}
		body["configurationData"] = cfg
	}
	if val, ok := d.GetOk("pointcut_data"); ok {
		collection := newApimPolicyPointcutDataBody(val.([]any))
		slice := make([]map[string]any, len(collection))
		for i, item := range collection {
			m, _ := item.ToMap()
			slice[i] = m
		}
		body["pointcutData"] = slice
	} else {
		body["pointcutData"] = nil
	}
	if val, ok := d.GetOk("asset_group_id"); ok {
		body["groupId"] = val
	}
	if val, ok := d.GetOk("asset_id"); ok {
		body["assetId"] = val
	}
	if val, ok := d.GetOk("asset_version"); ok {
		body["assetVersion"] = val
	}
	return body, nil
}

func newApimPolicyPointcutDataBody(collection []any) []apim_policy.PointcutDataItem {
	slice := make([]apim_policy.PointcutDataItem, len(collection))
	for i, item := range collection {
		data := item.(map[string]any)
		body := apim_policy.NewPointcutDataItem()
		if val, ok := data["method_regex"]; ok && val != nil {
			set := val.(*schema.Set)
			body.SetMethodRegex(JoinStringInterfaceSlice(set.List(), "|"))
		}
		if val, ok := data["uri_template_regex"]; ok {
			body.SetUriTemplateRegex(val.(string))
		}
		slice[i] = *body
	}
	return slice
}

// decomposeApimPolicyId accepts a 4-segment composite id ORG/ENV/APIM/POLICY_ID.
// Returns (orgId, envId, apimId, policyId, diags).
func decomposeApimPolicyId(d *schema.ResourceData) (string, string, string, string, diag.Diagnostics) {
	var diags diag.Diagnostics
	s := DecomposeResourceId(d.Id())
	if len(s) != 4 {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Invalid APIM Policy ID format",
			Detail:   fmt.Sprintf("Expected ORG_ID/ENV_ID/APIM_ID/POLICY_ID, got %s", d.Id()),
		})
		return "", "", "", "", diags
	}
	return s[0], s[1], s[2], s[3], diags
}

// diagToError flattens a diag.Diagnostics returned by SDK helpers into a plain
// error for use inside CustomizeDiff (which only accepts error). Concatenates
// summary + detail per diag.
func diagToError(diags diag.Diagnostics) error {
	if len(diags) == 0 {
		return nil
	}
	var parts []string
	for _, d := range diags {
		if d.Severity != diag.Error {
			continue
		}
		if d.Detail != "" {
			parts = append(parts, fmt.Sprintf("%s: %s", d.Summary, d.Detail))
		} else {
			parts = append(parts, d.Summary)
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(parts, "; "))
}
