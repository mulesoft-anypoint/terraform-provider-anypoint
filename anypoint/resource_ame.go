package anypoint

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	ame "github.com/mulesoft-anypoint/anypoint-client-go/ame"
)

func resourceAME() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceAMECreate,
		ReadContext:   resourceAMERead,
		UpdateContext: resourceAMEUpdate,
		DeleteContext: resourceAMEDelete,
		Description: `
		Creates an ` + "`" + `Anypoint MQ Exchange` + "`" + ` in your ` + "`" + `region` + "`" + `.
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
			"encrypted": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Whether to encrypt the Exchange or not.",
			},
			"type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The type of the Anypoint MQ Exchange.",
			},
		},
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func resourceAMECreate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	regionid := d.Get("region_id").(string)
	exchangeid := d.Get("exchange_id").(string)
	authctx := getAMEAuthCtx(ctx, &pco)
	body := newAMECreateBody(d)
	//request user creation
	_, httpr, err := pco.ameclient.DefaultApi.CreateAME(authctx, orgid, envid, regionid, exchangeid).ExchangeBody(*body).Execute()
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
			Summary:  "Unable to create AME " + exchangeid,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()

	d.SetId(ComposeResourceId([]string{orgid, envid, regionid, exchangeid}))

	return resourceAMERead(ctx, d, m)
}

func resourceAMERead(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	regionid := d.Get("region_id").(string)
	exchangeid := d.Get("exchange_id").(string)
	id := d.Id()
	if isComposedResourceId(id) {
		orgid, envid, regionid, exchangeid, diags = decomposeAMEId(d)
	}
	if diags.HasError() {
		return diags
	}
	authctx := getAMEAuthCtx(ctx, &pco)
	//request resource
	res, httpr, err := pco.ameclient.DefaultApi.GetAME(authctx, orgid, envid, regionid, exchangeid).Execute()
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
			Summary:  "Unable to get AME " + d.Id(),
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	//process data
	queue := flattenAMEData(&res)
	//save in data source schema
	if err := setAMEAttributesToResourceData(d, queue); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to set AME " + d.Id(),
			Detail:   err.Error(),
		})
		return diags
	}
	// setting resource id components for import purposes
	d.Set("org_id", orgid)
	d.Set("env_id", envid)
	d.Set("region_id", regionid)
	d.Set("exchange_id", exchangeid)
	d.SetId(ComposeResourceId([]string{orgid, envid, regionid, exchangeid}))

	return diags
}

func resourceAMEUpdate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	regionid := d.Get("region_id").(string)
	exchangeid := d.Get("exchange_id").(string)
	authctx := getAMEAuthCtx(ctx, &pco)
	//check for changes
	if d.HasChanges(getAMEPatchWatchAttributes()...) {
		body := newAMECreateBody(d)
		//request resource creation
		_, httpr, err := pco.ameclient.DefaultApi.UpdateAME(authctx, orgid, envid, regionid, exchangeid).ExchangeBody(*body).Execute()
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
				Summary:  "Unable to patch AME " + d.Id(),
				Detail:   details,
			})
			return diags
		}
		defer httpr.Body.Close()
		d.Set("last_updated", time.Now().Format(time.RFC850))
		return resourceAMERead(ctx, d, m)
	}
	return diags
}

func resourceAMEDelete(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	envid := d.Get("env_id").(string)
	regionid := d.Get("region_id").(string)
	exchangeid := d.Get("exchange_id").(string)
	authctx := getAMEAuthCtx(ctx, &pco)
	//perform request
	httpr, err := pco.ameclient.DefaultApi.DeleteAME(authctx, orgid, envid, regionid, exchangeid).Execute()
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
			Summary:  "Unable to delete AME " + d.Id(),
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

// Creates AME body
func newAMECreateBody(d *schema.ResourceData) *ame.ExchangeBody {
	body := new(ame.ExchangeBody)

	if encrypted := d.Get("encrypted"); encrypted != nil {
		body.SetEncrypted(encrypted.(bool))
	}

	return body
}

func decomposeAMEId(d *schema.ResourceData, separator ...string) (string, string, string, string, diag.Diagnostics) {
	var diags diag.Diagnostics
	s := DecomposeResourceId(d.Id(), separator...)
	if len(s) != 4 {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Invalid AME ID format",
			Detail:   fmt.Sprintf("Expected ORG_ID/ENV_ID/REGION_ID/EXCHANGE_ID, got %s", d.Id()),
		})
		return "", "", "", "", diags
	}
	return s[0], s[1], s[2], s[3], diags
}

/*
List of attributes that requires patching the team
*/
func getAMEPatchWatchAttributes() []string {
	attributes := [...]string{"encrypted"}
	return attributes[:]
}

/*
 * Returns authentication context (includes authorization header)
 */
func getAMEAuthCtx(ctx context.Context, pco *ProviderConfOutput) context.Context {
	tmp := context.WithValue(ctx, ame.ContextAccessToken, pco.access_token)
	return context.WithValue(tmp, ame.ContextServerIndex, pco.server_index)
}
