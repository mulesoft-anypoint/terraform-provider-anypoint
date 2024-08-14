package anypoint

import (
	"context"
	"io"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	rtf "github.com/mulesoft-anypoint/anypoint-client-go/rtf"
)

func resourceFabricsAssociations() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceFabricsAssociationsCreate,
		ReadContext:   resourceFabricsAssociationsRead,
		DeleteContext: resourceFabricsAssociationsDelete,
		Description: `
		Manages ` + "`" + `Runtime Fabrics` + "`" + ` Environment associations.
		NOTE: The fabrics will be associated with all sandbox environments in every available org when this resource is deleted.
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
				Description: "The unique id of this fabrics generated by the anypoint platform.",
			},
			"org_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The organization id where the fabrics is hosted.",
			},
			"fabrics_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The unique id of the fabrics instance in the platform.",
			},
			"associations": {
				Type:        schema.TypeSet,
				Required:    true,
				ForceNew:    true,
				MinItems:    1,
				Description: "The list of environment associations to an instance of fabrics",
				DiffSuppressFunc: func(k, old, new string, d *schema.ResourceData) bool {
					return equalFabricsAssociations(d.GetChange("associations"))
				},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The unique id of the fabrics instance in the platform.",
						},
						"org_id": {
							Type:        schema.TypeString,
							Required:    true,
							ForceNew:    true,
							Description: "The organization id to associate with fabrics.",
						},
						"env_id": {
							Type:        schema.TypeString,
							Required:    true,
							ForceNew:    true,
							Description: "The environment to associate with fabrics.",
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

func resourceFabricsAssociationsCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	fabricsid := d.Get("fabrics_id").(string)
	authctx := getFabricsAuthCtx(ctx, &pco)
	body := prepareFabricsAssociationsPostBody(d)
	//prepare request
	_, httpr, err := pco.rtfclient.DefaultApi.PostFabricsAssociations(authctx, orgid, fabricsid).FabricsAssociationsPostBody(*body).Execute()
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
			Summary:  "Unable to create fabrics " + fabricsid + " associations ",
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()

	d.SetId(ComposeResourceId([]string{orgid, fabricsid}))

	return resourceFabricsAssociationsRead(ctx, d, m)
}

func resourceFabricsAssociationsRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	fabricsid := d.Get("fabrics_id").(string)
	orgid := d.Get("org_id").(string)
	authctx := getFabricsAuthCtx(ctx, &pco)
	if isComposedResourceId(d.Id()) {
		orgid, fabricsid = decomposeFabricsAssociationsId(d)
	}
	//perform request
	res, httpr, err := pco.rtfclient.DefaultApi.GetFabricsAssociations(authctx, orgid, fabricsid).Execute()
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
			Summary:  "Unable to read fabrics " + fabricsid + " associations",
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	//process data
	list := flattenFabricsAssociationsData(res)
	//save in data source schema
	if err := d.Set("associations", list); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to set fabrics " + fabricsid + " associations",
			Detail:   err.Error(),
		})
		return diags
	}
	d.SetId(ComposeResourceId([]string{orgid, fabricsid}))
	d.Set("org_id", orgid)
	d.Set("fabrics_id", fabricsid)
	return diags
}

func resourceFabricsAssociationsDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	fabricsid := d.Get("fabrics_id").(string)
	orgid := d.Get("org_id").(string)
	authctx := getFabricsAuthCtx(ctx, &pco)
	body := prepareFabricsAssociationsDeleteBody(d)
	//perform request
	_, httpr, err := pco.rtfclient.DefaultApi.PostFabricsAssociations(authctx, orgid, fabricsid).FabricsAssociationsPostBody(*body).Execute()
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
			Summary:  "Unable to delete fabrics " + fabricsid,
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

func prepareFabricsAssociationsPostBody(d *schema.ResourceData) *rtf.FabricsAssociationsPostBody {
	body := rtf.NewFabricsAssociationsPostBody()
	associations := d.Get("associations").(*schema.Set)

	if associations.Len() == 0 {
		return nil
	}
	res := make([]rtf.FabricsAssociationsPostBodyAssociationsInner, associations.Len())
	for i, association := range associations.List() {
		parsedAssoc := association.(map[string]interface{})
		inner := rtf.NewFabricsAssociationsPostBodyAssociationsInner()
		inner.SetOrganizationId(parsedAssoc["org_id"].(string))
		inner.SetEnvironment(parsedAssoc["env_id"].(string))
		res[i] = *inner
	}

	body.SetAssociations(res)

	return body
}

func prepareFabricsAssociationsDeleteBody(_ *schema.ResourceData) *rtf.FabricsAssociationsPostBody {
	body := rtf.NewFabricsAssociationsPostBody()
	env := "sandbox"
	org := "all"
	associations := []rtf.FabricsAssociationsPostBodyAssociationsInner{
		{
			Environment:    &env,
			OrganizationId: &org,
		},
	}
	body.SetAssociations(associations)
	return body
}

func decomposeFabricsAssociationsId(d *schema.ResourceData) (string, string) {
	s := DecomposeResourceId(d.Id())
	return s[0], s[1]
}

func equalFabricsAssociations(old, new interface{}) bool {
	old_set := old.(*schema.Set)
	old_list := old_set.List()
	new_set := new.(*schema.Set)
	new_list := new_set.List()
	//sort lists
	sortAttr := []string{"org_id", "env_id"}
	SortMapListAl(new_list, sortAttr)
	SortMapListAl(old_list, sortAttr)
	if len(new_list) != len(old_list) {
		return false
	}
	for i, val := range old_list {
		o := val.(map[string]interface{})
		n := new_list[i].(map[string]interface{})
		if n["org_id"].(string) != o["org_id"].(string) || n["env_id"].(string) != o["env_id"].(string) {
			return false
		}
	}
	return true
}