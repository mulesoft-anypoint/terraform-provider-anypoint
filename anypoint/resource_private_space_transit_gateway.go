package anypoint

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	private_space "github.com/mulesoft-anypoint/anypoint-client-go/private_space"
)

func resourcePrivateSpaceTransitGateway() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourcePrivateSpaceTransitGatewayCreate,
		ReadContext:   resourcePrivateSpaceTransitGatewayRead,
		UpdateContext: resourcePrivateSpaceTransitGatewayUpdate,
		DeleteContext: resourcePrivateSpaceTransitGatewayDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(30 * time.Minute),
		},
		Description: "Manages an AWS Transit Gateway attachment on an Anypoint CloudHub 2.0 private space. " +
			"Two modes: create mode (`name`, `resource_share_id`, `resource_share_account`) creates the transit gateway connection from a RAM resource share owned by your AWS account, " +
			"with the MuleSoft AWS account whitelisted as principal and the TGW associated with the share; " +
			"attach mode (`transit_gateway_id`) attaches an existing organization transit gateway, for example the one created by another resource, to this private space. " +
			"Deleting the resource only detaches the private space: the organization transit gateway stays listed after its last detach; " +
			"per the Anypoint UI, delete the RAM resource share in AWS to remove it from the organization. " +
			"Create mode re-attaches an organization transit gateway left by an earlier detach when no other private space uses it. " +
			"Two create-mode resources on one resource share are an error: give the second one `transit_gateway_id` instead. " +
			"Replacing a create-mode resource replaces the attach-mode resources that reference its `transit_gateway_id`. " +
			"`create_before_destroy` on create-mode resources across private spaces is not supported; use attach mode. " +
			"An existing create-mode resource moves to attach mode without replacement: set `transit_gateway_id` to its current value and remove `name`, `resource_share_id` and `resource_share_account`.",
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Composite id ORG_ID/PRIVATE_SPACE_ID/TRANSIT_GATEWAY_ID.",
			},
			"last_updated": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The last time this resource has been updated locally.",
			},
			"org_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The organization id where the private space lives.",
			},
			"private_space_id": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The private space id.",
			},
			"transit_gateway_id": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
				ForceNew: true,
				Description: "The AWS transit gateway id (e.g. tgw-...). Set it to attach an existing organization transit gateway " +
					"(for example another resource's `transit_gateway_id`) to this private space; leave it unset to create the transit gateway connection from a RAM resource share.",
				ExactlyOneOf:     []string{"transit_gateway_id", "resource_share_id"},
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringMatch(regexp.MustCompile("^tgw-[0-9a-f]+$"), "must look like tgw-...")),
			},
			"name": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				Description:   "Display name of the transit gateway attachment. Create mode only: in attach mode the name belongs to the resource that created the transit gateway and is read back.",
				ConflictsWith: []string{"transit_gateway_id"},
			},
			"resource_share_id": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				ForceNew:     true,
				Description:  "RAM resource share UUID (trailing GUID of the ARN, NOT the full ARN). Create mode only; requires `resource_share_account` and `name`.",
				ExactlyOneOf: []string{"transit_gateway_id", "resource_share_id"},
				RequiredWith: []string{"resource_share_account", "name"},
			},
			"resource_share_account": {
				Type:          schema.TypeString,
				Optional:      true,
				Computed:      true,
				ForceNew:      true,
				Description:   "AWS account id that owns the RAM share (your AWS account, NOT MuleSoft's). Create mode only.",
				ConflictsWith: []string{"transit_gateway_id"},
			},
			"routes": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "Static routes (CIDR strings) pushed into the private space route table. Must not equal or be more specific than the private space CIDR.",
				Elem: &schema.Schema{
					Type:             schema.TypeString,
					ValidateDiagFunc: validation.ToDiagFunc(validation.IsCIDR),
				},
			},
			"account_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "MuleSoft AWS account id, region-bound to the private space.",
			},
			"region": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS region (inherits the private space region).",
			},
			"space_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Private space display name.",
			},
			"status_gateway": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Gateway status (refreshing, available, ...).",
			},
			"status_attachment": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Attachment status (refreshing, available, ...).",
			},
			"tgw_resource_url": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "AWS console URL of the transit gateway.",
			},
		},
	}
}

func resourcePrivateSpaceTransitGatewayCreate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	psid := d.Get("private_space_id").(string)
	summary := "Unable to create transit gateway for private space " + psid

	// The SDK skips unknown values in ConflictsWith / ExactlyOneOf, so a
	// transit_gateway_id that was unknown at plan time can arrive here
	// together with create-mode attributes. At apply the raw config is known.
	attach, tgwID, conflicting := tgwModeFromRawConfig(d.GetRawConfig())
	if d.GetRawConfig().IsNull() {
		tgwID = d.Get("transit_gateway_id").(string)
		attach = tgwID != ""
	}
	if attach && len(conflicting) > 0 {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  summary,
			Detail: "transit_gateway_id cannot be combined with name, resource_share_id or resource_share_account (set: " +
				strings.Join(conflicting, ", ") + ").",
		}}
	}
	// Defensive: the raw config is known at apply, so an unknown id here
	// would be an SDK change.
	if attach && tgwID == "" {
		tgwID = d.Get("transit_gateway_id").(string)
		if tgwID == "" {
			return diag.Diagnostics{{
				Severity: diag.Error,
				Summary:  summary,
				Detail:   "transit_gateway_id is unknown at apply time.",
			}}
		}
	}

	lock, err := acquireTGWOrgLock(ctx, orgid)
	if err != nil {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  summary,
			Detail:   "Gave up waiting for another transit gateway create in organization " + orgid + ": " + err.Error(),
		}}
	}
	defer lock.Unlock()

	if attach {
		return createTGWAttachMode(ctx, d, &pco, orgid, psid, tgwID)
	}
	return createTGWCreateMode(ctx, d, &pco, orgid, psid, lock)
}

// createTGWAttachMode attaches the existing organization transit gateway
// tgwID to the private space. The caller holds the org lock.
func createTGWAttachMode(ctx context.Context, d *schema.ResourceData, pco *ProviderConfOutput, org, ps, tgwID string) diag.Diagnostics {
	list, httpr, err := attachTGWWithRetry(ctx, pco, org, ps, tgwID, tgwRoutes(d))
	if err != nil {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  "Unable to attach transit gateway " + tgwID + " to private space " + ps,
			Detail:   extractAPIErrorDetail(err, httpr),
		}}
	}
	defer httpr.Body.Close()
	d.SetId(ComposeResourceId([]string{org, ps, tgwID}))
	return tgwStateFromResponseDiags(d, list, tgwID)
}

// createTGWCreateMode creates the transit gateway connection from the RAM
// share and, when the share is already known to the organization, falls back
// to rescueTGWAttach. The caller holds lock.
func createTGWCreateMode(ctx context.Context, d *schema.ResourceData, pco *ProviderConfOutput, org, ps string, lock *tgwOrgLock) diag.Diagnostics {
	authctx := getPrivateSpaceAuthCtx(ctx, pco)
	share := d.Get("resource_share_id").(string)
	body := newPrivateSpaceTransitGatewayPostBody(d)
	res, httpr, err := pco.privatespaceclient.DefaultAPI.CreatePrivateSpaceTransitGateway(authctx, org, ps).TransitGatewayPostBody(*body).Execute()
	if err != nil {
		createErr := diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to create transit gateway for private space " + ps,
			Detail:   extractAPIErrorDetail(err, httpr),
		}
		if httpr == nil || httpr.StatusCode != http.StatusBadRequest {
			return diag.Diagnostics{createErr}
		}
		diags, attached := rescueTGWAttach(ctx, d, pco, org, ps, createErr)
		if attached {
			lock.Claim(share, d.Id())
		}
		return diags
	}
	defer httpr.Body.Close()
	tgwID := res.GetId()
	d.SetId(ComposeResourceId([]string{org, ps, tgwID}))
	lock.Claim(share, d.Id())
	return tgwStateFromResponseDiags(d, []private_space.TransitGateway{*res}, tgwID)
}

// rescueTGWAttach handles a 400 on the create POST. When the organization
// already holds a transit gateway for this resource share and no private
// space has a live attachment to it, it attaches that transit gateway with
// this resource's routes and takes over its name. attached reports whether
// the id was set. The caller holds the org lock.
func rescueTGWAttach(ctx context.Context, d *schema.ResourceData, pco *ProviderConfOutput, org, ps string, createErr diag.Diagnostic) (diag.Diagnostics, bool) {
	authctx := getPrivateSpaceAuthCtx(ctx, pco)
	share := d.Get("resource_share_id").(string)
	account := d.Get("resource_share_account").(string)
	name := d.Get("name").(string)
	withDetail := func(extra string) diag.Diagnostics {
		e := createErr
		e.Detail = extra + "\n\nOriginal error: " + createErr.Detail
		return diag.Diagnostics{e}
	}

	entry, ok := lookupOrgTGWByShare(authctx, pco, org, share)
	// Another resource of this apply owns the share. The org list is
	// eventually consistent and may not list it yet, so the claim alone
	// decides; its owner id ORG/PS/TGW names the transit gateway.
	claimOwner, claimed := tgwOrgLockFor(org).ClaimOwner(share)
	if !ok {
		if parts := DecomposeResourceId(claimOwner); claimed && len(parts) == 3 {
			return withDetail(tgwShareClaimedHint(parts[2], "", ps)), false
		}
		return diag.Diagnostics{createErr}, false
	}
	tgwID := entry.GetId()

	if len(tgwLiveAttachments(entry)) > 0 {
		if tgwAttachedToSpace(authctx, pco, org, ps, tgwID) {
			return withDetail(fmt.Sprintf(
				"Transit gateway %s is already attached to private space %s. Import it instead: terraform import <resource address> %s",
				tgwID, ps, ComposeResourceId([]string{org, ps, tgwID}),
			)), false
		}
		return withDetail(tgwShareConflictHint(entry, ps)), false
	}
	if claimed {
		return withDetail(tgwShareClaimedHint(tgwID, entry.GetName(), ps)), false
	}
	shareSpec := entry.GetSpec()
	shareRef := shareSpec.GetResourceShare()
	if got := shareRef.GetAccount(); got != account {
		return diag.Diagnostics{{
			Severity: diag.Error,
			Summary:  createErr.Summary,
			Detail: createErr.Detail + fmt.Sprintf(
				"\n\nTransit gateway %s uses this resource share with account %q, but resource_share_account is %q. "+
					"Set resource_share_account to the account that owns the share.",
				tgwID, got, account,
			),
		}}, false
	}

	// Detached attachments flicker in the org list: only attach when two
	// reads some seconds apart agree that nothing is live.
	select {
	case <-ctx.Done():
		return diag.Diagnostics{createErr}, false
	case <-time.After(tgwRescueRecheckDelay):
	}
	again, ok := lookupOrgTGWByShare(authctx, pco, org, share)
	if !ok || again.GetId() != tgwID {
		return diag.Diagnostics{createErr}, false
	}
	if len(tgwLiveAttachments(again)) > 0 {
		return withDetail(tgwShareConflictHint(again, ps)), false
	}

	list, httpr, err := attachTGWWithRetry(ctx, pco, org, ps, tgwID, tgwRoutes(d))
	if err != nil {
		return diag.Diagnostics{createErr, {
			Severity: diag.Error,
			Summary:  "Unable to attach transit gateway " + tgwID + " to private space " + ps,
			Detail:   extractAPIErrorDetail(err, httpr),
		}}, false
	}
	defer httpr.Body.Close()
	log.Printf("[INFO] re-attached organization transit gateway %s to private space %s", tgwID, ps)
	d.SetId(ComposeResourceId([]string{org, ps, tgwID}))
	diags := tgwStateFromResponseDiags(d, list, tgwID)

	if again.GetName() != name {
		if pd := patchTGWNameWithRetry(ctx, pco, org, tgwID, name); pd != nil {
			pd.Severity = diag.Warning
			pd.Detail += " The transit gateway is attached; the next plan shows an in-place name update that retries it."
			return append(diags, *pd), true
		}
		if err := d.Set("name", name); err != nil {
			diags = append(diags, diag.Diagnostic{Severity: diag.Warning, Summary: "Unable to set name for transit gateway " + tgwID, Detail: err.Error()})
		}
	}
	return diags, true
}

// lookupOrgTGWByShare reads the organization transit gateways and returns the
// one using share. A failed read counts as no match.
func lookupOrgTGWByShare(authctx context.Context, pco *ProviderConfOutput, org, share string) (private_space.TransitGateway, bool) {
	list, httpr, err := pco.privatespaceclient.DefaultAPI.GetOrgTransitGateways(authctx, org).Execute()
	if err != nil {
		log.Printf("[WARN] unable to list organization transit gateways of %s: %s", org, extractAPIErrorDetail(err, httpr))
		return private_space.TransitGateway{}, false
	}
	defer httpr.Body.Close()
	return findOrgTGWByShare(list, share)
}

// tgwAttachedToSpace reports whether the private space lists tgwID with an
// attachment that is not detached. A failed read counts as not attached.
func tgwAttachedToSpace(authctx context.Context, pco *ProviderConfOutput, org, ps, tgwID string) bool {
	list, httpr, err := pco.privatespaceclient.DefaultAPI.GetPrivateSpaceTransitGateways(authctx, org, ps).Execute()
	if err != nil {
		log.Printf("[WARN] unable to list transit gateways of private space %s: %s", ps, extractAPIErrorDetail(err, httpr))
		return false
	}
	defer httpr.Body.Close()
	for _, tgw := range list {
		status := tgw.GetStatus()
		if tgw.GetId() == tgwID && status.GetAttachment() != "detached" {
			return true
		}
	}
	return false
}

// attachTGWWithRetry posts the attach request, retrying 403/409 "not ready"
// answers with exponential backoff within tgwAttachRetryBudget and ctx.
func attachTGWWithRetry(ctx context.Context, pco *ProviderConfOutput, org, ps, tgwID string, routes []string) ([]private_space.TransitGateway, *http.Response, error) {
	authctx := getPrivateSpaceAuthCtx(ctx, pco)
	deadline := time.Now().Add(tgwAttachRetryBudget)
	delay := tgwAttachRetryBase
	for {
		list, httpr, err := pco.privatespaceclient.DefaultAPI.AttachPrivateSpaceTransitGateway(authctx, org, ps, tgwID).RequestBody(routes).Execute()
		if err == nil || !tgwNotReady(httpr) || time.Now().Add(delay).After(deadline) {
			return list, httpr, err
		}
		log.Printf("[WARN] attach of transit gateway %s to private space %s answered %s; retrying in %s", tgwID, ps, extractAPIErrorDetail(err, httpr), delay)
		select {
		case <-ctx.Done():
			return list, httpr, err
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// patchTGWNameWithRetry renames the organization transit gateway, retrying
// 403/409 up to three attempts. It returns the error diagnostic of the last
// attempt, or nil on success.
func patchTGWNameWithRetry(ctx context.Context, pco *ProviderConfOutput, org, tgwID, name string) *diag.Diagnostic {
	authctx := getPrivateSpaceAuthCtx(ctx, pco)
	body := private_space.NewTransitGatewayPatchNameBody(name)
	const attempts = 3
	for i := 1; ; i++ {
		_, httpr, err := pco.privatespaceclient.DefaultAPI.UpdateOrgTransitGatewayName(authctx, org, tgwID).TransitGatewayPatchNameBody(*body).Execute()
		if err == nil {
			defer httpr.Body.Close()
			return nil
		}
		failed := &diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to update name for transit gateway " + tgwID,
			Detail:   extractAPIErrorDetail(err, httpr),
		}
		if i == attempts || !tgwNotReady(httpr) {
			return failed
		}
		select {
		case <-ctx.Done():
			return failed
		case <-time.After(tgwAttachRetryBase):
		}
	}
}

func tgwNotReady(httpr *http.Response) bool {
	return httpr != nil && (httpr.StatusCode == http.StatusForbidden || httpr.StatusCode == http.StatusConflict)
}

func tgwRoutes(d *schema.ResourceData) []string {
	return ListInterface2ListStrings(d.Get("routes").(*schema.Set).List())
}

// setTGWStateFromResponse writes the attributes of tgwID from a create or
// attach response, so that Create does not depend on the per-space list
// being read-your-writes.
func setTGWStateFromResponse(d *schema.ResourceData, list []private_space.TransitGateway, tgwID string) error {
	if err := d.Set("transit_gateway_id", tgwID); err != nil {
		return err
	}
	for i := range list {
		if list[i].GetId() == tgwID {
			return setPrivateSpaceTransitGatewayAttrs(d, &list[i])
		}
	}
	return fmt.Errorf("transit gateway %s missing from the response; attributes are refreshed on the next plan", tgwID)
}

// tgwStateFromResponseDiags wraps setTGWStateFromResponse: the object exists,
// so a failure is only a warning and the id is kept.
func tgwStateFromResponseDiags(d *schema.ResourceData, list []private_space.TransitGateway, tgwID string) diag.Diagnostics {
	if err := setTGWStateFromResponse(d, list, tgwID); err != nil {
		return diag.Diagnostics{{
			Severity: diag.Warning,
			Summary:  "Unable to read transit gateway " + tgwID + " after create",
			Detail:   err.Error(),
		}}
	}
	return nil
}

func resourcePrivateSpaceTransitGatewayRead(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid, psid, tgwid, derr := splitPrivateSpaceTransitGatewayId(d)
	if derr.HasError() {
		return derr
	}
	authctx := getPrivateSpaceAuthCtx(ctx, &pco)
	list, httpr, err := pco.privatespaceclient.DefaultAPI.GetPrivateSpaceTransitGateways(authctx, orgid, psid).Execute()
	if err != nil {
		if httpr != nil && httpr.StatusCode == 404 {
			d.SetId("")
			return nil
		}
		details := extractAPIErrorDetail(err, httpr)
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to Read transit gateway " + tgwid + " for private space " + psid,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	var found *private_space.TransitGateway
	for i := range list {
		if list[i].GetId() == tgwid {
			found = &list[i]
			break
		}
	}
	if found == nil {
		d.SetId("")
		return diags
	}
	if err := setPrivateSpaceTransitGatewayAttrs(d, found); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to set transit gateway attributes for " + tgwid,
			Detail:   err.Error(),
		})
		return diags
	}
	d.Set("org_id", orgid)
	d.Set("private_space_id", psid)
	d.Set("transit_gateway_id", tgwid)
	return diags
}

func resourcePrivateSpaceTransitGatewayUpdate(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid, psid, tgwid, derr := splitPrivateSpaceTransitGatewayId(d)
	if derr.HasError() {
		return derr
	}
	authctx := getPrivateSpaceAuthCtx(ctx, &pco)
	if d.HasChange("routes") {
		body := private_space.NewTransitGatewayPatchRoutesBody(ListInterface2ListStrings(d.Get("routes").(*schema.Set).List()))
		_, httpr, err := pco.privatespaceclient.DefaultAPI.UpdatePrivateSpaceTransitGatewayRoutes(authctx, orgid, psid, tgwid).TransitGatewayPatchRoutesBody(*body).Execute()
		if err != nil {
			details := extractAPIErrorDetail(err, httpr)
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to Update routes for transit gateway " + tgwid,
				Detail:   details,
			})
			return diags
		}
		defer httpr.Body.Close()
	}
	// In attach mode the org-level name belongs to the creating resource.
	attach, _, _ := tgwModeFromRawConfig(d.GetRawConfig())
	if d.HasChange("name") && attach {
		log.Printf("[DEBUG] transit gateway %s is in attach mode; not renaming it", tgwid)
	}
	if d.HasChange("name") && !attach {
		body := private_space.NewTransitGatewayPatchNameBody(d.Get("name").(string))
		_, httpr, err := pco.privatespaceclient.DefaultAPI.UpdateOrgTransitGatewayName(authctx, orgid, tgwid).TransitGatewayPatchNameBody(*body).Execute()
		if err != nil {
			details := extractAPIErrorDetail(err, httpr)
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to Update name for transit gateway " + tgwid,
				Detail:   details,
			})
			return diags
		}
		defer httpr.Body.Close()
	}
	d.Set("last_updated", time.Now().Format(time.RFC850))
	return resourcePrivateSpaceTransitGatewayRead(ctx, d, m)
}

func resourcePrivateSpaceTransitGatewayDelete(ctx context.Context, d *schema.ResourceData, m any) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid, psid, tgwid, derr := splitPrivateSpaceTransitGatewayId(d)
	if derr.HasError() {
		return derr
	}
	authctx := getPrivateSpaceAuthCtx(ctx, &pco)
	httpr, err := pco.privatespaceclient.DefaultAPI.DeletePrivateSpaceTransitGateway(authctx, orgid, psid, tgwid).Execute()
	if err != nil {
		details := extractAPIErrorDetail(err, httpr)
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to Delete transit gateway " + tgwid + " for private space " + psid,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	if share, ok := d.Get("resource_share_id").(string); ok && share != "" {
		tgwOrgLockFor(orgid).Release(share, d.Id())
	}
	d.SetId("")
	return diags
}

func newPrivateSpaceTransitGatewayPostBody(d *schema.ResourceData) *private_space.TransitGatewayPostBody {
	return private_space.NewTransitGatewayPostBody(
		d.Get("name").(string),
		d.Get("resource_share_id").(string),
		d.Get("resource_share_account").(string),
		ListInterface2ListStrings(d.Get("routes").(*schema.Set).List()),
	)
}

func setPrivateSpaceTransitGatewayAttrs(d *schema.ResourceData, tgw *private_space.TransitGateway) error {
	if err := d.Set("name", tgw.GetName()); err != nil {
		return err
	}
	if err := d.Set("account_id", tgw.GetAccountId()); err != nil {
		return err
	}
	spec := tgw.GetSpec()
	if err := d.Set("region", spec.GetRegion()); err != nil {
		return err
	}
	if err := d.Set("space_name", spec.GetSpaceName()); err != nil {
		return err
	}
	share := spec.GetResourceShare()
	if err := d.Set("resource_share_id", share.GetId()); err != nil {
		return err
	}
	if err := d.Set("resource_share_account", share.GetAccount()); err != nil {
		return err
	}
	status := tgw.GetStatus()
	if err := d.Set("status_gateway", status.GetGateway()); err != nil {
		return err
	}
	if err := d.Set("status_attachment", status.GetAttachment()); err != nil {
		return err
	}
	if err := d.Set("tgw_resource_url", status.GetTgwResource()); err != nil {
		return err
	}
	if err := d.Set("routes", status.GetRoutes()); err != nil {
		return err
	}
	return nil
}

func splitPrivateSpaceTransitGatewayId(d *schema.ResourceData) (string, string, string, diag.Diagnostics) {
	var diags diag.Diagnostics
	s := DecomposeResourceId(d.Id())
	if len(s) != 3 {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Invalid transit gateway resource id",
			Detail:   fmt.Sprintf("Expected ORG_ID/PRIVATE_SPACE_ID/TRANSIT_GATEWAY_ID, got %s", d.Id()),
		})
		return "", "", "", diags
	}
	return s[0], s[1], s[2], diags
}

// Test seams for the create-mode rescue and the attach retry.
var (
	tgwRescueRecheckDelay = 3 * time.Second
	tgwAttachRetryBudget  = 5 * time.Minute
	tgwAttachRetryBase    = 5 * time.Second
)
