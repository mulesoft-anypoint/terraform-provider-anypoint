package anypoint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/mulesoft-anypoint/anypoint-client-go/user"
)

func dataSourceUser() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceUserRead,
		Description: `
		Reads a specific ` + "`" + `user` + "`" + ` in the business group.
		`,
		Schema: map[string]*schema.Schema{
			"org_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The master organization id where the user is defined.",
			},
			"id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The unique id of this user generated by the anypoint platform.",
			},
			"organization_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The master organization id where the user is defined.",
			},
			"first_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The firstname of this user.",
			},
			"last_name": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The lastname of this user.",
			},
			"email": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The email of this user.",
			},
			"phone_number": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The phone number of this user.",
			},
			"username": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The username of this user.",
			},
			"idprovider_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The identity provider id",
			},
			"enabled": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether this user is enabled",
			},
			"deleted": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether this user is deleted",
			},
			"created_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The time when the user was created.",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The last time this user was updated.",
			},
			"last_login": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The last time this user logged in.",
			},
			"mfa_verifiers_configured": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The MFA configured for this user.",
			},
			"mfa_verification_excluded": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether MFA verification is excluded for this user",
			},
			"is_federated": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Whether this user is federated.",
			},
			"type": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The type of user.",
			},
			"organization_preferences": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "The preferences of the user within the organization.",
			},
			"member_of_organizations": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeMap,
				},
				Description: "The user's list of organizations membership",
			},
			"contributor_of_organizations": {
				Type:     schema.TypeSet,
				Computed: true,
				Elem: &schema.Schema{
					Type: schema.TypeMap,
				},
				Description: "The list of organizations this user has contributed to.",
			},
			"organization": {
				Type:        schema.TypeMap,
				Computed:    true,
				Description: "The organization information",
			},
			"properties": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The user's properties.",
			},
		},
	}
}

func dataSourceUserRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	pco := m.(ProviderConfOutput)
	orgid := d.Get("org_id").(string)
	userid := d.Get("id").(string)
	authctx := getUserAuthCtx(ctx, &pco)
	//request roles
	res, httpr, err := pco.userclient.DefaultApi.OrganizationsOrgIdUsersUserIdGet(authctx, orgid, userid).Execute()
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
			Summary:  "Unable to get user " + userid,
			Detail:   details,
		})
		return diags
	}
	defer httpr.Body.Close()
	//process data
	user := flattenUserData(&res)
	//save in data source schema
	if err := setUserAttributesToResourceData(d, user); err != nil {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to set user " + userid,
			Detail:   err.Error(),
		})
		return diags
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))

	return diags
}

/*
Transforms a set of users to the dataSourceUsers schema
*/
func flattenUserData(usr *user.User) map[string]interface{} {
	res := make(map[string]interface{})
	if usr == nil {
		return res
	}

	if val, ok := usr.GetIdOk(); ok {
		res["id"] = *val
	}
	if val, ok := usr.GetCreatedAtOk(); ok {
		res["created_at"] = *val
	}
	if val, ok := usr.GetUpdatedAtOk(); ok {
		res["updated_at"] = *val
	}
	if val, ok := usr.GetOrganizationIdOk(); ok {
		res["organization_id"] = *val
	}
	if val, ok := usr.GetPhoneNumberOk(); ok {
		res["phone_number"] = *val
	}
	if val, ok := usr.GetEnabledOk(); ok {
		res["enabled"] = *val
	}
	if val, ok := usr.GetDeletedOk(); ok {
		res["deleted"] = *val
	}
	if val, ok := usr.GetIdproviderIdOk(); ok {
		res["idprovider_id"] = *val
	}
	if val, ok := usr.GetLastLoginOk(); ok {
		res["last_login"] = *val
	}
	if val, ok := usr.GetIsFederatedOk(); ok {
		res["is_federated"] = *val
	}
	if val, ok := usr.GetUsernameOk(); ok {
		res["username"] = *val
	}
	if val, ok := usr.GetTypeOk(); ok {
		res["type"] = *val
	}
	if val, ok := usr.GetMfaVerifiersConfiguredOk(); ok {
		res["mfa_verifiers_configured"] = *val
	}
	if val, ok := usr.GetMfaVerificationExcludedOk(); ok {
		res["mfa_verification_excluded"] = *val
	}
	if val, ok := usr.GetOrganizationOk(); ok {
		usrOrgData := val
		res["organization"] = flattenUserOrganizationData(usrOrgData)
	}
	if val, ok := usr.GetOrganizationPreferencesOk(); ok {
		res["organization_preferences"] = *val
	}
	if val, ok := usr.GetPropertiesOk(); ok {
		jsonProps, _ := json.Marshal(val)
		res["properties"] = string(jsonProps)
	}
	if val, ok := usr.GetMemberOfOrganizationsOk(); ok {
		res["member_of_organizations"] = flattenUserOrgsData(val)
	}
	if val, ok := usr.GetContributorOfOrganizationsOk(); ok {
		res["contributor_of_organizations"] = flattenUserOrgsData(val)
	}

	return res
}

/*
 * Transforms a user organization array to a generic map array
 */
func flattenUserOrgsData(userOrgs *[]user.Org) []map[string]interface{} {
	if userOrgs == nil || len(*userOrgs) <= 0 {
		return make([]map[string]interface{}, 0)
	}
	res := make([]map[string]interface{}, len(*userOrgs))

	for i, usrOrgData := range *userOrgs {
		res[i] = flattenUserOrgData(&usrOrgData)
	}

	return res
}

/*
 * Transforms a user org data to generic map
 */
func flattenUserOrgData(usrOrgData *user.Org) map[string]interface{} {
	item := make(map[string]interface{})
	if usrOrgData == nil {
		return item
	}

	if val, ok := usrOrgData.GetParentNameOk(); ok {
		item["parent_name"] = val
	}
	if val, ok := usrOrgData.GetParentIdOk(); ok {
		item["parent_id"] = val
	}
	if val, ok := usrOrgData.GetDomainOk(); ok {
		item["domain"] = val
	}
	if val, ok := usrOrgData.GetNameOk(); ok {
		item["name"] = val
	}
	if val, ok := usrOrgData.GetIdOk(); ok {
		item["id"] = val
	}
	if val, ok := usrOrgData.GetCreatedAtOk(); ok {
		item["created_at"] = val
	}
	if val, ok := usrOrgData.GetUpdatedAtOk(); ok {
		item["updated_at"] = val
	}
	if val, ok := usrOrgData.GetOwnerIdOk(); ok {
		item["owner_id"] = val
	}
	if val, ok := usrOrgData.GetClientIdOk(); ok {
		item["client_id"] = val
	}
	if val, ok := usrOrgData.GetIdproviderIdOk(); ok {
		item["idprovider_id"] = val
	}
	if val, ok := usrOrgData.GetIsFederatedOk(); ok {
		item["is_federated"] = strconv.FormatBool(*val)
	}
	if val, ok := usrOrgData.GetParentOrganizationIdsOk(); ok {
		jsonParentOrgs, _ := json.Marshal(val)
		item["parent_organization_ids"] = string(jsonParentOrgs)
	}
	if val, ok := usrOrgData.GetSubOrganizationIdsOk(); ok {
		jsonSubOrgIds, _ := json.Marshal(val)
		item["sub_organization_ids"] = string(jsonSubOrgIds)
	}
	if val, ok := usrOrgData.GetTenantOrganizationIdsOk(); ok {
		jsonTenantOrgIds, _ := json.Marshal(val)
		item["tenant_organization_ids"] = string(jsonTenantOrgIds)
	}
	if val, ok := usrOrgData.GetMfaRequiredOk(); ok {
		item["mfa_required"] = val
	}
	if val, ok := usrOrgData.GetIsAutomaticAdminPromotionExemptOk(); ok {
		item["is_automatic_admin_promotion_exempt"] = strconv.FormatBool(*val)
	}
	if val, ok := usrOrgData.GetIsMasterOk(); ok {
		item["is_master"] = strconv.FormatBool(*val)
	}
	if val, ok := usrOrgData.GetSubscriptionOk(); ok {
		jsonSub, _ := json.Marshal(val)
		item["subscription"] = string(jsonSub)
	}

	return item
}

/*
 * Transforms a user organization to a generic map
 */
func flattenUserOrganizationData(usrOrgData *user.Organization) map[string]interface{} {
	if usrOrgData == nil {
		return nil
	}
	res := make(map[string]interface{})

	if val, ok := usrOrgData.GetNameOk(); ok {
		res["name"] = val
	}
	if val, ok := usrOrgData.GetIdOk(); ok {
		res["id"] = val
	}
	if val, ok := usrOrgData.GetCreatedAtOk(); ok {
		res["created_at"] = val
	}
	if val, ok := usrOrgData.GetUpdatedAtOk(); ok {
		res["updated_at"] = val
	}
	if val, ok := usrOrgData.GetOwnerIdOk(); ok {
		res["owner_id"] = val
	}
	if val, ok := usrOrgData.GetClientIdOk(); ok {
		res["client_id"] = val
	}
	if val, ok := usrOrgData.GetIdproviderIdOk(); ok {
		res["idprovider_id"] = val
	}
	if val, ok := usrOrgData.GetIsFederatedOk(); ok {
		res["is_federated"] = strconv.FormatBool(*val)
	}
	if val, ok := usrOrgData.GetParentOrganizationIdsOk(); ok {
		jsonParentOrgs, _ := json.Marshal(val)
		res["parent_organization_ids"] = string(jsonParentOrgs)
	}
	if val, ok := usrOrgData.GetSubOrganizationIdsOk(); ok {
		jsonSubOrgIds, _ := json.Marshal(val)
		res["sub_organization_ids"] = string(jsonSubOrgIds)
	}
	if val, ok := usrOrgData.GetTenantOrganizationIdsOk(); ok {
		jsonTenantOrgIds, _ := json.Marshal(val)
		res["tenant_organization_ids"] = string(jsonTenantOrgIds)
	}
	if val, ok := usrOrgData.GetMfaRequiredOk(); ok {
		res["mfa_required"] = val
	}
	if val, ok := usrOrgData.GetIsAutomaticAdminPromotionExemptOk(); ok {
		res["is_automatic_admin_promotion_exempt"] = strconv.FormatBool(*val)
	}
	if val, ok := usrOrgData.GetDomainOk(); ok {
		res["domain"] = val
	}
	if val, ok := usrOrgData.GetIsMasterOk(); ok {
		res["is_master"] = strconv.FormatBool(*val)
	}
	if val, ok := usrOrgData.GetSubscriptionOk(); ok {
		jsonSub, _ := json.Marshal(val)
		res["subscription"] = string(jsonSub)
	}
	if val, ok := usrOrgData.GetPropertiesOk(); ok {
		jsonProps, _ := json.Marshal(val)
		res["properties"] = string(jsonProps)
	}
	if val, ok := usrOrgData.GetEntitlementsOk(); ok {
		jsonEntitlments, _ := json.Marshal(val)
		res["entitlements"] = string(jsonEntitlments)
	}

	return res
}

/*
 * Copies the given user instance into the given Source data
 */
func setUserAttributesToResourceData(d *schema.ResourceData, usr map[string]interface{}) error {
	attributes := getUserAttributes()
	if usr != nil {
		for _, attr := range attributes {
			if err := d.Set(attr, usr[attr]); err != nil {
				return fmt.Errorf("unable to set user attribute %s\n details: %s", attr, err)
			}
		}
	}
	return nil
}

func getUserAttributes() []string {
	attributes := [...]string{
		"created_at", "updated_at", "organization_id", "first_name", "last_name", "email", "phone_number",
		"username", "idprovider_id", "enabled", "deleted", "last_login", "mfa_verifiers_configured", "mfa_verification_excluded",
		"is_federated", "type", "organization_preferences", "organization", "properties", "member_of_organizations", "contributor_of_organizations",
	}
	return attributes[:]
}
