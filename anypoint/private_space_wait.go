package anypoint

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/mulesoft-anypoint/anypoint-client-go/private_space"
)

const (
	privateSpaceProvisionSuccess    = "InfrastructureProvisionSuccess"
	privateSpaceProvisionInProgress = "InfrastructureProvisionInProgress"
)

// Seams: tests shrink them to milliseconds.
var (
	privateSpacePollInterval             = 30 * time.Second
	privateSpaceMaxConsecutivePollErrors = 5
)

// privateSpaceStatusTerminal reports whether a provisioning status is a
// failure. No failure value has been observed, so anything containing Fail or
// Error counts; every other unknown value keeps the poll going.
func privateSpaceStatusTerminal(status string) bool {
	return strings.Contains(status, "Fail") || strings.Contains(status, "Error")
}

// waitPrivateSpaceProvisioned polls the private space until
// provisioning.status is InfrastructureProvisionSuccess and returns the last
// GET object. Transient errors (5xx, 429, transport) are retried; a 404, five
// consecutive errors, a failed status or ctx expiry end the wait with an error.
// The top-level status is not used: it reads Active about 10 minutes early.
func waitPrivateSpaceProvisioned(ctx context.Context, pco *ProviderConfOutput, orgid, psid string) (*private_space.PrivateSpace, diag.Diagnostics) {
	var diags diag.Diagnostics
	authctx := getPrivateSpaceAuthCtx(ctx, pco)
	consecutiveErrors := 0
	var lastErr string
	for {
		ps, httpr, err := pco.privatespaceclient.DefaultAPI.GetPrivateSpace(authctx, orgid, psid).Execute()
		if err == nil {
			closeResponseBody(httpr)
			status, message := privateSpaceProvisioning(ps)
			switch {
			case status == privateSpaceProvisionSuccess:
				return ps, diags
			case privateSpaceStatusTerminal(status):
				return nil, append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Unable to provision Private Space " + psid,
					Detail: fmt.Sprintf("Provisioning ended with status %q: %s\n\nThe private space exists in org %s. Delete it, or run `terraform untaint <resource address>` after fixing the cause to keep it.",
						status, message, orgid),
				})
			}
			consecutiveErrors = 0
			log.Printf("[DEBUG] Private Space %s provisioning status %q, waiting", psid, status)
		} else {
			if ctx.Err() != nil {
				return nil, append(diags, privateSpaceWaitTimeoutDiag(diag.Error, psid, ctx.Err()))
			}
			details := extractAPIErrorDetail(err, httpr)
			if httpr != nil && httpr.StatusCode == http.StatusNotFound {
				return nil, append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Unable to read Private Space " + psid + " while waiting for provisioning",
					Detail:   "HTTP 404: the private space no longer exists. " + details,
				})
			}
			consecutiveErrors++
			lastErr = details
			log.Printf("[WARN] Private Space %s poll error %d/%d: %s", psid, consecutiveErrors, privateSpaceMaxConsecutivePollErrors, details)
			if consecutiveErrors >= privateSpaceMaxConsecutivePollErrors {
				return nil, append(diags, diag.Diagnostic{
					Severity: diag.Error,
					Summary:  "Unable to read Private Space " + psid + " while waiting for provisioning",
					Detail: fmt.Sprintf("%d consecutive errors, last: %s\n\nThe private space exists and may still finish provisioning. Run `terraform untaint <resource address>` and refresh to keep it.",
						consecutiveErrors, lastErr),
				})
			}
		}
		select {
		case <-ctx.Done():
			return nil, append(diags, privateSpaceWaitTimeoutDiag(diag.Error, psid, ctx.Err()))
		case <-time.After(privateSpacePollInterval):
		}
	}
}

// waitPrivateSpaceAfterUpdate is the lenient wait after a PATCH: it waits only
// when the first GET says InfrastructureProvisionInProgress, and every problem
// is a warning because the PATCH has already been applied.
func waitPrivateSpaceAfterUpdate(ctx context.Context, pco *ProviderConfOutput, orgid, psid string) diag.Diagnostics {
	authctx := getPrivateSpaceAuthCtx(ctx, pco)
	ps, httpr, err := pco.privatespaceclient.DefaultAPI.GetPrivateSpace(authctx, orgid, psid).Execute()
	if err != nil {
		log.Printf("[WARN] Private Space %s status check after update failed, not waiting: %s", psid, extractAPIErrorDetail(err, httpr))
		return nil
	}
	closeResponseBody(httpr)
	status, _ := privateSpaceProvisioning(ps)
	if status != privateSpaceProvisionInProgress {
		log.Printf("[DEBUG] Private Space %s provisioning status %q after update, not waiting", psid, status)
		return nil
	}
	_, diags := waitPrivateSpaceProvisioned(ctx, pco, orgid, psid)
	for i := range diags {
		if diags[i].Severity == diag.Error {
			diags[i].Severity = diag.Warning
			diags[i].Summary = "The update of Private Space " + psid + " was applied but waiting for provisioning failed"
		}
	}
	return diags
}

func privateSpaceWaitTimeoutDiag(severity diag.Severity, psid string, cause error) diag.Diagnostic {
	return diag.Diagnostic{
		Severity: severity,
		Summary:  "Timed out waiting for Private Space " + psid + " to finish provisioning",
		Detail: fmt.Sprintf("%v. The private space %s exists and may still finish provisioning. "+
			"To keep it instead of replacing it, run `terraform untaint <resource address>` and then `terraform apply` (or refresh) once provisioning has completed. "+
			"The wait is bounded by the `timeouts` block (60m by default).", cause, psid),
	}
}

func privateSpaceProvisioning(ps *private_space.PrivateSpace) (status, message string) {
	if prov, ok := ps.GetProvisioningOk(); ok {
		return prov.GetStatus(), prov.GetMessage()
	}
	return "", ""
}

func closeResponseBody(httpr *http.Response) {
	if httpr != nil && httpr.Body != nil {
		httpr.Body.Close()
	}
}

// privateSpacePlannedDiffers reports whether the PATCH that would be built from
// the planned values (newPrivateSpacePatchBody) carries anything the API object
// does not already show. Fields the builder never sends are not compared.
func privateSpacePlannedDiffers(d *schema.ResourceData, ps *private_space.PrivateSpace) bool {
	env, _ := ps.GetEnvironmentsOk()
	if v := d.Get("environments_type").(string); v != "" && v != env.GetType() {
		return true
	}
	if v := privateSpaceStrings(d.Get("environments_business_groups").([]any)); len(v) > 0 &&
		!sameStringSet(v, env.GetBusinessGroups()) {
		return true
	}
	network, _ := ps.GetNetworkOk()
	dns, _ := network.GetInternalDnsOk()
	if v := privateSpaceStrings(d.Get("network_internal_dns_servers").([]any)); len(v) > 0 &&
		!sameStringSet(v, dns.GetDnsServers()) {
		return true
	}
	if v := privateSpaceStrings(d.Get("network_internal_dns_special_domains").([]any)); len(v) > 0 &&
		!sameStringSet(v, dns.GetSpecialDomains()) {
		return true
	}
	if rules := d.Get("firewall_rules").([]any); len(rules) > 0 {
		planned := make([]string, 0, len(rules))
		for _, r := range rules {
			m := r.(map[string]any)
			planned = append(planned, fmt.Sprintf("%s|%s|%d|%d|%s", m["cidr_block"], m["protocol"], m["from_port"], m["to_port"], m["type"]))
		}
		actual := make([]string, 0)
		for _, r := range ps.GetFirewallRules() {
			actual = append(actual, fmt.Sprintf("%s|%s|%d|%d|%s", r.GetCidrBlock(), r.GetProtocol(), r.GetFromPort(), r.GetToPort(), r.GetType()))
		}
		if !sameStringSet(planned, actual) {
			return true
		}
	}
	if d.Get("enable_iam_role").(bool) && !ps.GetEnableIAMRole() {
		return true
	}
	if d.Get("enable_egress").(bool) && !ps.GetEnableEgress() {
		return true
	}
	return false
}

func privateSpaceStrings(in []any) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
