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
	privateSpaceSettleWindow             = 5 * time.Minute
)

// privateSpaceStatusTerminal reports whether a provisioning status is a
// failure. No failure value has been observed, so anything containing Fail or
// Error counts; every other unknown value keeps the poll going.
func privateSpaceStatusTerminal(status string) bool {
	return strings.Contains(status, "Fail") || strings.Contains(status, "Error")
}

// privateSpaceWaitError is a wait failure before it is turned into a
// diagnostic, so Create (error) and Update (warning) can word it differently.
type privateSpaceWaitError struct {
	summary string
	detail  string
}

// pollPrivateSpaceProvisioned polls until provisioning.status is
// InfrastructureProvisionSuccess and returns the last GET object. Transient
// errors (5xx, 429, transport) are retried; a 404, five consecutive errors, a
// failed status or ctx expiry end the poll with an error.
// The top-level status is not used: it reads Active about 10 minutes early.
func pollPrivateSpaceProvisioned(ctx context.Context, pco *ProviderConfOutput, orgid, psid string) (*private_space.PrivateSpace, *privateSpaceWaitError) {
	authctx := getPrivateSpaceAuthCtx(ctx, pco)
	consecutiveErrors := 0
	for {
		ps, httpr, err := pco.privatespaceclient.DefaultAPI.GetPrivateSpace(authctx, orgid, psid).Execute()
		if err == nil {
			closeResponseBody(httpr)
			status, message := privateSpaceProvisioning(ps)
			switch {
			case status == privateSpaceProvisionSuccess:
				return ps, nil
			case privateSpaceStatusTerminal(status):
				return nil, &privateSpaceWaitError{
					summary: "Unable to provision Private Space " + psid,
					detail:  fmt.Sprintf("Provisioning ended with status %q: %s", status, message),
				}
			}
			consecutiveErrors = 0
			log.Printf("[DEBUG] Private Space %s provisioning status %q, waiting", psid, status)
		} else {
			if ctx.Err() != nil {
				return nil, privateSpaceWaitCtxError(psid, ctx.Err())
			}
			details := extractAPIErrorDetail(err, httpr)
			if httpr != nil && httpr.StatusCode == http.StatusNotFound {
				return nil, &privateSpaceWaitError{
					summary: "Unable to read Private Space " + psid + " while waiting for provisioning",
					detail:  "HTTP 404: the private space no longer exists. " + details,
				}
			}
			consecutiveErrors++
			log.Printf("[WARN] Private Space %s poll error %d/%d: %s", psid, consecutiveErrors, privateSpaceMaxConsecutivePollErrors, details)
			if consecutiveErrors >= privateSpaceMaxConsecutivePollErrors {
				return nil, &privateSpaceWaitError{
					summary: "Unable to read Private Space " + psid + " while waiting for provisioning",
					detail:  fmt.Sprintf("%d consecutive errors, last: %s", consecutiveErrors, details),
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, privateSpaceWaitCtxError(psid, ctx.Err())
		case <-time.After(privateSpacePollInterval):
		}
	}
}

func privateSpaceWaitCtxError(psid string, cause error) *privateSpaceWaitError {
	return &privateSpaceWaitError{
		summary: "Unable to wait for Private Space " + psid + " provisioning",
		detail:  fmt.Sprintf("%v. The wait is bounded by the `timeouts` block (60m by default).", cause),
	}
}

// privateSpaceCreateDiag words a wait failure for Create, where the space
// exists but the resource ends up tainted.
func privateSpaceCreateDiag(psid string, we *privateSpaceWaitError) diag.Diagnostic {
	return diag.Diagnostic{
		Severity: diag.Error,
		Summary:  we.summary,
		Detail: we.detail + fmt.Sprintf("\n\nThe private space %s exists and may still finish provisioning. "+
			"To keep it instead of replacing it, run `terraform untaint <resource address>` and then `terraform apply` (or refresh) once provisioning has completed.", psid),
	}
}

// waitPrivateSpaceProvisioned is the strict wait used by Create.
func waitPrivateSpaceProvisioned(ctx context.Context, pco *ProviderConfOutput, orgid, psid string) (*private_space.PrivateSpace, diag.Diagnostics) {
	ps, we := pollPrivateSpaceProvisioned(ctx, pco, orgid, psid)
	if we != nil {
		return nil, diag.Diagnostics{privateSpaceCreateDiag(psid, we)}
	}
	return ps, nil
}

// waitPrivateSpaceSettled runs after the Create PATCH. The platform was observed
// to reprovision a few minutes after a PATCH (provisioning stays Success first),
// so a single Success GET proves nothing. Poll for up to privateSpaceSettleWindow
// for the status to leave Success; if it does, wait strictly for Success again,
// otherwise return when the window ends.
func waitPrivateSpaceSettled(ctx context.Context, pco *ProviderConfOutput, orgid, psid string) diag.Diagnostics {
	authctx := getPrivateSpaceAuthCtx(ctx, pco)
	deadline := time.Now().Add(privateSpaceSettleWindow)
	for {
		ps, httpr, err := pco.privatespaceclient.DefaultAPI.GetPrivateSpace(authctx, orgid, psid).Execute()
		if err == nil {
			closeResponseBody(httpr)
			if status, _ := privateSpaceProvisioning(ps); status != "" && status != privateSpaceProvisionSuccess {
				log.Printf("[DEBUG] Private Space %s left Success (%q) after the PATCH, waiting for Success", psid, status)
				_, diags := waitPrivateSpaceProvisioned(ctx, pco, orgid, psid)
				return diags
			}
		} else {
			if ctx.Err() != nil {
				return diag.Diagnostics{privateSpaceCreateDiag(psid, privateSpaceWaitCtxError(psid, ctx.Err()))}
			}
			if httpr != nil && httpr.StatusCode == http.StatusNotFound {
				return diag.Diagnostics{privateSpaceCreateDiag(psid, &privateSpaceWaitError{
					summary: "Unable to read Private Space " + psid + " while waiting for provisioning",
					detail:  "HTTP 404: the private space no longer exists. " + extractAPIErrorDetail(err, httpr),
				})}
			}
			log.Printf("[WARN] Private Space %s settle poll error: %s", psid, extractAPIErrorDetail(err, httpr))
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			log.Printf("[DEBUG] Private Space %s stayed Success for the settle window, continuing", psid)
			return nil
		}
		wait := privateSpacePollInterval
		if remaining < wait {
			wait = remaining
		}
		select {
		case <-ctx.Done():
			return diag.Diagnostics{privateSpaceCreateDiag(psid, privateSpaceWaitCtxError(psid, ctx.Err()))}
		case <-time.After(wait):
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
	if _, we := pollPrivateSpaceProvisioned(ctx, pco, orgid, psid); we != nil {
		return diag.Diagnostics{{
			Severity: diag.Warning,
			Summary:  "The update of Private Space " + psid + " was applied but waiting for provisioning did not complete",
			Detail: we.summary + ": " + we.detail + "\n\nThe update was applied and the private space may still be reprovisioning; " +
				"the next refresh reconciles the state.",
		}}
	}
	return nil
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
