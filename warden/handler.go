package warden

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/coupa/foundation-go/metrics"
	"github.com/julienschmidt/httprouter"
	"github.com/ory/hydra/firewall"
	"github.com/ory/hydra/x"
	"github.com/pkg/errors"
)

const (
	// TokenAllowedHandlerPath points to the token access request validation endpoint.
	TokenAllowedHandlerPath = "/warden/token/allowed"

	// AllowedHandlerPath points to the access request validation endpoint.
	AllowedHandlerPath = "/warden/allowed"
)

type wardenAuthorizedRequest struct {
	// Scopes is an array of scopes that are requried.
	Scopes []string `json:"scopes"`

	// Token is the token to introspect.
	Token string `json:"token"`
}

type wardenAccessRequest struct {
	*firewall.TokenAccessRequest
	*wardenAuthorizedRequest
}

var notAllowed = struct {
	Allowed bool `json:"allowed"`
}{Allowed: false}

type Handler struct {
	r InternalRegistry
	c Configuration
}

func NewHandler(r InternalRegistry, c Configuration) *Handler {
	return &Handler{r: r, c: c}
}

func (h *Handler) SetRoutes(admin *x.RouterAdmin) {
	admin.POST(TokenAllowedHandlerPath, h.TokenAllowed)
	admin.POST(AllowedHandlerPath, h.Allowed)
}

// swagger:route POST /warden/allowed warden wardenAllowed
//
// Check if a subject is allowed to do something
//
// Checks if an arbitrary subject is allowed to perform an action on a resource. This endpoint requires a subject,
// a resource name, an action name and a context.If the subject is not allowed to perform the action on the resource,
// this endpoint returns a 200 response with `{ "allowed": false} }`.
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:warden:allowed"],
//    "actions": ["decide"],
//    "effect": "allow"
//  }
//  ```
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       oauth2: hydra.warden
//
//     Responses:
//       200: wardenAllowedResponse
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) Allowed(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var ctx = r.Context()

	var access = new(firewall.AccessRequest)
	if err := json.NewDecoder(r.Body).Decode(access); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}
	defer r.Body.Close()

	if err := h.r.Warden().IsAllowed(ctx, access); err != nil {
		h.r.Writer().Write(w, r, &notAllowed)
		return
	}

	res := notAllowed
	res.Allowed = true
	h.r.Writer().Write(w, r, &res)
}

// swagger:route POST /warden/token/allowed warden wardenTokenAllowed
//
// Check if the subject of a token is allowed to do something
//
// Checks if a token is valid and if the token owner is allowed to perform an action on a resource.
// This endpoint requires a token, a scope, a resource name, an action name and a context.
//
// If a token is expired/invalid, has not been granted the requested scope or the subject is not allowed to
// perform the action on the resource, this endpoint returns a 200 response with `{ "allowed": false} }`.
//
// Extra data set through the `at_ext` claim in the consent response will be included in the response.
// The `id_ext` claim will never be returned by this endpoint.
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:warden:token:allowed"],
//    "actions": ["decide"],
//    "effect": "allow"
//  }
//  ```
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
//     Schemes: http, https
//
//     Security:
//       oauth2: hydra.warden
//
//     Responses:
//       200: wardenTokenAllowedResponse
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) TokenAllowed(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := r.Context()

	var ar = wardenAccessRequest{
		TokenAccessRequest:      new(firewall.TokenAccessRequest),
		wardenAuthorizedRequest: new(wardenAuthorizedRequest),
	}
	if err := json.NewDecoder(r.Body).Decode(&ar); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		clientID := ""
		// if authContext != nil {
		// 	clientID = authContext.Subject
		// }
		metrics.Increment("Warden.Failure.MalformedRequest", map[string]string{
			"client_id": clientID,
			"resource":  "rn_hydra_warden_token_allowed",
			"reason":    "Error decoding request body",
		})
		return
	}
	defer r.Body.Close()

	authContext, err := h.r.Warden().TokenAllowed(ctx, ar.Token, ar.TokenAccessRequest, ar.Scopes...)
	if err != nil {
		h.r.Writer().Write(w, r, &notAllowed)
		return
	}

	h.r.Writer().Write(w, r, struct {
		*firewall.Context
		Allowed bool `json:"allowed"`
	}{
		Context: authContext,
		Allowed: true,
	})
}

func TokenFromRequest(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	split := strings.SplitN(auth, " ", 2)
	if len(split) != 2 || !strings.EqualFold(split[0], "bearer") {
		return ""
	}

	return split[1]
}
