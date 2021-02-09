package policy

import (
	"encoding/json"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/hydra/x"
	"github.com/ory/ladon"
	"github.com/ory/x/pagination"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
)

const (
	endpoint = "/policies"
)

type Handler struct {
	r InternalRegistry
	c Configuration
}

func NewHandler(r InternalRegistry, c Configuration) *Handler {
	return &Handler{r: r, c: c}
}

func (h *Handler) SetRoutes(admin *x.RouterAdmin) {
	admin.POST(endpoint, h.Create)
	admin.GET(endpoint, h.List)
	admin.GET(endpoint+"/:id", h.Get)
	admin.PUT(endpoint+"/:id", h.Update)
	admin.DELETE(endpoint+"/:id", h.Delete)
}

// swagger:route GET /policies policies listPolicies
//
// List access control policies
//
// Visit https://github.com/ory/ladon#usage for more information on policy usage.
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:policies"],
//    "actions": ["list"],
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
//       oauth2: hydra.policies
//
//     Responses:
//       200: listPolicyResponse
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) List(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	query := r.URL.Query().Get("query")
	subject := r.URL.Query().Get("subject")
	resource := r.URL.Query().Get("resource")
	if query != "" {
		if subject != "" || resource != "" {
			h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.New("cannot have both 'query' and 'subject' or 'resource' parameters. Only one of them can be supplied"))
			return
		}
		//Ladon protects against SQL injection
		policies, err := h.r.PolicyManager().Search(query)
		if err != nil {
			h.r.Writer().WriteError(w, r, errors.WithStack(err))
			return
		}
		h.r.Writer().Write(w, r, policies)
		return
	}

	if subject != "" && resource != "" {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.New("cannot have both 'subject' and 'resource' parameters. Only one of them can be supplied"))
		return
	}

	policies, err := h.findPolicies(subject, resource)
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}
	if policies != nil {
		h.r.Writer().Write(w, r, policies)
		return
	}

	limit, offset := pagination.Parse(r, 100, 0, 500)

	n, err := h.r.PolicyManager().Count()
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}
	pagination.Header(w, r.URL, n, limit, offset)

	policies, err = h.r.PolicyManager().GetAll(int64(limit), int64(offset))
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}
	h.r.Writer().Write(w, r, policies)
}

// swagger:route POST /policies policies createPolicy
//
// Create an access control policy
//
// Visit https://github.com/ory/ladon#usage for more information on policy usage.
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:policies"],
//    "actions": ["create"],
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
//       oauth2: hydra.policies
//
//     Responses:
//       201: policy
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) Create(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var p = ladon.DefaultPolicy{
		Conditions: ladon.Conditions{},
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}

	if p.ID == "" {
		p.ID = uuid.New()
	}

	if err := h.r.PolicyManager().Create(&p); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}
	h.r.Writer().WriteCreated(w, r, "/policies/"+p.ID, &p)
}

// swagger:route GET /policies/{id} policies getPolicy
//
// Get an access control policy
//
// Visit https://github.com/ory/ladon#usage for more information on policy usage.
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:policies:<id>"],
//    "actions": ["get"],
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
//       oauth2: hydra.policies
//
//     Responses:
//       200: policy
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) Get(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	policy, err := h.r.PolicyManager().Get(ps.ByName("id"))
	if err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}
	h.r.Writer().Write(w, r, policy)
}

// swagger:route DELETE /policies/{id} policies deletePolicy
//
// Delete an access control policy
//
// Visit https://github.com/ory/ladon#usage for more information on policy usage.
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:policies:<id>"],
//    "actions": ["delete"],
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
//       oauth2: hydra.policies
//
//     Responses:
//       204: emptyResponse
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	// ctx := r.Context()
	id := ps.ByName("id")

	if err := h.r.PolicyManager().Delete(id); err != nil {
		h.r.Writer().WriteError(w, r, errors.New("Could not delete client"))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// swagger:route PUT /policies/{id} policies updatePolicy
//
// Update an access control policy
//
// Visit https://github.com/ory/ladon#usage for more information on policy usage.
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:policies"],
//    "actions": ["update"],
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
//       oauth2: hydra.policies
//
//     Responses:
//       200: policy
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) Update(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")
	var p = ladon.DefaultPolicy{Conditions: ladon.Conditions{}}

	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}

	if p.ID != id {
		h.r.Writer().WriteErrorCode(w, r, http.StatusBadRequest, errors.New("Payload ID does not match ID from URL"))
		return
	}

	if err := h.r.PolicyManager().Update(&p); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}

	h.r.Writer().Write(w, r, p)
}

func (h *Handler) findPolicies(subject, resource string) (ladon.Policies, error) {
	if subject != "" {
		return h.r.PolicyManager().FindPoliciesForSubject(&ladon.Request{Subject: subject})
	} else if resource != "" {
		return h.r.PolicyManager().FindPoliciesForResource(&ladon.Request{Resource: resource})
	}
	return nil, nil
}
