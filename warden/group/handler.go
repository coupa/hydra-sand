package group

import (
	"encoding/json"
	"net/http"

	"github.com/ory/hydra/x"

	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"
)

type membersRequest struct {
	Members []string `json:"members"`
}

const (
	GroupsHandlerPath = "/warden/groups"
)

type Handler struct {
	r InternalRegistry
	c Configuration
}

func NewHandler(r InternalRegistry, c Configuration) *Handler {
	return &Handler{r: r, c: c}
}

func (h *Handler) SetRoutes(admin *x.RouterAdmin) {
	admin.POST(GroupsHandlerPath, h.CreateGroup)
	admin.GET(GroupsHandlerPath, h.FindGroupNames)
	admin.GET(GroupsHandlerPath+"/:id", h.GetGroup)
	admin.DELETE(GroupsHandlerPath+"/:id", h.DeleteGroup)
	admin.POST(GroupsHandlerPath+"/:id/members", h.AddGroupMembers)
	admin.DELETE(GroupsHandlerPath+"/:id/members", h.RemoveGroupMembers)
}

// swagger:route GET /warden/groups warden groups findGroupsByMember
//
// Find group IDs by member
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:warden:groups:<member>"],
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
//       oauth2: hydra.groups
//
//     Responses:
//       200: findGroupsByMemberResponse
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) FindGroupNames(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var member = r.URL.Query().Get("member")

	g, err := h.r.GroupManager().FindGroupNames(member)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().Write(w, r, g)
}

// swagger:route POST /warden/groups warden groups createGroup
//
// Create a group
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:warden:groups"],
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
//       oauth2: hydra.groups
//
//     Responses:
//       201: groupResponse
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var g Group

	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}

	if err := h.r.GroupManager().CreateGroup(&g); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().WriteCreated(w, r, GroupsHandlerPath+"/"+g.ID, &g)
}

// swagger:route GET /warden/groups/{id} warden groups getGroup
//
// Get a group by id
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:warden:groups:<id>"],
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
//       oauth2: hydra.groups
//
//     Responses:
//       201: groupResponse
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) GetGroup(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")

	g, err := h.r.GroupManager().GetGroup(id)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	h.r.Writer().Write(w, r, g)
}

// swagger:route DELETE /warden/groups/{id} warden groups deleteGroup
//
// Delete a group by id
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:warden:groups:<id>"],
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
//       oauth2: hydra.groups
//
//     Responses:
//       204: emptyResponse
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) DeleteGroup(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")

	if err := h.r.GroupManager().DeleteGroup(id); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// swagger:route POST /warden/groups/{id}/members warden groups addMembersToGroup
//
// Add members to a group
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:warden:groups:<id>"],
//    "actions": ["members.add"],
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
//       oauth2: hydra.groups
//
//     Responses:
//       204: emptyResponse
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) AddGroupMembers(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")

	var m membersRequest
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}

	if err := h.r.GroupManager().AddGroupMembers(id, m.Members); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// swagger:route DELETE /warden/groups/{id}/members warden groups removeMembersFromGroup
//
// Remove members from a group
//
// The subject making the request needs to be assigned to a policy containing:
//
//  ```
//  {
//    "resources": ["rn:hydra:warden:groups:<id>"],
//    "actions": ["members.remove"],
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
//       oauth2: hydra.groups
//
//     Responses:
//       204: emptyResponse
//       401: genericError
//       403: genericError
//       500: genericError
func (h *Handler) RemoveGroupMembers(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var id = ps.ByName("id")

	var m membersRequest
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		h.r.Writer().WriteError(w, r, errors.WithStack(err))
		return
	}

	if err := h.r.GroupManager().RemoveGroupMembers(id, m.Members); err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
