package health

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/hydra/x"
)

type Handler struct {
	r InternalRegistry
	c Configuration
}

func NewHandler(r InternalRegistry, c Configuration) *Handler {
	return &Handler{r: r, c: c}
}

func (h *Handler) SetRoutes(public *x.RouterPublic) {
	public.GET("/health", h.Health)
	public.GET("/v1/health/detailed", h.DetailedHealth)
}

// swagger:route GET /health health
//
// Check health status of instance
//
//     Produces:
//     - application/json
//
//     Responses:
//       200: healthStatus
//       500: genericError
func (h *Handler) Health(rw http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	rw.Write(SimpleStatus(h.r))
}

// swagger:route GET /v1/health/detailed health detailed
//
// Check health status of instance with detailed information including dependencies' health
//
//     Produces:
//     - application/json
//
//     Responses:
//       200: healthStatus
//       500: genericError
func (h *Handler) DetailedHealth(rw http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	rw.Write(DetailedStatus(h.r, h.c))
}
