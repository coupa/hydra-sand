package policy_test

import (
	"net/http/httptest"
	"testing"

	"github.com/ory/hydra/internal"
	"github.com/ory/hydra/policy"
	"github.com/ory/hydra/x"
	"github.com/ory/ladon"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ts *httptest.Server
var managers = map[string]policy.Manager{}

func init() {
	conf := internal.NewConfigurationWithDefaults()
	reg := internal.NewRegistryMemory(conf)

	serv := policy.NewHandler(reg, conf)

	r := x.NewRouterAdmin()
	serv.SetRoutes(r)
	ts = httptest.NewServer(r)
}

func TestManagers(t *testing.T) {
	p := &ladon.DefaultPolicy{
		ID:          uuid.New(),
		Description: "description",
		Subjects:    []string{"<peter>"},
		Effect:      ladon.AllowAccess,
		Resources:   []string{"<article|user>"},
		Actions:     []string{"view"},
		Conditions: ladon.Conditions{
			"ip": &ladon.CIDRCondition{
				CIDR: "1234",
			},
			"owner": &ladon.EqualsSubjectCondition{},
		},
	}

	for k, m := range managers {
		t.Run("manager="+k, func(t *testing.T) {
			_, err := m.Get(p.ID)
			require.Error(t, err)
			require.NoError(t, m.Create(p))

			res, err := m.Get(p.ID)
			require.NoError(t, err)
			assert.Equal(t, p, res)

			p.Subjects = []string{"stan"}
			require.NoError(t, m.Update(p))

			pols, err := m.List(10, 0)
			require.NoError(t, err)
			assert.Len(t, pols, 1)

			res, err = m.Get(p.ID)
			require.NoError(t, err)
			assert.Equal(t, p, res)

			require.NoError(t, m.Delete(p.ID))

			_, err = m.Get(p.ID)
			assert.Error(t, err)
		})
	}
}
