package group_test

import (
	"net/http/httptest"
	"testing"

	"fmt"

	_ "github.com/lib/pq"
	. "github.com/ory/hydra/warden/group"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var clientManagers = map[string]Manager{}
var ts *httptest.Server

func init() {
	clientManagers["memory"] = &MemoryManager{
		Groups: map[string]Group{},
	}
	//
	// conf := internal.NewConfigurationWithDefaults()
	// reg := internal.NewRegistryMemory(conf)
	//
	// serv := group.NewHandler(reg, conf)
	//
	// r := x.NewRouterAdmin()
	// serv.SetRoutes(r)
	// ts = httptest.NewServer(r)
}

func TestManagers(t *testing.T) {
	for k, m := range clientManagers {
		t.Run(fmt.Sprintf("case=%s", k), testHelperManagers(m))
	}
}

func testHelperManagers(m Manager) func(t *testing.T) {
	return func(t *testing.T) {
		_, err := m.GetGroup("4321")
		assert.NotNil(t, err)

		c := &Group{
			ID:      "1",
			Members: []string{"bar", "foo"},
		}
		assert.NoError(t, m.CreateGroup(c))
		assert.NoError(t, m.CreateGroup(&Group{
			ID:      "2",
			Members: []string{"foo"},
		}))

		d, err := m.GetGroup("1")
		require.NoError(t, err)
		assert.EqualValues(t, c.Members, d.Members)
		assert.EqualValues(t, c.ID, d.ID)

		ds, err := m.FindGroupNames("foo")
		require.NoError(t, err)
		assert.Len(t, ds, 2)

		assert.NoError(t, m.AddGroupMembers("1", []string{"baz"}))

		ds, err = m.FindGroupNames("baz")
		require.NoError(t, err)
		assert.Len(t, ds, 1)

		assert.NoError(t, m.RemoveGroupMembers("1", []string{"baz"}))
		ds, err = m.FindGroupNames("baz")
		require.NoError(t, err)
		assert.Len(t, ds, 0)

		assert.NoError(t, m.DeleteGroup("1"))
		_, err = m.GetGroup("1")
		require.NotNil(t, err)
	}
}
