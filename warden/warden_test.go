package warden_test

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"context"

	"github.com/ory/fosite"
	foauth "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/hydra/client"
	"github.com/ory/hydra/driver"
	"github.com/ory/hydra/driver/configuration"
	"github.com/ory/hydra/firewall"
	"github.com/ory/hydra/internal"
	"github.com/ory/hydra/oauth2"
	"github.com/ory/hydra/warden"
	"github.com/ory/hydra/warden/group"
	"github.com/ory/hydra/x"
	"github.com/ory/ladon"
	"github.com/ory/ladon/manager/memory"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	wardens = map[string]firewall.Firewall{}
	now     = time.Now().Round(time.Second)
	conf    *configuration.ViperProvider
	reg     *driver.RegistryMemory

	ts     *httptest.Server
	tokens [][]string

	policies = map[string]ladon.Policy{
		"1": &ladon.DefaultPolicy{
			ID:        "1",
			Subjects:  []string{"alice", "group1"},
			Resources: []string{"matrix", "forbidden_matrix", "rn:hydra:token<.*>"},
			Actions:   []string{"create", "decide"},
			Effect:    ladon.AllowAccess,
		},
		"2": &ladon.DefaultPolicy{
			ID:        "2",
			Subjects:  []string{"siri"},
			Resources: []string{"<.*>"},
			Actions:   []string{"decide"},
			Effect:    ladon.AllowAccess,
		},
		"3": &ladon.DefaultPolicy{
			ID:        "3",
			Subjects:  []string{"group1"},
			Resources: []string{"forbidden_matrix", "rn:hydra:token<.*>"},
			Actions:   []string{"create", "decide"},
			Effect:    ladon.DenyAccess,
		},
	}
)

func init() {
	conf = internal.NewConfigurationWithDefaults()
	reg = internal.NewRegistryMemory(conf)

	x.InitStatsd("")
	tokens = Tokens(conf, 4)

	w := &warden.LocalWarden{
		Warden: &ladon.Ladon{
			Manager: &memory.MemoryManager{
				Policies: policies,
			},
		},
		R:                   reg,
		Issuer:              "tests",
		AccessTokenLifespan: conf.AccessTokenLifespan(),
	}
	reg = reg.WithWarden(w)

	//Create test warden group
	reg.GroupManager().CreateGroup(
		&group.Group{
			ID:      "group1",
			Members: []string{"ken"},
		},
	)

	//Create test clients
	c := &client.Client{
		ID:     "siri",
		Secret: "secret",
		Scope:  "core",
	}
	ctx := context.TODO()
	reg.ClientManager().CreateClient(ctx, c)

	wardens["local"] = reg.Warden()

	serv := reg.WardenHandler()
	r := x.NewRouterAdmin()
	serv.SetRoutes(r)
	ts = httptest.NewServer(r)

	ar := fosite.NewAccessRequest(oauth2.NewSession("alice"))
	ar.GrantedScope = fosite.Arguments{"core", "hydra.warden"}
	ar.RequestedAt = now
	ar.Client = &fosite.DefaultClient{ID: "siri"}
	ar.Session.SetExpiresAt(fosite.AccessToken, time.Now().Add(time.Hour).Round(time.Second))
	reg.OAuth2Storage().CreateAccessTokenSession(nil, tokens[0][0], ar)

	ar2 := fosite.NewAccessRequest(oauth2.NewSession("siri"))
	ar2.GrantedScope = fosite.Arguments{"core", "hydra.warden"}
	ar2.RequestedAt = now
	ar2.Client = &fosite.DefaultClient{ID: "bob"}
	ar2.Session.SetExpiresAt(fosite.AccessToken, time.Now().Add(time.Hour).Round(time.Second))
	reg.OAuth2Storage().CreateAccessTokenSession(nil, tokens[1][0], ar2)

	ar3 := fosite.NewAccessRequest(oauth2.NewSession("siri"))
	ar3.GrantedScope = fosite.Arguments{"core", "hydra.warden"}
	ar3.RequestedAt = now
	ar3.Client = &fosite.DefaultClient{ID: "doesnt-exist"}
	ar3.Session.SetExpiresAt(fosite.AccessToken, time.Now().Add(-time.Hour).Round(time.Second))
	reg.OAuth2Storage().CreateAccessTokenSession(nil, tokens[2][0], ar3)

	ar4 := fosite.NewAccessRequest(oauth2.NewSession("ken"))
	ar4.GrantedScope = fosite.Arguments{"core", "hydra.warden"}
	ar4.RequestedAt = now
	ar4.Client = &fosite.DefaultClient{ID: "siri"}
	ar4.Session.SetExpiresAt(fosite.AccessToken, time.Now().Add(time.Hour).Round(time.Second))
	reg.OAuth2Storage().CreateAccessTokenSession(nil, tokens[3][0], ar4)
}

func TestActionAllowed(t *testing.T) {
	for n, w := range wardens {
		for k, c := range []struct {
			token     string
			req       *firewall.TokenAccessRequest
			scopes    []string
			expectErr bool
			assert    func(*firewall.Context)
		}{
			{
				token:     "invalid",
				req:       &firewall.TokenAccessRequest{},
				scopes:    []string{},
				expectErr: true,
			},
			{
				token:     tokens[0][1],
				req:       &firewall.TokenAccessRequest{},
				scopes:    []string{"core"},
				expectErr: true,
			},
			{
				token:     tokens[0][1],
				req:       &firewall.TokenAccessRequest{},
				scopes:    []string{"foo"},
				expectErr: true,
			},
			{
				token: tokens[0][1],
				req: &firewall.TokenAccessRequest{
					Resource: "matrix",
					Action:   "create",
					Context:  ladon.Context{},
				},
				scopes:    []string{"foo"},
				expectErr: true,
			},
			{
				token: tokens[0][1],
				req: &firewall.TokenAccessRequest{
					Resource: "matrix",
					Action:   "delete",
					Context:  ladon.Context{},
				},
				scopes:    []string{"core"},
				expectErr: true,
			},
			{
				token: tokens[0][1],
				req: &firewall.TokenAccessRequest{
					Resource: "matrix",
					Action:   "create",
					Context:  ladon.Context{},
				},
				scopes:    []string{"illegal"},
				expectErr: true,
			},
			{
				token: tokens[0][1],
				req: &firewall.TokenAccessRequest{
					Resource: "matrix",
					Action:   "create",
					Context:  ladon.Context{},
				},
				scopes:    []string{"core"},
				expectErr: false,
				assert: func(c *firewall.Context) {
					assert.Equal(t, "siri", c.Audience)
					assert.Equal(t, "alice", c.Subject)
					assert.Equal(t, "tests", c.Issuer)
					assert.Equal(t, now.Add(time.Hour).Unix(), c.ExpiresAt.Unix())
					assert.Equal(t, now.Unix(), c.IssuedAt.Unix())
				},
			},
			{
				token: tokens[3][1],
				req: &firewall.TokenAccessRequest{
					Resource: "forbidden_matrix",
					Action:   "create",
					Context:  ladon.Context{},
				},
				scopes:    []string{"core"},
				expectErr: true,
			},
			{
				token: tokens[3][1],
				req: &firewall.TokenAccessRequest{
					Resource: "matrix",
					Action:   "create",
					Context:  ladon.Context{},
				},
				scopes:    []string{"core"},
				expectErr: false,
				assert: func(c *firewall.Context) {
					assert.Equal(t, "siri", c.Audience)
					assert.Equal(t, "ken", c.Subject)
					assert.Equal(t, "tests", c.Issuer)
					assert.Equal(t, now.Add(time.Hour).Unix(), c.ExpiresAt.Unix())
					assert.Equal(t, now.Unix(), c.IssuedAt.Unix())
				},
			},
		} {
			ctx, err := w.TokenAllowed(context.Background(), c.token, c.req, c.scopes...)
			if c.expectErr {
				require.Error(t, err, fmt.Sprintf("n = %s, k = %d", n, k))
			} else {
				require.NoError(t, err, fmt.Sprintf("n = %s, k = %d", n, k))
			}
			if err == nil && c.assert != nil {
				c.assert(ctx)
			}
		}
	}
}

func TestAllowed(t *testing.T) {
	for n, w := range wardens {
		for k, c := range []struct {
			req       *firewall.AccessRequest
			expectErr bool
			assert    func(*firewall.Context)
		}{
			{
				req: &firewall.AccessRequest{
					Subject:  "alice",
					Resource: "other-thing",
					Action:   "create",
					Context:  ladon.Context{},
				},
				expectErr: true,
			},
			{
				req: &firewall.AccessRequest{
					Subject:  "alice",
					Resource: "matrix",
					Action:   "delete",
					Context:  ladon.Context{},
				},
				expectErr: true,
			},
			{
				req: &firewall.AccessRequest{
					Subject:  "alice",
					Resource: "matrix",
					Action:   "create",
					Context:  ladon.Context{},
				},
				expectErr: false,
			},
		} {
			err := w.IsAllowed(context.Background(), c.req)
			if c.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			t.Logf("Passed test case %d\n", k)
		}
		t.Logf("Passed tests %s\n", n)
	}
}

func Tokens(c configuration.Provider, length int) (res [][]string) {
	s := &foauth.HMACSHAStrategy{
		Enigma: &hmac.HMACStrategy{
			GlobalSecret: c.GetSystemSecret(),
		},
		AccessTokenLifespan:   time.Hour,
		AuthorizeCodeLifespan: time.Hour,
	}

	for i := 0; i < length; i++ {
		tok, sig, _ := s.Enigma.Generate()
		res = append(res, []string{sig, tok})
	}
	return res
}
