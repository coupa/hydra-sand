package driver

import (
	"github.com/ory/fosite"
	"github.com/ory/hydra/firewall"
	"github.com/ory/hydra/oauth2"
	"github.com/ory/hydra/persistence/memory"
	"github.com/ory/hydra/warden"
	"github.com/ory/hydra/warden/group"
	"github.com/ory/hydra/x"
	"github.com/ory/ladon"
	lmem "github.com/ory/ladon/manager/memory"

	"github.com/ory/hydra/client"
	"github.com/ory/hydra/consent"
	"github.com/ory/hydra/jwk"
	"github.com/ory/x/dbal"
)

type RegistryMemory struct {
	*RegistryBase
}

var _ Registry = new(RegistryMemory)

func init() {
	dbal.RegisterDriver(func() dbal.Driver {
		return NewRegistryMemory()
	})
}

func NewRegistryMemory() *RegistryMemory {
	r := &RegistryMemory{
		RegistryBase: new(RegistryBase),
	}
	r.RegistryBase.with(r)
	return r
}

// WithOAuth2Provider forces an oauth2 provider which is only used for testing.
func (m *RegistryMemory) WithOAuth2Provider(f fosite.OAuth2Provider) *RegistryMemory {
	m.RegistryBase.fop = f
	return m
}

// WithConsentStrategy forces a consent strategy which is only used for testing.
func (m *RegistryMemory) WithConsentStrategy(c consent.Strategy) *RegistryMemory {
	m.RegistryBase.cos = c
	return m
}

// WithWarden forces a warden which is only used for testing.
func (m *RegistryMemory) WithWarden(w firewall.Firewall) *RegistryMemory {
	m.war = w
	return m
}

func (m *RegistryMemory) Init() error {
	m.persister = &memory.Persister{}
	return nil
}

func (m *RegistryMemory) CanHandle(dsn string) bool {
	return dsn == "memory"
}

func (m *RegistryMemory) Ping() error {
	return nil
}

func (m *RegistryMemory) ClientManager() client.Manager {
	if m.cm == nil {
		m.cm = client.NewMemoryManager(m)
	}
	return m.cm
}

func (m *RegistryMemory) ConsentManager() consent.Manager {
	if m.com == nil {
		m.com = consent.NewMemoryManager(m)
	}
	return m.com
}

func (m *RegistryMemory) OAuth2Storage() x.FositeStorer {
	if m.fs == nil {
		m.fs = oauth2.NewFositeMemoryStore(m.r, m.C)
	}
	return m.fs
}

func (m *RegistryMemory) KeyManager() jwk.Manager {
	if m.km == nil {
		m.km = jwk.NewMemoryManager()
	}
	return m.km
}

func (m *RegistryMemory) PolicyManager() ladon.Manager {
	if m.pol == nil {
		m.pol = lmem.NewMemoryManager()
	}
	return m.pol
}

func (m *RegistryMemory) GroupManager() group.Manager {
	if m.gm == nil {
		m.gm = group.NewMemoryManager()
	}
	return m.gm
}

func (m *RegistryMemory) Warden() firewall.Firewall {
	if m.war == nil {
		m.war = &warden.LocalWarden{
			Warden: &ladon.Ladon{
				Manager: m.PolicyManager(),
			},
			R:                   m.r,
			Issuer:              m.C.IssuerURL().String(),
			AccessTokenLifespan: m.C.AccessTokenLifespan(),
		}
	}
	return m.war
}
