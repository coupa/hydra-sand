package policy

import (
	"github.com/ory/hydra/driver/configuration"
	"github.com/ory/hydra/firewall"
	"github.com/ory/hydra/x"
	"github.com/ory/ladon"
)

type InternalRegistry interface {
	x.RegistryWriter
	x.RegistryLogger
	Registry
}

type Registry interface {
	PolicyManager() ladon.Manager
	Warden() firewall.Firewall
}

type Configuration interface {
	configuration.Provider
}
