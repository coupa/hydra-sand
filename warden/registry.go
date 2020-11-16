package warden

import (
	"github.com/ory/fosite"
	"github.com/ory/hydra/driver/configuration"
	"github.com/ory/hydra/firewall"
	"github.com/ory/hydra/warden/group"
	"github.com/ory/hydra/x"
)

type InternalRegistry interface {
	x.RegistryWriter
	x.RegistryLogger
	Registry
}

type Registry interface {
	OAuth2Provider() fosite.OAuth2Provider
	Warden() firewall.Firewall
	GroupManager() group.Manager
}

type Configuration interface {
	configuration.Provider
}
