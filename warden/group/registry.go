package group

import (
	"github.com/ory/hydra/driver/configuration"
	"github.com/ory/hydra/x"
)

type InternalRegistry interface {
	x.RegistryWriter
	x.RegistryLogger
	Registry
}

type Registry interface {
	GroupManager() Manager
}

type Configuration interface {
	configuration.Provider
}
