package health

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
	BuildVersion() string
	BuildHash() string
	Ping() error
	Config() configuration.Provider
}

type Configuration interface {
	configuration.Provider
}
