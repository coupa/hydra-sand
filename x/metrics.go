package x

import (
	"os"
	"strconv"

	"github.com/coupa/foundation-go/metrics"
	"github.com/sirupsen/logrus"
)

func InitStatsd(version string) {
	sampleRate, err := strconv.ParseFloat(os.Getenv("STATSD_SAMPLE_RATE"), 32)
	if err != nil {
		logrus.Warnf("Error parsing statsd sample rate: %s. Use default 1.0", err.Error())
		sampleRate = 1.0
	}

	factory := func() *metrics.Statsd {
		return metrics.NewStatsd(os.Getenv("STATSD_ADDRESS"), os.Getenv("STATSD_PREFIX"), version, "Sand", float32(sampleRate))
	}
	metrics.SetFactory(factory)
}
