package health

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

var (
	serverStartTime time.Time
)

const (
	OK   = "OK"
	WARN = "WARN"
	CRIT = "CRIT"
)

type dependentInfo struct {
	Name         string         `json:"name"`
	Type         string         `json:"type"`
	State        dependentState `json:"state"`
	ResponseTime float64        `json:"responseTime"`
}

type dependentState struct {
	Status   string `json:"status"`
	Details  string `json:"details,omitempty"`
	Version  string `json:"version,omitempty"`
	Revision string `json:"revision,omitempty"`
}

type projectInfo struct {
	Repo   string   `json:"repo"`
	Home   string   `json:"home"`
	Owners []string `json:"owners"`
	Logs   []string `json:"logs"`
	Stats  []string `json:"stats"`
}

func init() {
	serverStartTime = time.Now()
}

func status(status string, r InternalRegistry) map[string]interface{} {
	return map[string]interface{}{
		"status":   status,
		"version":  r.BuildVersion(),
		"revision": r.BuildHash(),
	}
}

func SimpleStatus(r InternalRegistry) []byte {
	content := status(OK, r)
	data, _ := json.Marshal(content)
	return data
}

func DetailedStatus(r InternalRegistry, c Configuration) []byte {
	dependent := DBCheck(r)
	status := status(dependent.State.Status, r)
	status["project"] = GetProject()
	status["host"] = c.IssuerURL().String()
	status["description"] = "Sand authentication service for service to service communications."
	status["name"] = "Sand"
	status["uptime"] = int64(time.Since(serverStartTime).Seconds())
	status["dependencies"] = []interface{}{dependent}
	data, err := json.Marshal(status)
	if err != nil {
		data = []byte("Error producing JSON response: " + err.Error())
	}
	return data
}

func GetProject() projectInfo {
	logsStr := os.Getenv("APPLICATION_LOG_LINKS")
	logs := strings.Split(logsStr, " ")

	statsStr := os.Getenv("APPLICATION_STATS_LINKS")
	stats := strings.Split(statsStr, " ")

	return projectInfo{
		Repo:   "https://github.com/coupa/hydra-sand",
		Home:   "https://github.com/coupa/hydra-sand",
		Owners: []string{"Technology Platform"},
		Logs:   logs,
		Stats:  stats,
	}
}

func DBCheck(r InternalRegistry) dependentInfo {
	var err error
	var t float64
	var dbType string

	if r.Config().DSN() == "" {
		err = errors.New("No DB connection")
	} else {
		dbType = strings.Split(r.Config().DSN(), ":")[0]
		sTime := time.Now()

		err = r.Ping()
		t = time.Since(sTime).Seconds()
	}
	state := dependentState{Status: OK}
	if err != nil {
		state.Status = CRIT
		state.Details = err.Error()
	}

	return dependentInfo{
		Name:         "Database (" + dbType + ")",
		Type:         "internal",
		State:        state,
		ResponseTime: t,
	}
}
