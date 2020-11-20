package health_test

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/ory/dockertest/v3"
	"github.com/ory/hydra/driver/configuration"
	"github.com/ory/hydra/health"
	"github.com/ory/hydra/internal"
	"github.com/ory/viper"
	"github.com/stretchr/testify/assert"
)

var (
	mysql     *url.URL
	postgres  *url.URL
	resources []*dockertest.Resource
)

func TestMain(m *testing.M) {
	mysql = bootstrapMySQL()
	postgres = bootstrapPostgres()
	defer killAll()

	m.Run()
}

func TestDBCheck(t *testing.T) {
	for _, tc := range []struct {
		n   string
		dsn string
	}{
		{
			n:   "mysql",
			dsn: "mysql://" + mysql.String(),
		},
		{
			n:   "postgres",
			dsn: postgres.String(),
		},
	} {
		t.Run(fmt.Sprintf("case=%s", tc.n), func(t *testing.T) {
			r := internal.NewRegistrySQLFromURL(t, tc.dsn)
			info := health.DBCheck(r)
			assert.Equal(t, info.Name, "Database ("+tc.n+")")
			assert.Equal(t, info.Type, "internal")
			assert.Equal(t, info.State.Status, health.OK)
		})
	}
	conf := internal.NewConfigurationWithDefaults()
	viper.Set(configuration.ViperKeyDSN, "memory")
	r := internal.NewRegistryMemory(conf)
	info := health.DBCheck(r)
	assert.Equal(t, info.Name, "Database (memory)")
	assert.Equal(t, info.Type, "internal")
	assert.Equal(t, info.State.Status, health.OK)
}

func TestDbCheckWithError(t *testing.T) {
	conf := internal.NewConfigurationWithDefaults()
	r := internal.NewRegistryMemory(conf)
	info := health.DBCheck(r)
	assert.Equal(t, info.Type, "internal")
	assert.Equal(t, info.State.Status, health.CRIT)
	assert.Equal(t, info.State.Details, "No DB connection")
}

func TestSimpleStatus(t *testing.T) {
	conf := internal.NewConfigurationWithDefaults()
	r := internal.NewRegistryMemory(conf)
	data := health.SimpleStatus(r)
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	assert.Equal(t, d["status"], health.OK)
}

func TestDetailedStatusWithoutConnection(t *testing.T) {
	conf := internal.NewConfigurationWithDefaults()
	r := internal.NewRegistryMemory(conf)

	data := health.DetailedStatus(r, conf)
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	assert.Equal(t, d["status"], health.CRIT)
	assert.Equal(t, d["name"], "Sand")

	dependent := d["dependencies"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, dependent["name"], "Database ()")
	assert.Equal(t, dependent["type"], "internal")

	state := dependent["state"].(map[string]interface{})
	assert.Equal(t, state["status"], health.CRIT)
	assert.Equal(t, state["details"], "No DB connection")
}

func TestDetailedStatusWithSQLConnection(t *testing.T) {
	r := internal.NewRegistrySQLFromURL(t, "mysql://"+mysql.String())
	data := health.DetailedStatus(r, r.Config())
	var d map[string]interface{}
	json.Unmarshal(data, &d)
	assert.Equal(t, d["status"], health.OK)
	assert.Equal(t, d["name"], "Sand")

	dependent := d["dependencies"].([]interface{})[0].(map[string]interface{})
	assert.Equal(t, dependent["name"], "Database (mysql)")
	assert.Equal(t, dependent["type"], "internal")

	state := dependent["state"].(map[string]interface{})
	assert.Equal(t, state["status"], health.OK)
	assert.Nil(t, state["details"])
}

func TestGetProjectWithData(t *testing.T) {
	os.Setenv("APPLICATION_LOG_LINKS", "http://log1.com https://log2.com")
	os.Setenv("APPLICATION_STATS_LINKS", "http://stats1.com https://stats2.com")

	info := health.GetProject()
	assert.Equal(t, info.Logs, []string{"http://log1.com", "https://log2.com"})
	assert.Equal(t, info.Stats, []string{"http://stats1.com", "https://stats2.com"})
}

func TestGetProjectWithoutData(t *testing.T) {
	os.Setenv("APPLICATION_LOG_LINKS", "")
	os.Setenv("APPLICATION_STATS_LINKS", "")

	info := health.GetProject()
	assert.Equal(t, info.Logs, []string{""})
	assert.Equal(t, info.Stats, []string{""})
}

func killAll() {
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not Connect to pool because %s", err)
	}

	for _, resource := range resources {
		if err := pool.Purge(resource); err != nil {
			log.Printf("Got an error while trying to purge resource: %s", err)
		}
	}

	resources = []*dockertest.Resource{}
}

func bootstrapMySQL() *url.URL {
	var db *sqlx.DB
	var err error
	var urls string

	pool, err := dockertest.NewPool("")
	pool.MaxWait = time.Minute * 5
	if err != nil {
		log.Fatalf("Could not Connect to docker: %s", err)
	}

	resource, err := pool.Run("mysql", "5.7", []string{"MYSQL_ROOT_PASSWORD=secret"})
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}

	if err = pool.Retry(func() error {
		var err error
		urls = fmt.Sprintf("root:secret@(127.0.0.1:%s)/mysql?parseTime=true", resource.GetPort("3306/tcp"))
		db, err = sqlx.Open("mysql", urls)
		if err != nil {
			return err
		}

		return db.Ping()
	}); err != nil {
		pool.Purge(resource)
		log.Fatalf("Could not Connect to docker: %s", err)
	}

	resources = append(resources, resource)
	u, _ := url.Parse(urls)
	return u
}

func bootstrapPostgres() *url.URL {
	var db *sqlx.DB
	var err error
	var urls string

	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not Connect to docker: %s", err)
	}

	resource, err := pool.Run("postgres", "9.6", []string{"POSTGRES_PASSWORD=secret", "POSTGRES_DB=hydra"})
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}

	if err = pool.Retry(func() error {
		var err error
		urls = fmt.Sprintf("postgres://postgres:secret@127.0.0.1:%s/hydra?sslmode=disable", resource.GetPort("5432/tcp"))
		db, err = sqlx.Open("postgres", urls)
		if err != nil {
			return err
		}

		return db.Ping()
	}); err != nil {
		pool.Purge(resource)
		log.Fatalf("Could not Connect to docker: %s", err)
	}

	resources = append(resources, resource)
	u, _ := url.Parse(urls)
	return u
}
