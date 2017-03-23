package oauth2

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/jmoiron/sqlx"
	"github.com/ory-am/fosite"
	"github.com/ory-am/hydra/client"
	"github.com/pkg/errors"
	"github.com/rubenv/sql-migrate"
	"golang.org/x/net/context"
)

type FositeSQLStore struct {
	client.Manager
	DB *sqlx.DB
}

func sqlTemplate(table string) string {
	return fmt.Sprintf(`CREATE TABLE IF NOT EXISTS hydra_oauth2_%s (
	signature      	varchar(255) NOT NULL PRIMARY KEY,
	request_id  	varchar(255) NOT NULL,
	requested_at  	timestamp NOT NULL DEFAULT now(),
	client_id  	text NOT NULL,
	scope  		text NOT NULL,
	granted_scope 	text NOT NULL,
	form_data  	text NOT NULL,
	session_data  	text NOT NULL
)`, table)
}

const (
	sqlTableOpenID  = "oidc"
	sqlTableAccess  = "access"
	sqlTableRefresh = "refresh"
	sqlTableCode    = "code"
)

var migrations = &migrate.MemoryMigrationSource{
	Migrations: []*migrate.Migration{
		{
			Id: "1",
			Up: []string{
				sqlTemplate(sqlTableAccess),
				sqlTemplate(sqlTableRefresh),
				sqlTemplate(sqlTableCode),
				sqlTemplate(sqlTableOpenID),
			},
			Down: []string{
				fmt.Sprintf("DROP TABLE %s", sqlTableAccess),
				fmt.Sprintf("DROP TABLE %s", sqlTableRefresh),
				fmt.Sprintf("DROP TABLE %s", sqlTableCode),
				fmt.Sprintf("DROP TABLE %s", sqlTableOpenID),
			},
		},
	},
}

var sqlParams = []string{
	"signature",
	"request_id",
	"requested_at",
	"client_id",
	"scope",
	"granted_scope",
	"form_data",
	"session_data",
}

type sqlData struct {
	Signature     string    `db:"signature"`
	Request       string    `db:"request_id"`
	RequestedAt   time.Time `db:"requested_at"`
	Client        string    `db:"client_id"`
	Scopes        string    `db:"scope"`
	GrantedScopes string    `db:"granted_scope"`
	Form          string    `db:"form_data"`
	Session       []byte    `db:"session_data"`
}

func sqlSchemaFromRequest(signature string, r fosite.Requester) (*sqlData, error) {
	if r.GetSession() == nil {
		logrus.Debugf("Got an empty session in sqlSchemaFromRequest")
	}

	session, err := json.Marshal(r.GetSession())
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &sqlData{
		Request:       r.GetID(),
		Signature:     signature,
		RequestedAt:   r.GetRequestedAt(),
		Client:        r.GetClient().GetID(),
		Scopes:        strings.Join([]string(r.GetRequestedScopes()), "|"),
		GrantedScopes: strings.Join([]string(r.GetGrantedScopes()), "|"),
		Form:          r.GetRequestForm().Encode(),
		Session:       session,
	}, nil
}

func (s *sqlData) toRequest(session fosite.Session, cm client.Manager) (*fosite.Request, error) {
	if session != nil {
		if err := json.Unmarshal(s.Session, session); err != nil {
			return nil, errors.WithStack(err)
		}
	} else {
		logrus.Debugf("Got an empty session in toRequest")
	}

	c, err := cm.GetClient(s.Client)
	if err != nil {
		return nil, err
	}

	val, err := url.ParseQuery(s.Form)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	r := &fosite.Request{
		ID:            s.Request,
		RequestedAt:   s.RequestedAt,
		Client:        c,
		Scopes:        fosite.Arguments(strings.Split(s.Scopes, "|")),
		GrantedScopes: fosite.Arguments(strings.Split(s.GrantedScopes, "|")),
		Form:          val,
		Session:       session,
	}

	return r, nil
}

func (s *FositeSQLStore) createSession(signature string, requester fosite.Requester, table string) error {
	data, err := sqlSchemaFromRequest(signature, requester)
	if err != nil {
		return err
	}

	query := fmt.Sprintf(
		"INSERT INTO hydra_oauth2_%s (%s) VALUES (%s)",
		table,
		strings.Join(sqlParams, ", "),
		":"+strings.Join(sqlParams, ", :"),
	)
	if _, err := s.DB.NamedExec(query, data); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (s *FositeSQLStore) findSessionBySignature(signature string, session fosite.Session, table string) (fosite.Requester, error) {
	var d sqlData
	if err := s.DB.Get(&d, s.DB.Rebind(fmt.Sprintf("SELECT * FROM hydra_oauth2_%s WHERE signature=?", table)), signature); err == sql.ErrNoRows {
		return nil, errors.Wrap(fosite.ErrNotFound, "")
	} else if err != nil {
		return nil, errors.WithStack(err)
	}

	return d.toRequest(session, s.Manager)
}

func (s *FositeSQLStore) deleteSession(signature string, table string) error {
	if _, err := s.DB.Exec(s.DB.Rebind(fmt.Sprintf("DELETE FROM hydra_oauth2_%s WHERE signature=?", table)), signature); err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (s *FositeSQLStore) CreateSchemas() error {
	migrate.SetTable("hydra_oauth2_migration")
	n, err := migrate.Exec(s.DB.DB, s.DB.DriverName(), migrations, migrate.Up)
	if err != nil {
		return errors.Wrapf(err, "Could not migrate sql schema, applied %d migrations", n)
	}
	return nil
}

func (s *FositeSQLStore) CreateOpenIDConnectSession(_ context.Context, signature string, requester fosite.Requester) error {
	return s.createSession(signature, requester, sqlTableOpenID)
}

func (s *FositeSQLStore) GetOpenIDConnectSession(_ context.Context, signature string, requester fosite.Requester) (fosite.Requester, error) {
	return s.findSessionBySignature(signature, requester.GetSession(), sqlTableOpenID)
}

func (s *FositeSQLStore) DeleteOpenIDConnectSession(_ context.Context, signature string) error {
	return s.deleteSession(signature, sqlTableOpenID)
}

func (s *FositeSQLStore) CreateAuthorizeCodeSession(_ context.Context, signature string, requester fosite.Requester) error {
	return s.createSession(signature, requester, sqlTableCode)
}

func (s *FositeSQLStore) GetAuthorizeCodeSession(_ context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.findSessionBySignature(signature, session, sqlTableCode)
}

func (s *FositeSQLStore) DeleteAuthorizeCodeSession(_ context.Context, signature string) error {
	return s.deleteSession(signature, sqlTableCode)
}

func (s *FositeSQLStore) CreateAccessTokenSession(_ context.Context, signature string, requester fosite.Requester) error {
	return s.createSession(signature, requester, sqlTableAccess)
}

func (s *FositeSQLStore) GetAccessTokenSession(_ context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.findSessionBySignature(signature, session, sqlTableAccess)
}

func (s *FositeSQLStore) DeleteAccessTokenSession(_ context.Context, signature string) error {
	return s.deleteSession(signature, sqlTableAccess)
}

func (s *FositeSQLStore) CreateRefreshTokenSession(_ context.Context, signature string, requester fosite.Requester) error {
	return s.createSession(signature, requester, sqlTableRefresh)
}

func (s *FositeSQLStore) GetRefreshTokenSession(_ context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.findSessionBySignature(signature, session, sqlTableRefresh)
}

func (s *FositeSQLStore) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	return s.deleteSession(signature, sqlTableRefresh)
}

func (s *FositeSQLStore) CreateImplicitAccessTokenSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.CreateAccessTokenSession(ctx, signature, requester)
}

func (s *FositeSQLStore) PersistAuthorizeCodeGrantSession(ctx context.Context, authorizeCode, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := s.DeleteAuthorizeCodeSession(ctx, authorizeCode); err != nil {
		return err
	} else if err := s.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	}

	if refreshSignature == "" {
		return nil
	}

	if err := s.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}

	return nil
}

func (s *FositeSQLStore) PersistRefreshTokenGrantSession(ctx context.Context, originalRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := s.DeleteRefreshTokenSession(ctx, originalRefreshSignature); err != nil {
		return err
	} else if err := s.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if err := s.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}

	return nil
}

func (s *FositeSQLStore) RevokeRefreshToken(ctx context.Context, id string) error {
	return s.revokeSession(id, sqlTableRefresh)
}

func (s *FositeSQLStore) RevokeAccessToken(ctx context.Context, id string) error {
	return s.revokeSession(id, sqlTableAccess)
}

func (s *FositeSQLStore) revokeSession(id string, table string) error {
	if _, err := s.DB.Exec(s.DB.Rebind(fmt.Sprintf("DELETE FROM hydra_oauth2_%s WHERE request_id=?", table)), id); err == sql.ErrNoRows {
		return errors.Wrap(fosite.ErrNotFound, "")
	} else if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (s *FositeSQLStore) RemoveOldAccessTokens(lifespan time.Duration) (int64, error) {
	//If lifespan = 0 or less, don't delete tokens.
	if lifespan <= 0 {
		return 0, nil
	}
	query := fmt.Sprintf(
		`DELETE FROM hydra_oauth2_%s WHERE signature IN
			(SELECT t.signature FROM
				(SELECT signature, requested_at FROM hydra_oauth2_%s
					WHERE TIMESTAMPDIFF(MINUTE, requested_at, UTC_TIMESTAMP()) > ?) t)`, sqlTableAccess, sqlTableAccess)
	result, err := s.DB.Exec(s.DB.Rebind(query), int(math.Ceil(lifespan.Minutes())))
	if err != nil {
		return 0, errors.Wrap(err, "Error removing old tokens")
	}
	return result.RowsAffected()
}
