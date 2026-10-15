package proxy

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/grepplabs/kafka-proxy/pkg/apis"
	"github.com/grepplabs/kafka-proxy/proxy/protocol"
	"github.com/pkg/errors"
)

type errLocalAuthFailed struct {
	user string
}

func (e errLocalAuthFailed) Error() string {
	return fmt.Sprintf("user %s authentication failed", e.user)
}

type LocalSaslAuth interface {
	doLocalAuth(saslAuthBytes []byte) (err error)
	getCredential(username string)(password string, err error)
}

type LocalSaslPlain struct {
	localAuthenticator apis.PasswordAuthenticator
}
type LocalSaslScram struct {
	localAuthenticator apis.ScramAuthenticator
}

func NewLocalSaslPlain(localAuthenticator apis.PasswordAuthenticator) *LocalSaslPlain {
	return &LocalSaslPlain{
		localAuthenticator: localAuthenticator,
	}
}

func NewLocalSaslScram(localAuthenticator apis.ScramAuthenticator) *LocalSaslScram {
	return &LocalSaslScram{
		localAuthenticator: localAuthenticator,
	}
}

// implements LocalSaslAuth
func (p *LocalSaslScram) doLocalAuth(saslAuthBytes []byte) (err error) {
	return fmt.Errorf("SASL SCRAM DO NOT doLocalAuth")
}

func (p *LocalSaslScram) getCredential(username string) (password string, err error) {
	// The requested SASL username (parsed from the SCRAM client-first message) is
	// forwarded to the authenticator so that it can look up the matching credential.
	// This enables support for multiple SCRAM users.
	u, pw, err := p.localAuthenticator.GetCredential(username)
	if err != nil {
		return "", err
	}
	if u != username {
		return "", errors.Errorf("SaslAuthenticate Failed. User '%s' not exist", username)
	}
	return pw, nil
}

// implements LocalSaslAuth
func (p *LocalSaslPlain) getCredential(username string)(password string, err error) {
	return "", nil
}

func (p *LocalSaslPlain) doLocalAuth(saslAuthBytes []byte) (err error) {
	tokens := strings.Split(string(saslAuthBytes), "\x00")
	if len(tokens) != 3 {
		return fmt.Errorf("invalid SASL/PLAIN request: expected 3 tokens, got %d", len(tokens))
	}
	if p.localAuthenticator == nil {
		return protocol.PacketDecodingError{Info: "Listener authenticator is not set"}
	}

	// logrus.Infof("user: %s , password: %s", tokens[1], tokens[2])
	ok, status, err := p.localAuthenticator.Authenticate(tokens[1], tokens[2])
	if err != nil {
		proxyLocalAuthTotal.WithLabelValues("error", "1").Inc()
		return err
	}
	proxyLocalAuthTotal.WithLabelValues(strconv.FormatBool(ok), strconv.Itoa(int(status))).Inc()

	if !ok {
		return errLocalAuthFailed{
			user: tokens[1],
		}
	}
	return nil
}

type LocalSaslOauth struct {
	saslOAuthBearer    SaslOAuthBearer
	tokenAuthenticator apis.TokenInfo
}

func NewLocalSaslOauth(tokenAuthenticator apis.TokenInfo) *LocalSaslOauth {
	return &LocalSaslOauth{
		saslOAuthBearer:    SaslOAuthBearer{},
		tokenAuthenticator: tokenAuthenticator,
	}
}

// implements LocalSaslAuth
func (p *LocalSaslOauth) getCredential(username string) ( password string, err error) {
	return "", nil
}
func (p *LocalSaslOauth) doLocalAuth(saslAuthBytes []byte) (err error) {
	token, _, _, err := p.saslOAuthBearer.GetClientInitialResponse(saslAuthBytes)
	if err != nil {
		return err
	}
	resp, err := p.tokenAuthenticator.VerifyToken(context.Background(), apis.VerifyRequest{Token: token})
	if err != nil {
		return err
	}
	if !resp.Success {
		return fmt.Errorf("local oauth verify token failed with status: %d", resp.Status)
	}
	return nil
}
