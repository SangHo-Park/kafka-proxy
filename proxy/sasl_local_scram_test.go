package proxy

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/grepplabs/kafka-proxy/proxy/protocol"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

type testScramAuthenticator map[string]string

func (a testScramAuthenticator) GetCredential(username string) (string, string, error) {
	password, ok := a[username]
	if !ok {
		return "", "", errors.Errorf("user '%s' not found", username)
	}
	return username, password, nil
}

func newTestLocalSaslScram() *LocalSasl {
	return NewLocalSasl(LocalSaslParams{
		enabled:            true,
		timeout:            5 * time.Second,
		scramAuthenticator: testScramAuthenticator{"alice": "alice-secret", "bob": "bob-secret"},
	})
}

// All connections share one LocalSasl, so concurrent handshakes with different
// mechanisms must not interfere with each other.
func TestLocalSaslScramConcurrentMechanisms(t *testing.T) {
	localSasl := newTestLocalSaslScram()

	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := 0; i < 100; i++ {
		mechanism, username := SASLSCRAM256, "alice"
		if i%2 == 1 {
			mechanism, username = SASLSCRAM512, "bob"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			clientErr, serverErr := runLocalScramAuth(localSasl, mechanism, username, username+"-secret")
			if clientErr != nil || serverErr != nil {
				errs <- fmt.Errorf("%s %s: client: %v, server: %v", mechanism, username, clientErr, serverErr)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestLocalSaslScramRejectsBadCredentials(t *testing.T) {
	localSasl := newTestLocalSaslScram()

	tests := []struct {
		name      string
		mechanism string
		username  string
		password  string
	}{
		{name: "unknown user", mechanism: SASLSCRAM256, username: "mallory", password: "whatever"},
		{name: "wrong password", mechanism: SASLSCRAM512, username: "alice", password: "wrong-secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientErr, serverErr := runLocalScramAuth(localSasl, tt.mechanism, tt.username, tt.password)
			assert.Error(t, serverErr)
			assert.Equal(t, protocol.ErrSASLAuthenticationFailed, clientErr)
		})
	}
}

// The error message sent to the client must not reveal whether the user exists.
func TestLocalSaslScramUnknownUserErrorMessage(t *testing.T) {
	localSasl := newTestLocalSaslScram()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	serverDone := make(chan error, 1)
	go func() {
		keyVersionBuf := make([]byte, 8)
		_, err := io.ReadFull(serverConn, keyVersionBuf)
		if err == nil {
			err = localSasl.receiveAndSendSASLAuthV1(serverConn, keyVersionBuf)
		}
		serverConn.Close()
		serverDone <- err
	}()

	assert.NoError(t, writeTestRequest(clientConn, &protocol.Request{CorrelationID: 1, ClientID: "test",
		Body: &protocol.SaslHandshakeRequestV0orV1{Version: 1, Mechanism: SASLSCRAM256}}))
	_, err := readTestResponse(clientConn)
	assert.NoError(t, err)

	assert.NoError(t, writeTestRequest(clientConn, &protocol.Request{CorrelationID: 2, ClientID: "test",
		Body: &protocol.SaslAuthenticateRequestV0{SaslAuthBytes: []byte("n,,n=mallory,r=clientnonce")}}))
	body, err := readTestResponse(clientConn)
	if !assert.NoError(t, err) {
		return
	}
	authRes := &protocol.SaslAuthenticateResponseV0{}
	assert.NoError(t, protocol.Decode(body, authRes))

	assert.Equal(t, protocol.ErrSASLAuthenticationFailed, authRes.Err)
	if assert.NotNil(t, authRes.ErrMsg) {
		assert.Equal(t, "Authentication failed during authentication due to invalid credentials with SASL mechanism SCRAM-SHA-256", *authRes.ErrMsg)
		assert.NotContains(t, *authRes.ErrMsg, "mallory")
	}
	assert.Error(t, <-serverDone)
}

func runLocalScramAuth(localSasl *LocalSasl, mechanism, username, password string) (clientErr error, serverErr error) {
	clientConn, serverConn := net.Pipe()

	serverDone := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				serverDone <- fmt.Errorf("server panic: %v", r)
			}
			serverConn.Close()
		}()
		keyVersionBuf := make([]byte, 8)
		_, err := io.ReadFull(serverConn, keyVersionBuf)
		if err == nil {
			err = localSasl.receiveAndSendSASLAuthV1(serverConn, keyVersionBuf)
		}
		serverDone <- err
	}()

	client := &SASLSCRAMAuth{
		clientID:     "test",
		writeTimeout: 5 * time.Second,
		readTimeout:  5 * time.Second,
		username:     username,
		password:     password,
		mechanism:    mechanism,
	}
	clientErr = client.sendAndReceiveSASLAuth(clientConn, "")
	clientConn.Close()
	return clientErr, <-serverDone
}
