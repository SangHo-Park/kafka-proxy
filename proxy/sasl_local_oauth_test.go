package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/grepplabs/kafka-proxy/pkg/apis"
	"github.com/grepplabs/kafka-proxy/proxy/protocol"
	"github.com/stretchr/testify/assert"
)

type localOauthTokenInfo struct {
	validToken string
}

func (t localOauthTokenInfo) VerifyToken(ctx context.Context, request apis.VerifyRequest) (apis.VerifyResponse, error) {
	return apis.VerifyResponse{Success: request.Token == t.validToken}, nil
}

func newTestLocalSaslOauth() *LocalSasl {
	return NewLocalSasl(LocalSaslParams{
		enabled:            true,
		timeout:            5 * time.Second,
		tokenAuthenticator: localOauthTokenInfo{validToken: "good-token"},
	})
}

func writeTestRequest(conn net.Conn, req *protocol.Request) error {
	buf, err := protocol.Encode(req)
	if err != nil {
		return err
	}
	size := make([]byte, 4)
	binary.BigEndian.PutUint32(size, uint32(len(buf)))
	_, err = conn.Write(append(size, buf...))
	return err
}

func readTestResponse(conn net.Conn) ([]byte, error) {
	header := make([]byte, 8) // Length => int32 + CorrelationID => int32
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint32(header[:4])-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// runLocalSaslV1 runs a SaslHandshake v1 followed by a SaslAuthenticate v0 when the
// handshake succeeds, and returns the server result and the client-side errors.
func runLocalSaslV1(t *testing.T, localSasl *LocalSasl, mechanism string, authBytes []byte) (serverErr error, handshakeErr protocol.KError, authErr protocol.KError) {
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

	err := writeTestRequest(clientConn, &protocol.Request{CorrelationID: 1, ClientID: "test",
		Body: &protocol.SaslHandshakeRequestV0orV1{Version: 1, Mechanism: mechanism}})
	assert.NoError(t, err)
	body, err := readTestResponse(clientConn)
	assert.NoError(t, err)
	handshakeRes := &protocol.SaslHandshakeResponseV0orV1{}
	assert.NoError(t, protocol.Decode(body, handshakeRes))
	handshakeErr = handshakeRes.Err

	if handshakeErr == protocol.ErrNoError {
		err = writeTestRequest(clientConn, &protocol.Request{CorrelationID: 2, ClientID: "test",
			Body: &protocol.SaslAuthenticateRequestV0{SaslAuthBytes: authBytes}})
		assert.NoError(t, err)
		body, err = readTestResponse(clientConn)
		assert.NoError(t, err)
		authRes := &protocol.SaslAuthenticateResponseV0{}
		assert.NoError(t, protocol.Decode(body, authRes))
		authErr = authRes.Err
	}
	return <-serverDone, handshakeErr, authErr
}

func oauthBearerInitialResponse(token string) []byte {
	return []byte("n,,\x01auth=Bearer " + token + "\x01\x01")
}

func TestLocalSaslOauthBearerSuccess(t *testing.T) {
	localSasl := newTestLocalSaslOauth()

	serverErr, handshakeErr, authErr := runLocalSaslV1(t, localSasl, SASLOAuthBearer, oauthBearerInitialResponse("good-token"))

	assert.NoError(t, serverErr)
	assert.Equal(t, protocol.ErrNoError, handshakeErr)
	assert.Equal(t, protocol.ErrNoError, authErr)
}

func TestLocalSaslOauthBearerInvalidToken(t *testing.T) {
	localSasl := newTestLocalSaslOauth()

	serverErr, handshakeErr, authErr := runLocalSaslV1(t, localSasl, SASLOAuthBearer, oauthBearerInitialResponse("bad-token"))

	assert.Error(t, serverErr)
	assert.Equal(t, protocol.ErrNoError, handshakeErr)
	assert.Equal(t, protocol.ErrSASLAuthenticationFailed, authErr)
}

// A rejected handshake must not affect later authentications on the shared LocalSasl.
func TestLocalSaslUnsupportedMechanism(t *testing.T) {
	localSasl := newTestLocalSaslOauth()

	serverErr, handshakeErr, _ := runLocalSaslV1(t, localSasl, SASLSCRAM256, nil)
	assert.Error(t, serverErr)
	assert.Equal(t, protocol.ErrUnsupportedSASLMechanism, handshakeErr)

	serverErr, handshakeErr, authErr := runLocalSaslV1(t, localSasl, SASLOAuthBearer, oauthBearerInitialResponse("good-token"))
	assert.NoError(t, serverErr)
	assert.Equal(t, protocol.ErrNoError, handshakeErr)
	assert.Equal(t, protocol.ErrNoError, authErr)
}
