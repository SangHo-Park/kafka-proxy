package proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/grepplabs/kafka-proxy/pkg/apis"
	"github.com/grepplabs/kafka-proxy/proxy/protocol"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/xdg-go/scram"
)

type LocalSasl struct {
	enabled             bool
	timeout             time.Duration
	localAuthenticators map[string]LocalSaslAuth
	mechanism           string
}

type LocalSaslParams struct {
	enabled               bool
	timeout               time.Duration
	passwordAuthenticator apis.PasswordAuthenticator
	tokenAuthenticator    apis.TokenInfo
	scramAuthenticator    apis.ScramAuthenticator
}

func NewLocalSasl(params LocalSaslParams) *LocalSasl {
	localAuthenticators := make(map[string]LocalSaslAuth)
	if params.passwordAuthenticator != nil {
		localAuthenticators[SASLPlain] = NewLocalSaslPlain(params.passwordAuthenticator)
	}

	if params.scramAuthenticator != nil {
		localAuthenticators[SASLSCRAM256] = NewLocalSaslScram(params.scramAuthenticator)
		localAuthenticators[SASLSCRAM512] = NewLocalSaslScram(params.scramAuthenticator)
	}

	if params.tokenAuthenticator != nil {
		localAuthenticators[SASLOAuthBearer] = NewLocalSaslOauth(params.tokenAuthenticator)
	}
	return &LocalSasl{
		enabled:             params.enabled,
		timeout:             params.timeout,
		localAuthenticators: localAuthenticators,
	}
}

func (p *LocalSasl) receiveAndSendSASLAuthV1(conn DeadlineReaderWriter, readKeyVersionBuf []byte) (err error) {
	var localSaslAuth LocalSaslAuth
	if localSaslAuth, err = p.receiveAndSendSaslV0orV1(conn, readKeyVersionBuf, 1); err != nil {
		return err
	}
	if p.mechanism == "PLAIN" {
		if err = p.receiveAndSendAuthV1(conn, localSaslAuth); err != nil {
			return err
		}
	} else {
		if err = p.receiveAndSendAuthV1Scram(conn, localSaslAuth); err != nil {
			return err
		}
	}

	return nil
}

func (p *LocalSasl) receiveAndSendSASLAuthV0(conn DeadlineReaderWriter, readKeyVersionBuf []byte) (err error) {
	var localSaslAuth LocalSaslAuth
	if localSaslAuth, err = p.receiveAndSendSaslV0orV1(conn, readKeyVersionBuf, 0); err != nil {
		return err
	}
	if p.mechanism == "PLAIN" {
		if err = p.receiveAndSendAuthV0(conn, localSaslAuth); err != nil {
			return err
		}
	} else {
		if err = p.receiveAndSendAuthV0Scram(conn, localSaslAuth); err != nil {
			return err
		}
	}
	return nil
}

func (p *LocalSasl) receiveAndSendSaslV0orV1(conn DeadlineReaderWriter, keyVersionBuf []byte, version int16) (localSaslAuth LocalSaslAuth, err error) {
	requestDeadline := time.Now().Add(p.timeout)
	err = conn.SetDeadline(requestDeadline)
	if err != nil {
		return nil, err
	}

	if len(keyVersionBuf) != 8 {
		return nil, errors.New("length of keyVersionBuf should be 8")
	}
	// keyVersionBuf has already been read from connection
	requestKeyVersion := &protocol.RequestKeyVersion{}
	if err = protocol.Decode(keyVersionBuf, requestKeyVersion); err != nil {
		return nil, err
	}
	if !(requestKeyVersion.ApiKey == 17 && requestKeyVersion.ApiVersion == version) {
		return nil, fmt.Errorf("SaslHandshake version %d is expected, but got %d", version, requestKeyVersion.ApiVersion)
	}

	if int32(requestKeyVersion.Length) > protocol.MaxRequestSize {
		return nil, protocol.PacketDecodingError{Info: fmt.Sprintf("sasl handshake message of length %d too large", requestKeyVersion.Length)}
	}

	resp := make([]byte, int(requestKeyVersion.Length-4))
	if _, err = io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	payload := bytes.Join([][]byte{keyVersionBuf[4:], resp}, nil)

	saslReqV0orV1 := &protocol.SaslHandshakeRequestV0orV1{Version: version}
	req := &protocol.Request{Body: saslReqV0orV1}
	if err = protocol.Decode(payload, req); err != nil {
		return nil, err
	}

	var saslResult error
	saslErr := protocol.ErrNoError
	localSaslAuth = p.localAuthenticators[saslReqV0orV1.Mechanism]
	p.mechanism = saslReqV0orV1.Mechanism
	if localSaslAuth == nil {
		mechanisms := make([]string, 0)
		for mechanism := range p.localAuthenticators {
			mechanisms = append(mechanisms, mechanism)
		}
		saslResult = fmt.Errorf("PLAIN or OAUTHBEARER mechanism expected, %v are configured, but got %s", mechanisms, saslReqV0orV1.Mechanism)
		saslErr = protocol.ErrUnsupportedSASLMechanism
	}

	saslResV0 := &protocol.SaslHandshakeResponseV0orV1{Err: saslErr, EnabledMechanisms: []string{saslReqV0orV1.Mechanism}}
	newResponseBuf, err := protocol.Encode(saslResV0)
	if err != nil {
		return nil, err
	}
	newHeaderBuf, err := protocol.Encode(&protocol.ResponseHeader{Length: int32(len(newResponseBuf) + 4), CorrelationID: req.CorrelationID})
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(newHeaderBuf); err != nil {
		return nil, err
	}
	if _, err := conn.Write(newResponseBuf); err != nil {
		return nil, err
	}

	return localSaslAuth, saslResult
}

func (p *LocalSasl) receiveAndSendAuthV1(conn DeadlineReaderWriter, localSaslAuth LocalSaslAuth) (err error) {
	requestDeadline := time.Now().Add(p.timeout)
	err = conn.SetDeadline(requestDeadline)
	if err != nil {
		return err
	}

	keyVersionBuf := make([]byte, 8) // Size => int32 + ApiKey => int16 + ApiVersion => int16
	if _, err = io.ReadFull(conn, keyVersionBuf); err != nil {
		return err
	}
	requestKeyVersion := &protocol.RequestKeyVersion{}
	if err = protocol.Decode(keyVersionBuf, requestKeyVersion); err != nil {
		return err
	}
	if requestKeyVersion.ApiKey != 36 {
		return errors.Errorf("SaslAuthenticate is expected, but got apiKey %d", requestKeyVersion.ApiKey)
	}

	if requestKeyVersion.Length > protocol.MaxRequestSize {
		return protocol.PacketDecodingError{Info: fmt.Sprintf("sasl authenticate message of length %d too large", requestKeyVersion.Length)}
	}

	resp := make([]byte, int(requestKeyVersion.Length-4))
	if _, err = io.ReadFull(conn, resp); err != nil {
		return err
	}
	payload := bytes.Join([][]byte{keyVersionBuf[4:], resp}, nil)

	switch requestKeyVersion.ApiVersion {
	case 0:
		saslAuthReqV0 := &protocol.SaslAuthenticateRequestV0{}
		req := &protocol.Request{Body: saslAuthReqV0}
		if err = protocol.Decode(payload, req); err != nil {
			return err
		}

		authErr := localSaslAuth.doLocalAuth(saslAuthReqV0.SaslAuthBytes)

		var saslAuthResV0 *protocol.SaslAuthenticateResponseV0
		if authErr == nil {
			// Length of SaslAuthBytes !=0 for OAUTHBEARER causes that java SaslClientAuthenticator in INTERMEDIATE state will sent SaslAuthenticate(36) second time
			saslAuthResV0 = &protocol.SaslAuthenticateResponseV0{Err: protocol.ErrNoError, SaslAuthBytes: make([]byte, 0)}
		} else {
			errMsg := authErr.Error()
			saslAuthResV0 = &protocol.SaslAuthenticateResponseV0{Err: protocol.ErrSASLAuthenticationFailed, ErrMsg: &errMsg, SaslAuthBytes: make([]byte, 0)}
		}
		newResponseBuf, err := protocol.Encode(saslAuthResV0)
		if err != nil {
			return err
		}

		newHeaderBuf, err := protocol.Encode(&protocol.ResponseHeader{Length: int32(len(newResponseBuf) + 4), CorrelationID: req.CorrelationID})
		if err != nil {
			return err
		}
		if _, err := conn.Write(newHeaderBuf); err != nil {
			return err
		}
		if _, err := conn.Write(newResponseBuf); err != nil {
			return err
		}
		return authErr
	case 1:
		saslAuthReqV1 := &protocol.SaslAuthenticateRequestV1{}
		req := &protocol.Request{Body: saslAuthReqV1}
		if err = protocol.Decode(payload, req); err != nil {
			return err
		}

		authErr := localSaslAuth.doLocalAuth(saslAuthReqV1.SaslAuthBytes)

		var saslAuthResV1 *protocol.SaslAuthenticateResponseV1
		if authErr == nil {
			// Length of SaslAuthBytes !=0 for OAUTHBEARER causes that java SaslClientAuthenticator in INTERMEDIATE state will sent SaslAuthenticate(36) second time
			saslAuthResV1 = &protocol.SaslAuthenticateResponseV1{Err: protocol.ErrNoError, SaslAuthBytes: make([]byte, 0), SessionLifetimeMs: 0}
		} else {
			errMsg := authErr.Error()
			saslAuthResV1 = &protocol.SaslAuthenticateResponseV1{Err: protocol.ErrSASLAuthenticationFailed, ErrMsg: &errMsg, SaslAuthBytes: make([]byte, 0), SessionLifetimeMs: 0}
		}
		newResponseBuf, err := protocol.Encode(saslAuthResV1)
		if err != nil {
			return err
		}

		newHeaderBuf, err := protocol.Encode(&protocol.ResponseHeader{Length: int32(len(newResponseBuf) + 4), CorrelationID: req.CorrelationID})
		if err != nil {
			return err
		}
		if _, err := conn.Write(newHeaderBuf); err != nil {
			return err
		}
		if _, err := conn.Write(newResponseBuf); err != nil {
			return err
		}
		return authErr
	case 2:
		saslAuthReqV2 := &protocol.SaslAuthenticateRequestV2{}
		req := &protocol.RequestV2{Body: saslAuthReqV2}
		if err = protocol.Decode(payload, req); err != nil {
			return err
		}

		authErr := localSaslAuth.doLocalAuth(saslAuthReqV2.SaslAuthBytes)

		var saslAuthResV2 *protocol.SaslAuthenticateResponseV2
		if authErr == nil {
			// Length of SaslAuthBytes !=0 for OAUTHBEARER causes that java SaslClientAuthenticator in INTERMEDIATE state will sent SaslAuthenticate(36) second time
			saslAuthResV2 = &protocol.SaslAuthenticateResponseV2{Err: protocol.ErrNoError, SaslAuthBytes: make([]byte, 0), SessionLifetimeMs: 0}
		} else {
			errMsg := authErr.Error()
			saslAuthResV2 = &protocol.SaslAuthenticateResponseV2{Err: protocol.ErrSASLAuthenticationFailed, ErrMsg: &errMsg, SaslAuthBytes: make([]byte, 0), SessionLifetimeMs: 0}
		}
		newResponseBuf, err := protocol.Encode(saslAuthResV2)
		if err != nil {
			return err
		}
		// 2 (Length) + 2 (CorrelationID) + 1 (empty TaggedFields)
		newHeaderBuf, err := protocol.Encode(&protocol.ResponseHeaderV1{Length: int32(len(newResponseBuf) + 5), CorrelationID: req.CorrelationID})
		if err != nil {
			return err
		}
		if _, err := conn.Write(newHeaderBuf); err != nil {
			return err
		}
		if _, err := conn.Write(newResponseBuf); err != nil {
			return err
		}
		return authErr
	default:
		return errors.Errorf("SaslAuthenticate version 0,1 or 2 is expected, apiVersion %d", requestKeyVersion.ApiVersion)
	}
}

func (p *LocalSasl) receiveAndSendAuthV0(conn DeadlineReaderWriter, localSaslAuth LocalSaslAuth) (err error) {
	requestDeadline := time.Now().Add(p.timeout)
	err = conn.SetDeadline(requestDeadline)
	if err != nil {
		return err
	}

	sizeBuf := make([]byte, 4) // Size => int32
	if _, err = io.ReadFull(conn, sizeBuf); err != nil {
		return err
	}

	length := binary.BigEndian.Uint32(sizeBuf)
	if int32(length) > protocol.MaxRequestSize {
		return protocol.PacketDecodingError{Info: fmt.Sprintf("auth message of length %d too large", length)}
	}

	saslAuthBytes := make([]byte, length)
	_, err = io.ReadFull(conn, saslAuthBytes)
	if err != nil {
		return err
	}

	if localSaslAuth == nil {
		return errors.New("localSaslAuth is nil")
	}

	if err = localSaslAuth.doLocalAuth(saslAuthBytes); err != nil {
		return err
	}
	// If the credentials are valid, we would write a 4 byte response filled with null characters.
	// Otherwise, the closes the connection i.e. return error
	header := make([]byte, 4)
	if _, err := conn.Write(header); err != nil {
		return err
	}
	return nil
}

//// SCRAM
func getCredentialLookupFunc(localSaslAuth LocalSaslAuth, mechanism string) func(string) (scram.StoredCredentials, error) {
	return func(username string) (sc scram.StoredCredentials, err error) {
		password, err := localSaslAuth.getCredential(username)
		if err != nil {
			return scram.StoredCredentials{}, err
		}
		var scramClient *scram.Client
		switch mechanism {
		case "SCRAM-SHA-256":
			scramClient, err = SHA256.NewClient(username, password, "")
			if err != nil {
				return scram.StoredCredentials{}, err
			}
		case "SCRAM-SHA-512":
			scramClient, err = SHA512.NewClient(username, password, "")
			if err != nil {
				return scram.StoredCredentials{}, err
			}
		}
		kf := scram.KeyFactors{Salt: "c2FsdFNBTFRzYWx0\n", Iters: 4096}
		return scramClient.GetStoredCredentials(kf), nil
	}
}

func createScramConversation(mechanism string, cl scram.CredentialLookup) (conv *scram.ServerConversation, err error) {
	var scramServer *scram.Server
	switch mechanism {
	case "SCRAM-SHA-256":
		scramServer, err = SHA256.NewServer(cl)
		if err != nil {
			return nil, err
		}
	case "SCRAM-SHA-512":
		scramServer, err = SHA512.NewServer(cl)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid SCRAM specification provided: %s. Expected one of [\"SCRAM-SHA-256\",\"SCRAM-SHA-512\"]", mechanism)
	}
	conv = scramServer.NewConversation()
	return conv, nil
}

func (p *LocalSasl) receiveAndSendAuthV0Scram(conn DeadlineReaderWriter, localSaslAuth LocalSaslAuth) (err error) {
	requestDeadline := time.Now().Add(p.timeout)
	err = conn.SetDeadline(requestDeadline)
	if err != nil {
		return err
	}

	conv, err := createScramConversation(p.mechanism, getCredentialLookupFunc(localSaslAuth, p.mechanism))
	if err != nil {
		return err
	}

	for !conv.Done() {
		payload, err := p.receiveSaslAuthenticateRequestV0(conn)
		if err != nil {
			return err
		}

		if resStr, err := conv.Step(string(payload)); err != nil {
			return err
		} else {
			err = p.sendSaslAuthenticateResponseV0(conn, []byte(resStr))
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *LocalSasl) receiveAndSendAuthV1Scram(conn DeadlineReaderWriter, localSaslAuth LocalSaslAuth) (err error) {
	requestDeadline := time.Now().Add(p.timeout)
	err = conn.SetDeadline(requestDeadline)
	if err != nil {
		return err
	}

	conv, err := createScramConversation(p.mechanism, getCredentialLookupFunc(localSaslAuth, p.mechanism))
	if err != nil {
		return err
	}

	logrus.Debugf("Commencing scram loop")
	for !conv.Done() {
		payload, apiVersion, err := p.receiveSaslAuthenticateRequestV1(conn)
		if err != nil {
			return err
		}

		var authBytes []byte
		var correlationID int32
		switch apiVersion {
		case 0:
			saslAuthReqV0 := &protocol.SaslAuthenticateRequestV0{}
			req := &protocol.Request{Body: saslAuthReqV0}
			if err = protocol.Decode(payload, req); err != nil {
				return err
			}
			authBytes = saslAuthReqV0.SaslAuthBytes
			correlationID = req.CorrelationID
		case 1:
			saslAuthReqV1 := &protocol.SaslAuthenticateRequestV1{}
			req := &protocol.Request{Body: saslAuthReqV1}
			if err = protocol.Decode(payload, req); err != nil {
				return err
			}
			authBytes = saslAuthReqV1.SaslAuthBytes
			correlationID = req.CorrelationID
		case 2:
			saslAuthReqV2 := &protocol.SaslAuthenticateRequestV2{}
			req := &protocol.RequestV2{Body: saslAuthReqV2}
			if err = protocol.Decode(payload, req); err != nil {
				return err
			}
			authBytes = saslAuthReqV2.SaslAuthBytes
			correlationID = req.CorrelationID
		}

		if resStr, err := conv.Step(string(authBytes)); err != nil {
			return err
		} else {
			err = p.sendSaslAuthenticateResponseV1(conn, resStr, correlationID, apiVersion, err)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *LocalSasl) receiveSaslAuthenticateRequestV1(conn DeadlineReaderWriter) (payload []byte, apiVersion int16, err error) {
	keyVersionBuf := make([]byte, 8) // Size => int32 + ApiKey => int16 + ApiVersion => int16
	if _, err = io.ReadFull(conn, keyVersionBuf); err != nil {
		return nil, 0, err
	}
	requestKeyVersion := &protocol.RequestKeyVersion{}
	if err = protocol.Decode(keyVersionBuf, requestKeyVersion); err != nil {
		return nil, 0, err
	}
	if requestKeyVersion.ApiKey != 36 {
		return nil, 0, errors.Errorf("SaslAuthenticate is expected, but got apiKey %d", requestKeyVersion.ApiKey)
	}

	if requestKeyVersion.Length > protocol.MaxRequestSize {
		return nil, 0, protocol.PacketDecodingError{Info: fmt.Sprintf("sasl authenticate message of length %d too large", requestKeyVersion.Length)}
	}

	resp := make([]byte, int(requestKeyVersion.Length-4))
	if _, err = io.ReadFull(conn, resp); err != nil {
		return nil, 0, err
	}
	payload = bytes.Join([][]byte{keyVersionBuf[4:], resp}, nil)

	return payload, requestKeyVersion.ApiVersion, nil
}

func (p *LocalSasl) sendSaslAuthenticateResponseV1(conn DeadlineReaderWriter, resStr string, CorrelationID int32, apiVersion int16, authErr error) (err error) {
	switch apiVersion {
	case 0:
		var saslAuthResV0 *protocol.SaslAuthenticateResponseV0
		if authErr == nil {
			// Length of SaslAuthBytes !=0 for OAUTHBEARER causes that java SaslClientAuthenticator in INTERMEDIATE state will sent SaslAuthenticate(36) second time
			saslAuthResV0 = &protocol.SaslAuthenticateResponseV0{Err: protocol.ErrNoError, SaslAuthBytes: []byte(resStr)}
		} else {
			errMsg := authErr.Error()
			saslAuthResV0 = &protocol.SaslAuthenticateResponseV0{Err: protocol.ErrSASLAuthenticationFailed, ErrMsg: &errMsg, SaslAuthBytes: make([]byte, 0)}
		}
		newResponseBuf, err := protocol.Encode(saslAuthResV0)
		if err != nil {
			return err
		}
		newHeaderBuf, err := protocol.Encode(&protocol.ResponseHeader{Length: int32(len(newResponseBuf) + 4), CorrelationID: CorrelationID})
		if err != nil {
			return err
		}
		if _, err := conn.Write(newHeaderBuf); err != nil {
			return err
		}
		if _, err := conn.Write(newResponseBuf); err != nil {
			return err
		}
		return authErr
	case 1:
		var saslAuthResV1 *protocol.SaslAuthenticateResponseV1
		if authErr == nil {
			// Length of SaslAuthBytes !=0 for OAUTHBEARER causes that java SaslClientAuthenticator in INTERMEDIATE state will sent SaslAuthenticate(36) second time
			saslAuthResV1 = &protocol.SaslAuthenticateResponseV1{Err: protocol.ErrNoError, SaslAuthBytes: []byte(resStr), SessionLifetimeMs: 0}
		} else {
			errMsg := authErr.Error()
			saslAuthResV1 = &protocol.SaslAuthenticateResponseV1{Err: protocol.ErrSASLAuthenticationFailed, ErrMsg: &errMsg, SaslAuthBytes: make([]byte, 0), SessionLifetimeMs: 0}
		}
		newResponseBuf, err := protocol.Encode(saslAuthResV1)
		if err != nil {
			return err
		}

		newHeaderBuf, err := protocol.Encode(&protocol.ResponseHeader{Length: int32(len(newResponseBuf) + 4), CorrelationID: CorrelationID})
		if err != nil {
			return err
		}
		if _, err := conn.Write(newHeaderBuf); err != nil {
			return err
		}
		if _, err := conn.Write(newResponseBuf); err != nil {
			return err
		}
		return authErr
	case 2:
		var saslAuthResV2 *protocol.SaslAuthenticateResponseV2
		if authErr == nil {
			// Length of SaslAuthBytes !=0 for OAUTHBEARER causes that java SaslClientAuthenticator in INTERMEDIATE state will sent SaslAuthenticate(36) second time
			saslAuthResV2 = &protocol.SaslAuthenticateResponseV2{Err: protocol.ErrNoError, SaslAuthBytes: []byte(resStr), SessionLifetimeMs: 0}
		} else {
			errMsg := authErr.Error()
			saslAuthResV2 = &protocol.SaslAuthenticateResponseV2{Err: protocol.ErrSASLAuthenticationFailed, ErrMsg: &errMsg, SaslAuthBytes: make([]byte, 0), SessionLifetimeMs: 0}
		}
		newResponseBuf, err := protocol.Encode(saslAuthResV2)
		if err != nil {
			return err
		}
		// 2 (Length) + 2 (CorrelationID) + 1 (empty TaggedFields)
		newHeaderBuf, err := protocol.Encode(&protocol.ResponseHeaderV1{Length: int32(len(newResponseBuf) + 5), CorrelationID: CorrelationID})
		if err != nil {
			return err
		}
		if _, err := conn.Write(newHeaderBuf); err != nil {
			return err
		}
		if _, err := conn.Write(newResponseBuf); err != nil {
			return err
		}
		return nil
	default:
		return errors.Errorf("SaslAuthenticate version 0,1 or 2 is expected, apiVersion %d", apiVersion)
	}
}

func (p *LocalSasl) receiveSaslAuthenticateRequestV0(conn DeadlineReaderWriter) (payload []byte, err error) {
	sizeBuf := make([]byte, 4) // Size => int32
	if _, err = io.ReadFull(conn, sizeBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint32(sizeBuf)
	if int32(length) > protocol.MaxRequestSize {
		return nil, protocol.PacketDecodingError{Info: fmt.Sprintf("auth message of length %d too large", length)}
	}

	saslAuthBytes := make([]byte, length)
	_, err = io.ReadFull(conn, saslAuthBytes)
	if err != nil {
		return nil, err
	}
	return saslAuthBytes, nil
}

func (p *LocalSasl) sendSaslAuthenticateResponseV0(conn DeadlineReaderWriter, authBytes []byte) (err error) {
	header := make([]byte, 4) // int32 is 4 bytes
	binary.BigEndian.PutUint32(header, uint32(len(authBytes)))
	sendBytes := append(header, authBytes...)

	if _, err := conn.Write([]byte(sendBytes)); err != nil {
		return err
	}
	return nil
}
