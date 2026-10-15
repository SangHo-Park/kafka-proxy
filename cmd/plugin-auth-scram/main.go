package main

import (
	"flag"
	"os"
	"strings"

	"github.com/grepplabs/kafka-proxy/plugin/local-auth-scram/shared"
	"github.com/hashicorp/go-plugin"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const EnvSaslPassword = "SASL_PASSWORD"

// credentialList is a repeatable "username:password" flag value.
type credentialList []string

func (c *credentialList) String() string {
	return strings.Join(*c, ",")
}

func (c *credentialList) Set(value string) error {
	*c = append(*c, value)
	return nil
}

// parseCredential splits a "username:password" entry.
func parseCredential(entry string) (username string, password string, err error) {
	parts := strings.SplitN(entry, ":", 2)
	if len(parts) != 2 {
		return "", "", errors.Errorf("invalid credential %q, expected format username:password", entry)
	}
	username = strings.TrimSpace(parts[0])
	if username == "" || parts[1] == "" {
		return "", "", errors.Errorf("invalid credential %q, expected format username:password", entry)
	}
	if err := validateUsername(username); err != nil {
		return "", "", err
	}
	return username, parts[1], nil
}

// validateUsername rejects ',' and '=', which SCRAM clients encode as "=2C" and
// "=3D" in the username and the scram library does not decode, so such users
// could never authenticate.
func validateUsername(username string) error {
	if strings.ContainsAny(username, ",=") {
		return errors.Errorf("invalid username %q, ',' and '=' are not allowed", username)
	}
	return nil
}

type ScramAuthenticator struct {
	// Credentials holds the multi-user SASL users as "username:password" entries (--scram-credential).
	Credentials credentialList
	// PriorityUsername/PriorityPassword come from --username/--password and
	// take precedence over a --scram-credential entry with the same username.
	PriorityUsername string
	PriorityPassword string

	creds map[string]string
}

// GetCredential looks up the password for the requested SASL username.
// The proxy forwards the username via the storeinfo argument.
func (pa *ScramAuthenticator) GetCredential(storeinfo string) (username string, password string, err error) {
	pw, ok := pa.creds[storeinfo]
	if !ok {
		return "", "", errors.Errorf("user '%s' not found", storeinfo)
	}
	return storeinfo, pw, nil
}

// load builds the in-memory credential map from the configured credentials.
// Duplicate usernames among --scram-credential entries are rejected, while the
// single-user --username/--password credential overrides any matching entry.
func (pa *ScramAuthenticator) load() error {
	creds := make(map[string]string)

	for _, entry := range pa.Credentials {
		username, password, err := parseCredential(entry)
		if err != nil {
			return err
		}
		if _, exists := creds[username]; exists {
			return errors.Errorf("duplicate username '%s'", username)
		}
		creds[username] = password
	}

	// Single-user credential takes priority and overrides any duplicate.
	if pa.PriorityUsername != "" {
		if _, exists := creds[pa.PriorityUsername]; exists {
			logrus.Infof("user '%s' from --username/--password overrides the --scram-credential entry", pa.PriorityUsername)
		}
		creds[pa.PriorityUsername] = pa.PriorityPassword
	}

	if len(creds) == 0 {
		return errors.New("no credentials configured")
	}

	pa.creds = creds
	logrus.Infof("loaded %d scram credential(s)", len(creds))
	return nil
}

func main() {
	var username, password string
	scramAuthenticator := &ScramAuthenticator{}

	fs := flag.NewFlagSet("auth plugin settings", flag.ContinueOnError)
	fs.StringVar(&username, "username", "", "Expected SASL username (single-user mode)")
	fs.StringVar(&password, "password", "", "Expected SASL password (single-user mode)")
	fs.Var(&scramAuthenticator.Credentials, "scram-credential", "SASL user in 'username:password' format; may be repeated (multi-user mode)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		logrus.Errorf("error parsing flags: %v", err)
		os.Exit(1)
	}

	username = strings.TrimSpace(username)

	// SASL_PASSWORD is inherited from the kafka-proxy environment, where it may hold
	// the upstream broker password, so only use it when --username is given.
	if username != "" && password == "" {
		password = os.Getenv(EnvSaslPassword)
	}

	if username != "" || password != "" {
		if username == "" || password == "" {
			logrus.Errorf("both --username and --password are required for single-user mode")
			os.Exit(1)
		}
		if err := validateUsername(username); err != nil {
			logrus.Errorf("%v", err)
			os.Exit(1)
		}
		scramAuthenticator.PriorityUsername = username
		scramAuthenticator.PriorityPassword = password
	}

	if scramAuthenticator.PriorityUsername == "" && len(scramAuthenticator.Credentials) == 0 {
		logrus.Errorf("either --scram-credential or both --username and --password are required")
		os.Exit(1)
	}

	if err := scramAuthenticator.load(); err != nil {
		logrus.Errorf("failed to load credentials: %v", err)
		os.Exit(1)
	}

	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: shared.Handshake,
		Plugins: map[string]plugin.Plugin{
			"scramAuthenticator": &shared.ScramAuthenticatorPlugin{Impl: scramAuthenticator},
		},
		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
