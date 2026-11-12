package connector

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	cfg "github.com/conductorone/baton-opensearch/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTLSServer starts a TLS server with a self-signed certificate that answers every request with an empty JSON object.
func newTLSServer(t *testing.T) (*httptest.Server, []byte) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(server.Close)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	return server, caPEM
}

func TestNewTLS(t *testing.T) {
	server, caPEM := newTLSServer(t)

	tests := []struct {
		name               string
		insecureSkipVerify bool
		caCert             []byte
		wantNewErr         string
		wantRequestErr     string
	}{
		{
			name:   "valid CA cert is trusted",
			caCert: caPEM,
		},
		{
			name:           "no CA cert falls back to system pool and rejects self-signed server",
			wantRequestErr: "certificate",
		},
		{
			name:               "insecure skip verify accepts self-signed server",
			insecureSkipVerify: true,
		},
		{
			name:               "insecure skip verify ignores invalid CA cert",
			insecureSkipVerify: true,
			caCert:             []byte("not a certificate"),
		},
		{
			name:       "invalid CA cert is rejected",
			caCert:     []byte("not a certificate"),
			wantNewErr: "failed to parse CA certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cb, _, err := New(ctx, &cfg.Opensearch{
				Address:            server.URL,
				Username:           "admin",
				Password:           "admin",
				InsecureSkipVerify: tt.insecureSkipVerify,
				CaCertPath:         tt.caCert,
			}, nil)
			if tt.wantNewErr != "" {
				require.ErrorContains(t, err, tt.wantNewErr)
				return
			}
			require.NoError(t, err)

			c, ok := cb.(*Connector)
			require.True(t, ok)

			_, err = c.client.GetRoles(ctx)
			if tt.wantRequestErr != "" {
				assert.ErrorContains(t, err, tt.wantRequestErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}
