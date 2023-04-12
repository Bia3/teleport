/*
Copyright 2023 Gravitational, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package web

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/jwt"
	"github.com/gravitational/teleport/lib/reversetunnel"
)

const (
	// OIDCJWKWPartialURI is the relative path where the OIDC IdP JWKS is located
	OIDCJWKWPartialURI = "/.well-known/jwks-oidc"
)

// IdentityToken is a
type IdentityToken string

// GetIdentityToken returns the token configured
func (j IdentityToken) GetIdentityToken() ([]byte, error) {
	return []byte(j), nil
}

// openidConfiguration returns the openid-configuration for setting up the AWS OIDC Integration
func (h *Handler) openidConfiguration(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
	host, _, err := net.SplitHostPort(h.PublicProxyAddr())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	issuer := fmt.Sprintf("https://%s", host)

	return struct {
		Issuer                           string   `json:"issuer,omitempty"`
		JWKSURI                          string   `json:"jwks_uri,omitempty"`
		Claims                           []string `json:"claims,omitempty"`
		IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported,omitempty"`
		ResponseTypesSupported           []string `json:"response_types_supported,omitempty"`
		ScopesSupported                  []string `json:"scopes_supported,omitempty"`
		SubjectTypesSupported            []string `json:"subject_types_supported,omitempty"`
	}{
		Issuer:                           issuer,
		JWKSURI:                          issuer + OIDCJWKWPartialURI,
		Claims:                           []string{"iss", "sub", "obo", "aud", "jti", "iat", "exp", "nbf"},
		IdTokenSigningAlgValuesSupported: []string{"RS256"},
		ResponseTypesSupported:           []string{"id_token"},
		ScopesSupported:                  []string{"openid"},
		SubjectTypesSupported:            []string{"public", "pair-wise"},
	}, nil
}

// jwksOIDC returns all public keys used to sign JWT tokens for this cluster.
func (h *Handler) jwksOIDC(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {
	clusterName, err := h.cfg.ProxyClient.GetDomainName(r.Context())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Fetch the JWT public keys only.
	ca, err := h.cfg.ProxyClient.GetCertAuthority(r.Context(), types.CertAuthID{
		Type:       types.OIDCIdPCA,
		DomainName: clusterName,
	}, false)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	pairs := ca.GetTrustedJWTKeyPairs()

	// Create response and allocate space for the keys.
	var resp JWKSResponse
	resp.Keys = make([]jwt.JWK, 0, len(pairs))

	// Loop over and all add public keys in JWK format.
	for _, key := range pairs {
		jwk, err := jwt.MarshalJWK(key.PublicKey)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		resp.Keys = append(resp.Keys, jwk)
	}
	return &resp, nil
}

func (h *Handler) integrationsExecute(w http.ResponseWriter, r *http.Request, p httprouter.Params, sctx *SessionContext, site reversetunnel.RemoteSite) (interface{}, error) {
	integrationName := p.ByName("name")
	if integrationName == "" {
		return nil, trace.BadParameter("an integration name is required")
	}

	actionName := p.ByName("action")
	if actionName == "" {
		return nil, trace.BadParameter("an action name is required")
	}

	clt, err := sctx.GetUserClient(r.Context(), site)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	integration, err := clt.GetIntegration(r.Context(), integrationName)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if integration.GetSubKind() != types.IntegrationSubKindAWSOIDC {
		if err != nil {
			return nil, trace.BadParameter("unexpected integration subkind")
		}
	}
	roleARN := integration.GetAWSOIDCIntegrationSpec().RoleARN

	// comes from request
	awsRegion := "us-east-1"

	return h.executeAWSOIDCAction(r, clt, awsRegion, roleARN)
}

func (h *Handler) integrationsExecute2(w http.ResponseWriter, r *http.Request, p httprouter.Params) (interface{}, error) {

	// comes from integration 👆
	roleARN := "arn:aws:iam::278576220453:role/MarcoTestRoleOIDCProvider"

	// comes from request
	awsRegion := "us-east-1"

	return h.executeAWSOIDCAction(r, h.auth.proxyClient, awsRegion, roleARN)
}

func (h *Handler) executeAWSOIDCAction(r *http.Request, clt auth.ClientI, awsRegion string, roleARN string) (any, error) {
	host, _, err := net.SplitHostPort(h.PublicProxyAddr())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	issuer := fmt.Sprintf("https://%s", host)

	token, err := clt.GenerateAWSOIDCToken(r.Context(), types.GenerateAWSOIDCTokenRequest{
		Issuer: issuer,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cfg, err := config.LoadDefaultConfig(r.Context(), config.WithRegion(awsRegion))
	if err != nil {
		return nil, trace.Wrap(err)
	}

	cfg.Credentials = stscreds.NewWebIdentityRoleProvider(
		sts.NewFromConfig(cfg),
		roleARN,
		IdentityToken(token),
	)

	rdsClient := rds.NewFromConfig(cfg)
	rdsDBs, err := rdsClient.DescribeDBInstances(r.Context(), &rds.DescribeDBInstancesInput{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	result := make([]string, 0, len(rdsDBs.DBInstances))

	for _, db := range rdsDBs.DBInstances {
		result = append(result, fmt.Sprintf("engine=%q", *db.Engine))
	}

	return strings.Join(result, "\n"), nil
}
