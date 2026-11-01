package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"

	"github.com/pocket-id/pocket-id/backend/internal/appconfig"
	"github.com/pocket-id/pocket-id/backend/internal/claimmappingpolicy"
	"github.com/pocket-id/pocket-id/backend/internal/model"
	datatype "github.com/pocket-id/pocket-id/backend/internal/model/types"
	testutils "github.com/pocket-id/pocket-id/backend/internal/utils/testing"
)

func TestClaimMappingTokensRefreshCurrentGroupsAndPolicy(t *testing.T) {
	for _, requestedScopes := range []string{"openid offline_access groups read:orders", "offline_access read:orders"} {
		t.Run(requestedScopes, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			const issuer = "https://issuer.example.com"
			const resource = "https://api.example.com/orders"
			const clientID = "claims-client"
			const userID = "claims-user"
			const callback = "https://client.example.com/callback"

			db := testutils.NewDatabaseForTest(t)
			require.NoError(t, claimmappingpolicy.Bootstrap(t.Context(), db))
			policy := claimmappingpolicy.OidcClaimMappingPolicy{
				Base: model.Base{ID: "api-policy"}, Name: "API claims",
				ClaimMappings: claimmappingpolicy.OidcClaimMappings{
					{ClaimName: "groups", SourceType: claimmappingpolicy.MappingSourceUserField, SourceValue: "groups", Scope: []string{"read:orders"}, AccessToken: true},
					{ClaimName: "account_id", SourceType: claimmappingpolicy.MappingSourceCustomClaim, SourceValue: "account_id", Scope: []string{"read:orders"}, AccessToken: true},
				},
			}
			require.NoError(t, db.Create(&policy).Error)
			user := model.User{Base: model.Base{ID: userID}, Username: "original-name"}
			group := model.UserGroup{Base: model.Base{ID: "readers-group"}, Name: "readers", FriendlyName: "Readers"}
			require.NoError(t, db.Create(&user).Error)
			require.NoError(t, db.Create(&group).Error)
			require.NoError(t, db.Model(&user).Association("UserGroups").Append(&group))
			require.NoError(t, db.Create(&model.OidcClient{
				Base: model.Base{ID: clientID}, Name: "Claims client", IsPublic: true, PkceEnabled: true,
				CallbackURLs: datatype.StringList{callback}, ClaimMappingPolicyId: &policy.ID,
			}).Error)
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			apiAccess := fakeAPIAccess{allowed: map[string]map[SubjectType][]string{
				resource: {SubjectTypeUser: {"read:orders"}, SubjectTypeClient: {"read:orders"}},
			}}
			store := NewStore(db, apiAccess)
			provider, err := newProvider(store, nil, algTestSigner{key: key, alg: jwa.RS256()}, Config{BaseURL: issuer, TokenBaseURL: issuer, Secret: []byte("test-secret")}, nil)
			require.NoError(t, err)
			customClaims := fakeCustomClaimSource{claims: []model.CustomClaim{{Key: "account_id", Value: "account-a"}}}
			claims := newClaimsService(db, customClaims, issuer, nil, appconfig.StaticResolver{})
			handler := newTokenHandler(provider, claims, apiAccess)

			requestToken := func(form url.Values, expectedStatus int) map[string]any {
				t.Helper()
				req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/oidc/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				recorder := httptest.NewRecorder()
				ctx, _ := gin.CreateTestContext(recorder)
				ctx.Request = req
				handler.token(ctx)
				require.Equal(t, expectedStatus, recorder.Code, recorder.Body.String())
				var body map[string]any
				require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
				return body
			}
			refresh := func(previous map[string]any, expectedStatus int) map[string]any {
				t.Helper()
				return requestToken(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {previous["refresh_token"].(string)}, "client_id": {clientID}}, expectedStatus)
			}

			// Start after authentication and consent, using the real provider to create and redeem a PKCE-bound authorization code
			verifier := strings.Repeat("v", 64)
			challenge := sha256.Sum256([]byte(verifier))
			params := url.Values{"client_id": {clientID}, "response_type": {"code"}, "redirect_uri": {callback}, "state": {"state-with-enough-entropy"}, "scope": {requestedScopes}, "resource": {resource}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/oidc/authorize?"+params.Encode(), nil)
			authorize, err := provider.NewAuthorizeRequest(t.Context(), req)
			require.NoError(t, err)
			for _, scope := range strings.Fields(requestedScopes) {
				authorize.GrantScope(scope)
			}
			authorize.GrantAudience(resource)
			session := NewAuthenticatedSession(userID, "passkey", time.Now(), time.Now())
			source, err := claims.loadUserClaimsSource(t.Context(), userID, clientID)
			require.NoError(t, err)
			require.Equal(t, policy.ID, source.policy.ID)
			require.Len(t, source.policy.ClaimMappings, 2)
			require.Equal(t, []string{"read:orders"}, []string(source.policy.ClaimMappings[0].Scope))
			require.Equal(t, []string{"readers"}, claims.buildClaims(source, authorize.GetGrantedScopes(), AccessTokenType)["groups"])
			require.NoError(t, claims.applyTokenClaims(session, authorize.GetGrantedScopes(), source))
			response, err := provider.NewAuthorizeResponse(t.Context(), authorize, session)
			require.NoError(t, err)
			first := requestToken(url.Values{"grant_type": {"authorization_code"}, "code": {response.GetCode()}, "client_id": {clientID}, "redirect_uri": {callback}, "code_verifier": {verifier}}, http.StatusOK)
			firstClaims := decodeJWTPart(t, first["access_token"].(string), 1)
			require.Equal(t, []any{"readers"}, firstClaims["groups"])
			require.Equal(t, "account-a", firstClaims["account_id"])
			require.Equal(t, userID, firstClaims["sub"])
			require.Contains(t, jwtAudience(firstClaims), resource)
			if strings.Contains(requestedScopes, "openid") {
				require.NotContains(t, decodeJWTPart(t, first["id_token"].(string), 1), "groups")
			} else {
				require.NotContains(t, first, "id_token")
			}

			// A client with the same mapping policy must not receive human claims when acting as a machine
			require.NoError(t, db.Create(&model.OidcClient{
				Base: model.Base{ID: "machine-client"}, Name: "Machine", ClaimMappingPolicyId: &policy.ID,
				Credentials: testClientCredentials("machine-test-secret"),
			}).Error)
			machine := requestToken(url.Values{"grant_type": {"client_credentials"}, "client_id": {"machine-client"}, "client_secret": {"machine-test-secret"}, "resource": {resource}, "scope": {"openid groups read:orders"}}, http.StatusOK)
			machineClaims := decodeJWTPart(t, machine["access_token"].(string), 1)
			require.Equal(t, "client-machine-client", machineClaims["sub"])
			require.Equal(t, []string{"read:orders"}, jwtScopes(machineClaims))
			require.NotContains(t, machineClaims, "groups")
			require.NotContains(t, machineClaims, "account_id")

			// Removing an account binding must erase it from the next token even when group membership is unchanged
			claims.customClaims = fakeCustomClaimSource{}
			withoutBinding := refresh(first, http.StatusOK)
			withoutBindingClaims := decodeJWTPart(t, withoutBinding["access_token"].(string), 1)
			require.Equal(t, []any{"readers"}, withoutBindingClaims["groups"])
			require.NotContains(t, withoutBindingClaims, "account_id")
			claims.customClaims = customClaims

			// Refresh must use current group membership while retaining the immutable subject and API grant
			require.NoError(t, db.Model(&user).Association("UserGroups").Clear())
			require.NoError(t, db.Model(&user).Update("username", "renamed-user").Error)
			second := refresh(withoutBinding, http.StatusOK)
			secondClaims := decodeJWTPart(t, second["access_token"].(string), 1)
			require.Empty(t, secondClaims["groups"])
			require.Equal(t, userID, secondClaims["sub"])
			require.Equal(t, jwtAudience(firstClaims), jwtAudience(secondClaims))
			require.Equal(t, jwtScopes(firstClaims), jwtScopes(secondClaims))

			// Removing mappings must erase the old claims restored from the refresh-token session
			require.NoError(t, db.Model(&policy).Update("claim_mappings", claimmappingpolicy.OidcClaimMappings{}).Error)
			third := refresh(second, http.StatusOK)
			thirdClaims := decodeJWTPart(t, third["access_token"].(string), 1)
			require.NotContains(t, thirdClaims, "groups")
			require.NotContains(t, thirdClaims, "account_id")
			require.Equal(t, userID, thirdClaims["sub"])

			// Disabling the user must prevent the next refresh from minting a new token
			require.NoError(t, db.Model(&user).Update("disabled", true).Error)
			require.Equal(t, "invalid_grant", refresh(third, http.StatusBadRequest)["error"])
		})
	}
}

func TestClaimMappingAccessTokenDisclosure(t *testing.T) {
	db := testutils.NewDatabaseForTest(t)
	require.NoError(t, claimmappingpolicy.Bootstrap(t.Context(), db))
	policy := claimmappingpolicy.OidcClaimMappingPolicy{
		Base: model.Base{ID: "access-policy"}, Name: "Access claims",
		ClaimMappings: claimmappingpolicy.OidcClaimMappings{
			{ClaimName: "groups", SourceType: claimmappingpolicy.MappingSourceUserField, SourceValue: "groups", Scope: []string{"groups"}, AccessToken: true},
			{ClaimName: "account_id", SourceType: claimmappingpolicy.MappingSourceCustomClaim, SourceValue: "account_id", Scope: []string{"groups"}, AccessToken: true},
		},
	}
	require.NoError(t, db.Create(&policy).Error)
	user := model.User{Base: model.Base{ID: "disclosure-user"}, Username: "disclosure", Email: stringPointer("disclosure@example.com")}
	require.NoError(t, db.Create(&user).Error)
	require.NoError(t, db.Create(&model.OidcClient{Base: model.Base{ID: "mapped-client"}, Name: "Mapped", ClaimMappingPolicyId: &policy.ID}).Error)
	require.NoError(t, db.Create(&model.OidcClient{Base: model.Base{ID: "default-client"}, Name: "Default"}).Error)
	customClaims := fakeCustomClaimSource{claims: []model.CustomClaim{{Key: "account_id", Value: "account-a"}, {Key: "private_note", Value: "must-stay-private"}}}
	service := newClaimsService(db, customClaims, "", nil, appconfig.StaticResolver{})
	for _, clientID := range []string{"mapped-client", "default-client"} {
		for _, scopes := range [][]string{{"openid"}, {"groups"}, {"profile", "email", "groups"}} {
			t.Run(clientID+"/"+strings.Join(scopes, "+"), func(t *testing.T) {
				source, err := service.loadUserClaimsSource(t.Context(), user.ID, clientID)
				require.NoError(t, err)
				claims := service.buildClaims(source, scopes, AccessTokenType)
				if clientID == "mapped-client" && len(scopes) > 0 && scopes[len(scopes)-1] == "groups" {
					require.Equal(t, "account-a", claims["account_id"])
					require.Equal(t, []string{}, claims["groups"])
				} else {
					require.Empty(t, claims)
				}
				require.NotContains(t, claims, "email")
				require.NotContains(t, claims, "private_note")
			})
		}
	}
}
