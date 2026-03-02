package session

import "time"

// Session represents an authenticated user session stored in Redis.
// JSON tags use camelCase for backward compatibility with the TypeScript BFF
// during blue-green migration.
type Session struct {
	ID             string    `json:"id"`
	UserID         string    `json:"userId"`
	Email          string    `json:"email"`
	TenantID       string    `json:"tenantId"`
	TenantSlug     string    `json:"tenantSlug"`
	ClientType     string    `json:"clientType"` // "internal" or "customer"
	AccessToken    string    `json:"accessToken"`
	IDToken        string    `json:"idToken"`
	RefreshToken   string    `json:"refreshToken"`
	ExpiresAt      int64     `json:"expiresAt"` // Token expiry (unix seconds)
	UserInfo       *UserInfo `json:"userInfo,omitempty"`
	CSRFToken      string    `json:"csrfToken"`
	CreatedAt      int64     `json:"createdAt"`
	LastAccessedAt int64     `json:"lastAccessedAt"`
	AppName        string    `json:"appName,omitempty"` // Which app created this session
}

// UserInfo holds Keycloak user claims.
type UserInfo struct {
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Name              string   `json:"name"`
	GivenName         string   `json:"given_name"`
	FamilyName        string   `json:"family_name"`
	PreferredUsername  string   `json:"preferred_username"`
	TenantID          string   `json:"tenant_id,omitempty"`
	TenantSlug        string   `json:"tenant_slug,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	RealmAccessRoles  []string `json:"realm_access_roles,omitempty"`
	IsPlatformOwner   bool     `json:"is_platform_owner,omitempty"`
}

// AuthFlowState holds PKCE state during the OIDC authorization flow.
// Single-use: deleted after consumption.
type AuthFlowState struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"codeVerifier"`
	RedirectURI  string `json:"redirectUri"`
	ClientType   string `json:"clientType"` // "internal" or "customer"
	ReturnTo     string `json:"returnTo,omitempty"`
	TenantID     string `json:"tenantId,omitempty"`
	TenantSlug   string `json:"tenantSlug,omitempty"`
	IDPHint      string `json:"idpHint,omitempty"`
	AppName      string `json:"appName,omitempty"`
	CreatedAt    int64  `json:"createdAt"`
}

// MFASession holds partial login state awaiting MFA verification.
type MFASession struct {
	ID           string `json:"id"`
	UserID       string `json:"userId"`
	Email        string `json:"email"`
	TenantID     string `json:"tenantId"`
	TenantSlug   string `json:"tenantSlug"`
	ClientType   string `json:"clientType"`
	AccessToken  string `json:"accessToken"`
	IDToken      string `json:"idToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    int64  `json:"expiresAt"`
	MFAEnabled   bool   `json:"mfaEnabled"`
	TOTPEnabled  bool   `json:"totpEnabled"`
	AttemptCount int    `json:"attemptCount"`
	AppName      string `json:"appName,omitempty"`
}

// TOTPSetupSession holds temporary TOTP setup data.
type TOTPSetupSession struct {
	UserID           string   `json:"userId,omitempty"`
	Email            string   `json:"email,omitempty"`
	EncryptedSecret  string   `json:"encryptedSecret"`
	BackupCodeHashes []string `json:"backupCodeHashes"`
}

// PasskeyChallenge holds WebAuthn challenge data.
type PasskeyChallenge struct {
	Type       string `json:"type"` // "registration" or "authentication"
	Challenge  string `json:"challenge"`
	UserID     string `json:"userId,omitempty"`
	TenantID   string `json:"tenantId,omitempty"`
	TenantSlug string `json:"tenantSlug,omitempty"`
	RPID       string `json:"rpId"`
}

// SessionTransfer holds cross-app session transfer data.
type SessionTransfer struct {
	SessionID  string `json:"sessionId"`
	UserID     string `json:"userId"`
	TenantID   string `json:"tenantId"`
	TenantSlug string `json:"tenantSlug"`
	SourceApp  string `json:"sourceApp"`
	TargetApp  string `json:"targetApp"`
}

// WSTicket holds a short-lived WebSocket auth ticket.
type WSTicket struct {
	UserID     string `json:"userId"`
	TenantID   string `json:"tenantId"`
	TenantSlug string `json:"tenantSlug"`
	SessionID  string `json:"sessionId"`
}

// Key prefixes and TTLs for Redis storage.
const (
	PrefixSession         = "bff:session:"
	PrefixAuthFlow        = "bff:auth_flow:"
	PrefixWSTicket        = "bff:ws_ticket:"
	PrefixSessionTransfer = "bff:session_transfer:"
	PrefixMFASession      = "bff:mfa_session:"
	PrefixDeviceTrust     = "bff:device_trust:"
	PrefixTOTPSetup       = "bff:totp_setup:"
	PrefixPasskeyChallenge = "bff:passkey_challenge:"
	PrefixRateLimit       = "bff:rate_limit:"

	TTLSession         = 24 * time.Hour
	TTLAuthFlow        = 10 * time.Minute
	TTLWSTicket        = 30 * time.Second
	TTLSessionTransfer = 60 * time.Second
	TTLMFASession      = 5 * time.Minute
	TTLDeviceTrust     = 30 * 24 * time.Hour
	TTLTOTPSetup       = 10 * time.Minute
	TTLPasskeyChallenge = 5 * time.Minute
)
