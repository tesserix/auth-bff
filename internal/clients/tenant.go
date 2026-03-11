package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/tesserix/go-shared/serviceclient"
)

// TenantClient communicates with the tenant-service using auto-authenticated
// service-to-service calls (OIDC on Cloud Run, shared key for local dev).
type TenantClient struct {
	client *serviceclient.Client
}

// NewTenantClient creates a new tenant-service client with automatic auth.
func NewTenantClient(baseURL string) (*TenantClient, error) {
	client, err := serviceclient.NewClient(baseURL)
	if err != nil {
		return nil, fmt.Errorf("create tenant client: %w", err)
	}
	return &TenantClient{client: client}, nil
}

// Tenant represents a tenant returned from lookup.
type Tenant struct {
	ID      string `json:"id"`
	Slug    string `json:"slug"`
	Name    string `json:"name"`
	LogoURL string `json:"logo_url,omitempty"`
}

// UserTenantsResponse is the response from GET /tenants/user-tenants.
type UserTenantsResponse struct {
	Tenants      []Tenant `json:"tenants"`
	Count        int      `json:"count"`
	SingleTenant bool     `json:"single_tenant"`
}

// GetUserTenants looks up tenants associated with an email.
func (c *TenantClient) GetUserTenants(ctx context.Context, email string) (*UserTenantsResponse, error) {
	body := map[string]string{"email": email}
	var resp UserTenantsResponse
	if err := c.client.Post(ctx, "/api/v1/auth/lookup-tenants", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ValidateCredentialsRequest is the request for credential validation.
type ValidateCredentialsRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	TenantSlug  string `json:"tenant_slug,omitempty"`
	TenantID    string `json:"tenant_id,omitempty"`
	AuthContext string `json:"auth_context"` // "staff" or "customer"
	ClientIP    string `json:"client_ip,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
}

// ValidateCredentialsResponse is the response from credential validation.
type ValidateCredentialsResponse struct {
	Valid           bool   `json:"valid"`
	UserID          string `json:"user_id,omitempty"`
	IDPUserID       string `json:"idp_user_id,omitempty"`
	TenantID        string `json:"tenant_id,omitempty"`
	TenantSlug      string `json:"tenant_slug,omitempty"`
	Email           string `json:"email,omitempty"`
	FirstName       string `json:"first_name,omitempty"`
	LastName        string `json:"last_name,omitempty"`
	Role            string `json:"role,omitempty"`
	MFARequired     bool   `json:"mfa_required"`
	MFAEnabled      bool   `json:"mfa_enabled"`
	TOTPEnabled     bool   `json:"totp_enabled"`
	AccountLocked   bool   `json:"account_locked"`
	LockedUntil     string `json:"locked_until,omitempty"`
	GoogleLinked    bool   `json:"google_linked"`
	AccessToken     string `json:"access_token,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	IDToken         string `json:"id_token,omitempty"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	Error           string `json:"error,omitempty"`
	ErrorMessage    string `json:"error_message,omitempty"`
}

// ValidateCredentials validates user credentials via tenant-service.
// tenant-service wraps success responses under {"data": ...} via SuccessResponse(),
// but returns failure responses (401) as flat JSON. serviceclient treats 4xx as errors,
// so we need to handle both paths:
//   - 200 success: parse wrapper, extract from "data"
//   - 401 failure: serviceclient returns error containing the JSON body
func (c *TenantClient) ValidateCredentials(ctx context.Context, req *ValidateCredentialsRequest) (*ValidateCredentialsResponse, error) {
	var wrapper struct {
		Success bool                        `json:"success"`
		Data    *ValidateCredentialsResponse `json:"data"`
	}
	err := c.client.Post(ctx, "/api/v1/auth/validate-credentials", req, &wrapper)
	if err != nil {
		// serviceclient returns error for 4xx — parse the JSON body from the error message
		// to extract structured failure info (account_locked, error_code, etc.)
		// tenant-service failure response uses "error_code" and "message" field names,
		// which differ from auth-bff's "error" and "error_message" — map them here.
		errStr := err.Error()
		if idx := strings.Index(errStr, "{"); idx >= 0 {
			jsonBody := errStr[idx:]
			var raw struct {
				Valid            bool   `json:"valid"`
				ErrorCode        string `json:"error_code"`
				Message          string `json:"message"`
				AccountLocked    bool   `json:"account_locked"`
				LockedUntil      string `json:"locked_until"`
				RemainingAttempts int   `json:"remaining_attempts"`
				TenantID         string `json:"tenant_id"`
				TenantSlug       string `json:"tenant_slug"`
			}
			if jsonErr := json.Unmarshal([]byte(jsonBody), &raw); jsonErr == nil && raw.ErrorCode != "" {
				return &ValidateCredentialsResponse{
					Valid:         raw.Valid,
					Error:         raw.ErrorCode,
					ErrorMessage:  raw.Message,
					AccountLocked: raw.AccountLocked,
					LockedUntil:   raw.LockedUntil,
					TenantID:      raw.TenantID,
					TenantSlug:    raw.TenantSlug,
				}, nil
			}
		}
		return nil, err
	}

	// Success: unwrap from "data" envelope
	if wrapper.Data != nil {
		return wrapper.Data, nil
	}

	// Fallback: if "data" is nil but response was 200, return empty invalid response
	return &ValidateCredentialsResponse{Valid: false, Error: "EMPTY_RESPONSE"}, nil
}

// RegisterCustomerRequest is the request for customer registration.
type RegisterCustomerRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Phone      string `json:"phone,omitempty"`
	TenantSlug string `json:"tenant_slug"`
}

// RegisterCustomerResponse is the response from customer registration.
type RegisterCustomerResponse struct {
	Success      bool   `json:"success"`
	UserID       string `json:"user_id,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	Error        string `json:"error,omitempty"`
	Message      string `json:"message,omitempty"`
}

// RegisterCustomer registers a new customer.
func (c *TenantClient) RegisterCustomer(ctx context.Context, req *RegisterCustomerRequest) (*RegisterCustomerResponse, error) {
	var resp RegisterCustomerResponse
	if err := c.client.Post(ctx, "/api/v1/auth/register", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PasswordResetRequest is the request for initiating password reset.
type PasswordResetRequest struct {
	Email      string `json:"email"`
	TenantSlug string `json:"tenant_slug"`
	Context    string `json:"context,omitempty"` // "admin" or "storefront"
}

// RequestPasswordReset initiates a password reset.
func (c *TenantClient) RequestPasswordReset(ctx context.Context, req *PasswordResetRequest) error {
	var resp map[string]interface{}
	return c.client.Post(ctx, "/api/v1/auth/request-password-reset", req, &resp)
}

// ResetPassword completes a password reset with a token.
func (c *TenantClient) ResetPassword(ctx context.Context, token, newPassword string) error {
	body := map[string]string{"token": token, "new_password": newPassword}
	var resp map[string]interface{}
	return c.client.Post(ctx, "/api/v1/auth/reset-password", body, &resp)
}

// ValidateResetToken checks if a reset token is valid.
func (c *TenantClient) ValidateResetToken(ctx context.Context, token string) (bool, int, error) {
	body := map[string]string{"token": token}
	var resp struct {
		Valid     bool `json:"valid"`
		ExpiresIn int  `json:"expires_in"`
	}
	if err := c.client.Post(ctx, "/api/v1/auth/validate-reset-token", body, &resp); err != nil {
		return false, 0, err
	}
	return resp.Valid, resp.ExpiresIn, nil
}

// ChangePassword changes an authenticated user's password.
func (c *TenantClient) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	body := map[string]string{
		"user_id":          userID,
		"current_password": currentPassword,
		"new_password":     newPassword,
	}
	var resp map[string]interface{}
	return c.client.Post(ctx, "/api/v1/auth/change-password", body, &resp)
}

// TOTPSecretResponse is the response from getting TOTP secret.
type TOTPSecretResponse struct {
	TOTPEnabled          bool     `json:"totp_enabled"`
	TOTPSecretEncrypted  string   `json:"totp_secret_encrypted,omitempty"`
	BackupCodeHashes     []string `json:"backup_code_hashes,omitempty"`
	BackupCodesRemaining int      `json:"backup_codes_remaining"`
}

// GetTOTPSecret fetches the TOTP secret for a user.
func (c *TenantClient) GetTOTPSecret(ctx context.Context, userID, tenantID string) (*TOTPSecretResponse, error) {
	var resp TOTPSecretResponse
	endpoint := fmt.Sprintf("/api/v1/auth/totp/secret?user_id=%s&tenant_id=%s", userID, tenantID)
	if err := c.client.Get(ctx, endpoint, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EnableTOTP enables TOTP for a user with the encrypted secret and backup code hashes.
func (c *TenantClient) EnableTOTP(ctx context.Context, userID, tenantID, encryptedSecret string, backupCodeHashes []string) error {
	body := map[string]interface{}{
		"user_id":            userID,
		"tenant_id":          tenantID,
		"encrypted_secret":   encryptedSecret,
		"backup_code_hashes": backupCodeHashes,
	}
	var resp map[string]interface{}
	return c.client.Post(ctx, "/api/v1/auth/totp/enable", body, &resp)
}

// DisableTOTP disables TOTP for a user.
func (c *TenantClient) DisableTOTP(ctx context.Context, userID, tenantID string) error {
	body := map[string]string{"user_id": userID, "tenant_id": tenantID}
	var resp map[string]interface{}
	return c.client.Post(ctx, "/api/v1/auth/totp/disable", body, &resp)
}

// ConsumeBackupCode marks a backup code as used.
func (c *TenantClient) ConsumeBackupCode(ctx context.Context, userID, tenantID, codeHash string) error {
	body := map[string]string{
		"user_id":   userID,
		"tenant_id": tenantID,
		"code_hash": codeHash,
	}
	var resp map[string]interface{}
	return c.client.Post(ctx, "/api/v1/auth/totp/consume-backup", body, &resp)
}

// RegenerateBackupCodes generates new backup codes for a user.
func (c *TenantClient) RegenerateBackupCodes(ctx context.Context, userID, tenantID string, hashes []string) error {
	body := map[string]interface{}{
		"user_id":            userID,
		"tenant_id":          tenantID,
		"backup_code_hashes": hashes,
	}
	var resp map[string]interface{}
	return c.client.Post(ctx, "/api/v1/auth/totp/regenerate-backups", body, &resp)
}

// PasskeyCredential represents a stored passkey.
type PasskeyCredential struct {
	CredentialID string   `json:"credential_id"`
	PublicKey    string   `json:"public_key"`
	Name         string   `json:"name"`
	Transports   []string `json:"transports,omitempty"`
	SignCount    uint32   `json:"sign_count"`
	CreatedAt    string   `json:"created_at"`
	LastUsedAt   string   `json:"last_used_at,omitempty"`
}

// GetPasskeys fetches all passkeys for a user.
func (c *TenantClient) GetPasskeys(ctx context.Context, userID, tenantID string) ([]PasskeyCredential, error) {
	var resp struct {
		Passkeys []PasskeyCredential `json:"passkeys"`
	}
	endpoint := fmt.Sprintf("/api/v1/auth/passkeys?user_id=%s&tenant_id=%s", userID, tenantID)
	if err := c.client.Get(ctx, endpoint, &resp); err != nil {
		return nil, err
	}
	return resp.Passkeys, nil
}

// SavePasskey stores a new passkey credential.
func (c *TenantClient) SavePasskey(ctx context.Context, userID, tenantID string, cred *PasskeyCredential) error {
	body := map[string]interface{}{
		"user_id":       userID,
		"tenant_id":     tenantID,
		"credential_id": cred.CredentialID,
		"public_key":    cred.PublicKey,
		"name":          cred.Name,
		"transports":    cred.Transports,
		"sign_count":    cred.SignCount,
	}
	var resp map[string]interface{}
	return c.client.Post(ctx, "/api/v1/auth/passkeys", body, &resp)
}

// DeletePasskey removes a passkey credential.
func (c *TenantClient) DeletePasskey(ctx context.Context, userID, tenantID, credentialID string) error {
	endpoint := fmt.Sprintf("/api/v1/auth/passkeys/%s?user_id=%s&tenant_id=%s", credentialID, userID, tenantID)
	return c.client.Delete(ctx, endpoint, nil)
}

// AccountStatusResponse represents account status.
type AccountStatusResponse struct {
	AccountExists     bool   `json:"account_exists"`
	AccountLocked     bool   `json:"account_locked"`
	LockedUntil       string `json:"locked_until,omitempty"`
	RemainingAttempts int    `json:"remaining_attempts"`
}

func (c *TenantClient) CheckAccountStatus(ctx context.Context, email, tenantSlug string) (*AccountStatusResponse, error) {
	body := map[string]string{"email": email, "tenant_slug": tenantSlug}
	var resp AccountStatusResponse
	if err := c.client.Post(ctx, "/api/v1/auth/account-status", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeactivatedResponse represents deactivation status.
type DeactivatedResponse struct {
	IsDeactivated  bool   `json:"is_deactivated"`
	CanReactivate  bool   `json:"can_reactivate"`
	DaysUntilPurge int    `json:"days_until_purge"`
	DeactivatedAt  string `json:"deactivated_at,omitempty"`
	PurgeDate      string `json:"purge_date,omitempty"`
}

func (c *TenantClient) CheckDeactivated(ctx context.Context, email, tenantSlug string) (*DeactivatedResponse, error) {
	body := map[string]string{"email": email, "tenant_slug": tenantSlug}
	var resp DeactivatedResponse
	if err := c.client.Post(ctx, "/api/v1/auth/check-deactivated", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReactivateAccount reactivates a deactivated account.
func (c *TenantClient) ReactivateAccount(ctx context.Context, email, password, tenantSlug string) error {
	body := map[string]string{"email": email, "password": password, "tenant_slug": tenantSlug}
	var resp map[string]interface{}
	return c.client.Post(ctx, "/api/v1/auth/reactivate", body, &resp)
}

// DeactivateAccount deactivates a user account.
func (c *TenantClient) DeactivateAccount(ctx context.Context, userID, tenantID, reason string) error {
	body := map[string]string{"user_id": userID, "tenant_id": tenantID, "reason": reason}
	var resp map[string]interface{}
	return c.client.Post(ctx, "/api/v1/auth/deactivate", body, &resp)
}
