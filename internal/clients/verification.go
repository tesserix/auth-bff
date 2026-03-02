package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/tesserix/go-shared/httpclient"
)

// VerificationClient communicates with the verification-service for OTP.
type VerificationClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewVerificationClient creates a new verification-service client.
func NewVerificationClient(baseURL, apiKey string) *VerificationClient {
	return &VerificationClient{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: httpclient.NewClientWithProfile(httpclient.ProfileDefault),
	}
}

// SendOTPRequest is the request to send an OTP.
type SendOTPRequest struct {
	Recipient string            `json:"recipient"`
	Channel   string            `json:"channel"` // "email" or "sms"
	Purpose   string            `json:"purpose"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// OTPResponse is a generic OTP operation response.
type OTPResponse struct {
	Success bool        `json:"success"`
	Status  int         `json:"status"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
}

// SendOTP sends a verification code.
func (v *VerificationClient) SendOTP(ctx context.Context, req *SendOTPRequest) (*OTPResponse, error) {
	var resp OTPResponse
	if err := v.doPost(ctx, "/api/v1/verify/send", req, &resp); err != nil {
		return &OTPResponse{Success: false, Status: 503, Error: "unavailable"}, nil
	}
	return &resp, nil
}

// VerifyOTPRequest is the request to verify an OTP code.
type VerifyOTPRequest struct {
	Recipient string `json:"recipient"`
	Code      string `json:"code"`
	Purpose   string `json:"purpose"`
}

// VerifyOTPResponse is the response from OTP verification.
type VerifyOTPResponse struct {
	Success           bool   `json:"success"`
	Verified          bool   `json:"verified"`
	Message           string `json:"message,omitempty"`
	RemainingAttempts int    `json:"remainingAttempts,omitempty"`
}

// VerifyOTP verifies a submitted code.
func (v *VerificationClient) VerifyOTP(ctx context.Context, req *VerifyOTPRequest) (*VerifyOTPResponse, error) {
	var resp VerifyOTPResponse
	if err := v.doPost(ctx, "/api/v1/verify/code", req, &resp); err != nil {
		return &VerifyOTPResponse{Success: false, Verified: false, Message: "unavailable"}, nil
	}
	return &resp, nil
}

// GetOTPStatus checks the status of a verification.
func (v *VerificationClient) GetOTPStatus(ctx context.Context, email, purpose string) (*OTPResponse, error) {
	endpoint := fmt.Sprintf("/api/v1/verify/status?email=%s&purpose=%s", email, purpose)
	var resp OTPResponse
	if err := v.doGet(ctx, endpoint, &resp); err != nil {
		return &OTPResponse{Success: false, Status: 503, Error: "unavailable"}, nil
	}
	return &resp, nil
}

func (v *VerificationClient) doPost(ctx context.Context, path string, body interface{}, result interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if v.apiKey != "" {
		req.Header.Set("X-API-Key", v.apiKey)
	}

	return v.doRequest(req, result)
}

func (v *VerificationClient) doGet(ctx context.Context, path string, result interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.baseURL+path, nil)
	if err != nil {
		return err
	}
	if v.apiKey != "" {
		req.Header.Set("X-API-Key", v.apiKey)
	}

	return v.doRequest(req, result)
}

func (v *VerificationClient) doRequest(req *http.Request, result interface{}) error {
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("verification-service %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil && len(respBody) > 0 {
		return json.Unmarshal(respBody, result)
	}
	return nil
}
