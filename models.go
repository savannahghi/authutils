package authutils

import (
	"time"

	validator "gopkg.in/go-playground/validator.v9"
)

var v = validator.New()

// OAUTHResponse defines the object returned when a user successfully logs in
type OAUTHResponse struct {
	Scope        string `json:"scope"`
	ExpiresIn    int    `json:"expires_in"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

// MeResponse defines the object returned when a user's existence is validated on the authserver
type MeResponse struct {
	ID          int      `json:"id"`
	GUID        string   `json:"guid"`
	Email       string   `json:"email"`
	FirstName   string   `json:"first_name"`
	LastName    string   `json:"last_name"`
	OtherNames  string   `json:"other_names"`
	IsStaff     bool     `json:"is_staff"`
	IsActive    bool     `json:"is_active"`
	Permissions []string `json:"permissions"`
}

// LoginPayload defines the payload passed when logging in to slade 360 auth server
type LoginPayload struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Username     string `json:"username"`
	Password     string `json:"password"`
}

// TokenIntrospectionResponse defines the JSON object returned by slade auth server service during token introspection
type TokenIntrospectionResponse struct {
	ClientID string    `json:"client_id"`
	Expires  time.Time `json:"expires"`
	IsValid  bool      `json:"is_valid"`
	Scope    string    `json:"scope"`
	Token    string    `json:"token"`
	UserGUID string    `json:"user_guid"`
}

// TokenIntrospectionPayload defines the json object passed when introspecting a token
type TokenIntrospectionPayload struct {
	TokenType string `json:"token_type"`
	Token     string `json:"token"`
}

// CreateUserPayload defines the object passed when creating a user on authserver
type CreateUserPayload struct {
	Firstname       string `json:"first_name"`
	Lastname        string `json:"last_name"`
	Othernames      string `json:"other_names"`
	Email           string `json:"email"`
	IsActive        bool   `json:"is_active"`
	NewPassword     string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
	Organisation    string `json:"organisation"`
	AgreedToTerms   bool   `json:"agreed_to_terms"`
}

// CreateUserResponse defines the json object returned when a user is successfully created on Slade360 Auth Server
type CreateUserResponse struct {
	ID                 int           `json:"id"`
	GUID               string        `json:"guid"`
	Email              string        `json:"email"`
	FirstName          string        `json:"first_name"`
	LastName           string        `json:"last_name"`
	OtherNames         string        `json:"other_names"`
	IsStaff            bool          `json:"is_staff"`
	IsActive           bool          `json:"is_active"`
	DateJoined         time.Time     `json:"date_joined"`
	AgreedToTerms      bool          `json:"agreed_to_terms"`
	LastPasswordChange time.Time     `json:"last_password_change"`
	BusinessPartner    string        `json:"business_partner"`
	LastLogin          time.Time     `json:"last_login"`
	UserRoles          []interface{} `json:"user_roles"`
}

// PasswordResetPayload defines the object needed when making a password reset request
type PasswordResetPayload struct {
	Origin  string `json:"origin" validate:"required"`
	Variant string `json:"variant" validate:"required"`
	Email   string `json:"email" validate:"required,email"`
}

// EmailResetPayload defines object needed when making a password request
type EmailResetPayload struct {
	Email string `json:"email"`
}

// ResetPasswordResponse defines return the json object returned when password reset instruction has been sent
type PasswordResetResponse struct {
	Detail string `json:"detail"`
}

// LoginUserPayload defines the object passed when a user logs in
type LoginUserPayload struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// Validate ensures that the input passes validation checks
func (s *LoginUserPayload) Validate() error {
	err := v.Struct(s)
	if err != nil {
		return err
	}

	return nil
}

// Validate ensures that the reset password payload passes the validation checks
func (p *PasswordResetPayload) Validate() error {
	err := v.Struct(p)
	if err != nil {
		return err
	}
	return nil
}
