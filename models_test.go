package authutils

import "testing"

func TestLoginUserPayload_Validate(t *testing.T) {
	type args struct {
		payload LoginUserPayload
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success: valid payload",
			args: args{
				LoginUserPayload{
					Email:    "gojo@gmail.com",
					Password: "yessir",
				},
			},
			wantErr: false,
		},
		{
			name: "fail: no email",
			args: args{
				LoginUserPayload{
					Password: "yessir",
				},
			},
			wantErr: true,
		},
		{
			name: "fail: no password",
			args: args{
				LoginUserPayload{
					Email: "gojo@gmail.com",
				},
			},
			wantErr: true,
		},
		{
			name: "fail: invalid email",
			args: args{
				LoginUserPayload{
					Email:    "gojo",
					Password: "yessir",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.args.payload
			if err := s.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("LoginUserPayload.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestResetPasswordPayload_Validate(t *testing.T) {
	type args struct {
		payload PasswordResetPayload
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Happy case: valid payload",
			args: args{
				payload: PasswordResetPayload{
					Email:   "testuser@example.com",
					Variant: "UzaziSalamaProd",
					Origin:  "https://localhost:test.com",
				},
			},
			wantErr: false,
		},
		{
			name: "Sad case: invalid email",
			args: args{
				payload: PasswordResetPayload{
					Email:   "testuserexample",
					Variant: "UzaziSalamaProd",
					Origin:  "https://localhost:test.com",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.args.payload
			if err := p.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("PasswordResetPayload.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
