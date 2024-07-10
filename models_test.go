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
