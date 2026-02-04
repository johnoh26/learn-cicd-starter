package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}{
		{
			name:    "valid authorization header",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			want:    "my-secret-key",
			wantErr: nil,
		},
		{
			name:    "no authorization header",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "malformed authorization header - missing ApiKey prefix",
			headers: http.Header{"Authorization": []string{"Bearer my-token"}},
			want:    "",
			wantErr: nil, // expecting some error, checked below
		},
		{
			name:    "malformed authorization header - no space",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			want:    "",
			wantErr: nil, // expecting some error, checked below
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if tt.name == "malformed authorization header - missing ApiKey prefix" || tt.name == "malformed authorization header - no space" {
				if err == nil {
					t.Errorf("GetAPIKey() expected error for malformed header, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("GetAPIKey() unexpected error = %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("GetAPIKey() = %v, want %v", got, tt.want)
			}
		})
	}
}