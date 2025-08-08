package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name: "valid header",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey test123")
				return h
			}(),
			wantKey: "test123",
			wantErr: nil,
		},
		{
			name:    "missing Authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - wrong prefix",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer token123")
				return h
			}(),
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "malformed header - missing token part",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKeyOnly")
				return h
			}(),
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %v; want %v", gotKey, tt.wantKey)
			}

			if (gotErr == nil) != (tt.wantErr == nil) ||
				(gotErr != nil && gotErr.Error() != tt.wantErr.Error()) {
				t.Errorf("GetAPIKey() error = %v; want %v", gotErr, tt.wantErr)
			}
		})
	}
}
