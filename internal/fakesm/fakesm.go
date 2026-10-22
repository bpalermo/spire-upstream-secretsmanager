// Package fakesm is an in-process AWS Secrets Manager that answers
// GetSecretValue over HTTP (the AWS JSON 1.1 protocol), for tests that use a
// real AWS SDK client through the plugin's `endpoint` setting. Requests are
// not authenticated.
package fakesm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
)

// Server is a fake Secrets Manager.
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	values   map[string]string
	requests []Request
}

// Request is a GetSecretValue request the server received.
type Request struct {
	SecretID      string
	VersionStage  string
	Authorization string
}

// New starts a server holding the given SecretStrings by secret ID.
func New(values map[string]string) *Server {
	s := &Server{values: map[string]string{}}
	for k, v := range values {
		s.values[k] = v
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// Set stores a SecretString.
func (s *Server) Set(id, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[id] = value
}

// Requests returns the requests received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("X-Amz-Target") != "secretsmanager.GetSecretValue" {
		writeError(w, http.StatusBadRequest, "UnknownOperationException", "unsupported operation")
		return
	}
	var in struct {
		SecretID     string `json:"SecretId"`
		VersionStage string `json:"VersionStage"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestException", err.Error())
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, Request{SecretID: in.SecretID, VersionStage: in.VersionStage, Authorization: r.Header.Get("Authorization")})
	v, ok := s.values[in.SecretID]
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusBadRequest, "ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ARN":           in.SecretID,
		"Name":          in.SecretID,
		"SecretString":  v,
		"VersionId":     "00000000-0000-0000-0000-000000000001",
		"VersionStages": []string{"AWSCURRENT"},
		"CreatedDate":   0,
	})
}

func writeError(w http.ResponseWriter, code int, typ, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": msg})
}
