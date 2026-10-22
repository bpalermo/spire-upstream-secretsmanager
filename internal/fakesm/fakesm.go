// Package fakesm is an in-process AWS Secrets Manager over HTTP (the AWS JSON
// 1.1 protocol), for tests that use a real AWS SDK client through a custom
// endpoint: the plugin's `endpoint` setting, or the rotator's client. It
// keeps each secret's versions and staging labels and answers the operations
// the two use: GetSecretValue, DescribeSecret, PutSecretValue and
// UpdateSecretVersionStage. Requests are not authenticated.
//
// A secret is known by one identifier, which is also its ARN and its name.
package fakesm

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
)

// The staging labels Secrets Manager itself moves.
const (
	StageCurrent  = "AWSCURRENT"
	StagePending  = "AWSPENDING"
	StagePrevious = "AWSPREVIOUS"
)

// Server is a fake Secrets Manager.
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	secrets  map[string]*secret
	requests []Request
	// hang, when not nil, makes requests wait until it is closed or the
	// client goes away.
	hang chan struct{}
}

// secret is one secret: its versions (nil value: a version Secrets Manager
// made for a rotation, which has no value yet) and their labels.
type secret struct {
	rotation bool
	values   map[string]*string
	stages   map[string][]string
}

// Request is a GetSecretValue request the server received.
type Request struct {
	SecretID      string
	VersionStage  string
	Authorization string
}

// New starts a server holding the given SecretStrings by secret ID, each as
// the AWSCURRENT version of its secret.
func New(values map[string]string) *Server {
	s := &Server{secrets: map[string]*secret{}}
	for k, v := range values {
		s.Set(k, v)
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// Set stores a SecretString as a new AWSCURRENT version of the secret id,
// creating the secret if needed; the version it replaces becomes
// AWSPREVIOUS.
func (s *Server) Set(id, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.secret(id)
	version := newVersionID()
	sec.values[version] = &value
	sec.stages[version] = nil
	sec.attach(StageCurrent, version)
}

// StartRotation does what RotateSecret does before it invokes the rotation
// function: it turns rotation on and adds a version, with no value, labelled
// AWSPENDING. It returns the version's ID, the ClientRequestToken of the
// rotation's four steps.
func (s *Server) StartRotation(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	sec := s.secret(id)
	sec.rotation = true
	version := newVersionID()
	sec.values[version] = nil
	sec.stages[version] = nil
	sec.attach(StagePending, version)
	return version
}

// Hang makes every request hang until [Server.Recover] or until the client
// gives up.
func (s *Server) Hang() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hang == nil {
		s.hang = make(chan struct{})
	}
}

// Recover ends [Server.Hang].
func (s *Server) Recover() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hang != nil {
		close(s.hang)
		s.hang = nil
	}
}

// Requests returns the GetSecretValue requests received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// secret returns the secret id, created if it does not exist. s.mu is held.
func (s *Server) secret(id string) *secret {
	sec, ok := s.secrets[id]
	if !ok {
		sec = &secret{values: map[string]*string{}, stages: map[string][]string{}}
		s.secrets[id] = sec
	}
	return sec
}

// holder is the version label is attached to, or "".
func (sec *secret) holder(label string) string {
	for id, labels := range sec.stages {
		if slices.Contains(labels, label) {
			return id
		}
	}
	return ""
}

func (sec *secret) detach(label string) {
	for id, labels := range sec.stages {
		sec.stages[id] = slices.DeleteFunc(labels, func(l string) bool { return l == label })
	}
}

// attach moves label to version; moving AWSCURRENT leaves AWSPREVIOUS on the
// version that had it, as Secrets Manager does.
func (sec *secret) attach(label, version string) {
	previous := sec.holder(label)
	if previous == version {
		return
	}
	sec.detach(label)
	sec.stages[version] = append(sec.stages[version], label)
	if label == StageCurrent && previous != "" {
		sec.detach(StagePrevious)
		sec.stages[previous] = append(sec.stages[previous], StagePrevious)
	}
}

func newVersionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

// apiError is an error response: its HTTP status, __type and message.
type apiError struct {
	code    int
	typ     string
	message string
}

func badRequest(typ, msg string) *apiError {
	return &apiError{http.StatusBadRequest, typ, msg}
}

func noSecret() *apiError {
	return badRequest("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	hang := s.hang
	s.mu.Unlock()
	if hang != nil {
		select {
		case <-hang:
		case <-r.Context().Done():
			return
		}
	}
	ops := map[string]func(*http.Request, []byte) (any, *apiError){
		"secretsmanager.GetSecretValue":           s.getSecretValue,
		"secretsmanager.DescribeSecret":           s.describeSecret,
		"secretsmanager.PutSecretValue":           s.putSecretValue,
		"secretsmanager.UpdateSecretVersionStage": s.updateSecretVersionStage,
	}
	op, ok := ops[r.Header.Get("X-Amz-Target")]
	if r.Method != http.MethodPost || !ok {
		writeError(w, badRequest("UnknownOperationException", "unsupported operation"))
		return
	}
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, badRequest("InvalidRequestException", err.Error()))
		return
	}
	out, apiErr := op(r, body)
	if apiErr != nil {
		writeError(w, apiErr)
		return
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) getSecretValue(r *http.Request, body []byte) (any, *apiError) {
	var in struct {
		SecretID     string `json:"SecretId"`
		VersionID    string `json:"VersionId"`
		VersionStage string `json:"VersionStage"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, badRequest("InvalidRequestException", err.Error())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, Request{SecretID: in.SecretID, VersionStage: in.VersionStage, Authorization: r.Header.Get("Authorization")})
	sec, ok := s.secrets[in.SecretID]
	if !ok {
		return nil, noSecret()
	}
	stage := in.VersionStage
	if in.VersionID == "" && stage == "" {
		stage = StageCurrent
	}
	version := in.VersionID
	if version == "" {
		version = sec.holder(stage)
	}
	v, ok := sec.values[version]
	if !ok || v == nil || (stage != "" && !slices.Contains(sec.stages[version], stage)) {
		return nil, badRequest("ResourceNotFoundException", "Secrets Manager can't find the specified secret value for staging label: "+stage)
	}
	return map[string]any{
		"ARN":           in.SecretID,
		"Name":          in.SecretID,
		"SecretString":  *v,
		"VersionId":     version,
		"VersionStages": slices.Clone(sec.stages[version]),
		"CreatedDate":   0,
	}, nil
}

func (s *Server) describeSecret(_ *http.Request, body []byte) (any, *apiError) {
	var in struct {
		SecretID string `json:"SecretId"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, badRequest("InvalidRequestException", err.Error())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[in.SecretID]
	if !ok {
		return nil, noSecret()
	}
	stages := map[string][]string{}
	for id, labels := range sec.stages {
		if len(labels) > 0 {
			stages[id] = slices.Clone(labels)
		}
	}
	return map[string]any{
		"ARN":                in.SecretID,
		"Name":               in.SecretID,
		"RotationEnabled":    sec.rotation,
		"VersionIdsToStages": stages,
	}, nil
}

func (s *Server) putSecretValue(_ *http.Request, body []byte) (any, *apiError) {
	var in struct {
		SecretID           string   `json:"SecretId"`
		ClientRequestToken string   `json:"ClientRequestToken"`
		SecretString       *string  `json:"SecretString"`
		VersionStages      []string `json:"VersionStages"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, badRequest("InvalidRequestException", err.Error())
	}
	if in.ClientRequestToken == "" || in.SecretString == nil {
		return nil, badRequest("InvalidParameterException", "ClientRequestToken and SecretString are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[in.SecretID]
	if !ok {
		return nil, noSecret()
	}
	version := in.ClientRequestToken
	out := map[string]any{"ARN": in.SecretID, "Name": in.SecretID, "VersionId": version}
	if v := sec.values[version]; v != nil {
		if *v != *in.SecretString {
			return nil, badRequest("ResourceExistsException", "a version with this ClientRequestToken already exists with another value")
		}
		out["VersionStages"] = slices.Clone(sec.stages[version])
		return out, nil
	}
	stages := in.VersionStages
	if len(stages) == 0 {
		stages = []string{StageCurrent}
	}
	sec.values[version] = in.SecretString
	if _, ok := sec.stages[version]; !ok {
		sec.stages[version] = nil
	}
	for _, label := range stages {
		sec.attach(label, version)
	}
	out["VersionStages"] = slices.Clone(sec.stages[version])
	return out, nil
}

func (s *Server) updateSecretVersionStage(_ *http.Request, body []byte) (any, *apiError) {
	var in struct {
		SecretID            string `json:"SecretId"`
		VersionStage        string `json:"VersionStage"`
		MoveToVersionID     string `json:"MoveToVersionId"`
		RemoveFromVersionID string `json:"RemoveFromVersionId"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return nil, badRequest("InvalidRequestException", err.Error())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sec, ok := s.secrets[in.SecretID]
	if !ok {
		return nil, noSecret()
	}
	label, to, from := in.VersionStage, in.MoveToVersionID, in.RemoveFromVersionID
	// Like Secrets Manager: a label attached elsewhere moves only when the
	// request names the version it is on.
	if holder := sec.holder(label); holder != "" && holder != to && holder != from {
		return nil, badRequest("InvalidParameterException", fmt.Sprintf("%s is attached to %s, not %s", label, holder, from))
	}
	out := map[string]any{"ARN": in.SecretID, "Name": in.SecretID}
	if to == "" {
		if from != "" {
			sec.stages[from] = slices.DeleteFunc(sec.stages[from], func(l string) bool { return l == label })
		}
		return out, nil
	}
	if _, ok := sec.stages[to]; !ok {
		return nil, badRequest("ResourceNotFoundException", "no version "+to)
	}
	sec.attach(label, to)
	return out, nil
}

func writeError(w http.ResponseWriter, e *apiError) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(e.code)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": e.typ, "message": e.message})
}
