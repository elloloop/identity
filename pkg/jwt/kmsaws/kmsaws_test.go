package kmsaws

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/elloloop/identity/pkg/jwt"
)

// fakeKMS is an in-process stand-in for the AWS KMS client. It serves
// GetPublicKey from an in-memory map and Sign with the matching
// private key using RSASSA-PKCS1-v1_5 + SHA-256 — exactly what real
// KMS does for a SIGN_VERIFY asymmetric RSA key.
type fakeKMS struct {
	keys map[string]*rsa.PrivateKey
}

func newFakeKMS() *fakeKMS {
	return &fakeKMS{keys: make(map[string]*rsa.PrivateKey)}
}

func (f *fakeKMS) addKey(t *testing.T, arn string) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate fake KMS key: %v", err)
	}
	f.keys[arn] = priv
	return priv
}

func (f *fakeKMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if in == nil || in.KeyId == nil {
		return nil, errors.New("missing key id")
	}
	priv, ok := f.keys[*in.KeyId]
	if !ok {
		return nil, errors.New("NotFoundException: " + *in.KeyId)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{
		KeyId:             aws.String(*in.KeyId),
		PublicKey:         der,
		KeyUsage:          kmstypes.KeyUsageTypeSignVerify,
		KeySpec:           kmstypes.KeySpecRsa2048,
		SigningAlgorithms: []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256},
	}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if in == nil || in.KeyId == nil {
		return nil, errors.New("missing key id")
	}
	priv, ok := f.keys[*in.KeyId]
	if !ok {
		return nil, errors.New("NotFoundException: " + *in.KeyId)
	}
	if in.SigningAlgorithm != kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256 {
		return nil, errors.New("unsupported algorithm: " + string(in.SigningAlgorithm))
	}
	if in.MessageType != kmstypes.MessageTypeDigest {
		return nil, errors.New("MessageType must be DIGEST")
	}
	if len(in.Message) != sha256.Size {
		return nil, errors.New("DIGEST message must be 32 bytes")
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, in.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{
		KeyId:            in.KeyId,
		Signature:        sig,
		SigningAlgorithm: in.SigningAlgorithm,
	}, nil
}

// TestKMSSigner_KeysAndJWKS confirms the public-key snapshot the
// JWKS endpoint consumes is populated end-to-end.
func TestKMSSigner_KeysAndJWKS(t *testing.T) {
	f := newFakeKMS()
	f.addKey(t, "arn:a")
	f.addKey(t, "arn:b")
	s, err := New(context.Background(), Config{
		API: f,
		Keys: []KeyRef{
			{KID: "a", KeyARN: "arn:a", NotBefore: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(time.Hour)},
			{KID: "b", KeyARN: "arn:b", NotBefore: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(24 * time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pubs := s.Keys()
	if len(pubs) != 2 {
		t.Fatalf("Keys = %d, want 2", len(pubs))
	}
	jwksBytes, err := jwt.JWKS(s)
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(jwksBytes) == 0 {
		t.Fatalf("empty JWKS")
	}
	if pub, ok := s.Get("a"); !ok || pub == nil {
		t.Fatalf("Get(a) = %v %v", pub, ok)
	}
	if _, ok := s.Get("nope"); ok {
		t.Fatalf("Get(nope) = true")
	}
}

func TestKMSSigner_SignAndVerify(t *testing.T) {
	f := newFakeKMS()
	f.addKey(t, "arn:k1")

	s, err := New(context.Background(), Config{
		API: f,
		Keys: []KeyRef{
			{KID: "k1", KeyARN: "arn:k1", NotBefore: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour)},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.ActiveKID(); got != "k1" {
		t.Fatalf("ActiveKID = %q, want k1", got)
	}

	tok, err := s.SignAccessToken(context.Background(), jwt.Claims{
		Sub:    "user-x",
		Email:  "x@example.com",
		Tenant: "t",
	}, 15*time.Minute)
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}
	if tok == "" {
		t.Fatalf("empty token")
	}

	claims, err := jwt.VerifyAccessToken(tok, s, "t", "", false)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Sub != "user-x" {
		t.Fatalf("sub = %q, want user-x", claims.Sub)
	}
}

func TestKMSSigner_Rotation(t *testing.T) {
	// Rotate to a new KMS key: tokens issued under the old kid must
	// still verify (old public key is still served), new tokens are
	// signed with the new kid.
	f := newFakeKMS()
	f.addKey(t, "arn:kA")
	f.addKey(t, "arn:kB")

	now := time.Now().UTC()

	cfg := Config{
		API: f,
		Keys: []KeyRef{
			{KID: "kA", KeyARN: "arn:kA", NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour)},
		},
	}
	s, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	aToken, err := s.SignAccessToken(context.Background(), jwt.Claims{Sub: "u", Tenant: "t"}, time.Hour)
	if err != nil {
		t.Fatalf("Sign A: %v", err)
	}

	// Now reconfigure with both keys, B as the new active.
	cfg2 := Config{
		API: f,
		Keys: []KeyRef{
			{KID: "kA", KeyARN: "arn:kA", NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour)},
			{KID: "kB", KeyARN: "arn:kB", NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(48 * time.Hour)},
		},
	}
	s2, err := New(context.Background(), cfg2)
	if err != nil {
		t.Fatalf("New B: %v", err)
	}
	if got := s2.ActiveKID(); got != "kB" {
		t.Fatalf("active = %q, want kB", got)
	}

	// kA-signed token still verifies via s2 because kA's public key is
	// in the provider.
	if _, err := jwt.VerifyAccessToken(aToken, s2, "t", "", false); err != nil {
		t.Fatalf("pre-rotation token failed against rotated signer: %v", err)
	}

	bToken, err := s2.SignAccessToken(context.Background(), jwt.Claims{Sub: "u2", Tenant: "t"}, time.Hour)
	if err != nil {
		t.Fatalf("Sign B: %v", err)
	}
	if _, err := jwt.VerifyAccessToken(bToken, s2, "t", "", false); err != nil {
		t.Fatalf("post-rotation token verify: %v", err)
	}
}

func TestKMSSigner_RejectsNonSignVerifyKey(t *testing.T) {
	bad := &badKMS{usage: kmstypes.KeyUsageTypeEncryptDecrypt}
	_, err := New(context.Background(), Config{
		API:  bad,
		Keys: []KeyRef{{KID: "k", KeyARN: "arn:k"}},
	})
	if err == nil {
		t.Fatalf("expected error for ENCRYPT_DECRYPT key")
	}
	if !strings.Contains(err.Error(), "SIGN_VERIFY") {
		t.Fatalf("error = %v, want SIGN_VERIFY", err)
	}
}

func TestKMSSigner_RejectsNonRS256Algorithms(t *testing.T) {
	bad := &badKMS{
		usage:      kmstypes.KeyUsageTypeSignVerify,
		algorithms: []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEcdsaSha256},
	}
	_, err := New(context.Background(), Config{
		API:  bad,
		Keys: []KeyRef{{KID: "k", KeyARN: "arn:k"}},
	})
	if err == nil {
		t.Fatalf("expected error for non-RS256 key")
	}
}

func TestKMSSigner_RejectsDuplicateKID(t *testing.T) {
	f := newFakeKMS()
	f.addKey(t, "arn:k1")
	_, err := New(context.Background(), Config{
		API: f,
		Keys: []KeyRef{
			{KID: "same", KeyARN: "arn:k1"},
			{KID: "same", KeyARN: "arn:k1"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestKMSSigner_RejectsEmptyConfig(t *testing.T) {
	if _, err := New(context.Background(), Config{}); err == nil {
		t.Fatalf("expected error for empty config")
	}
}

func TestKMSSigner_FailsWhenAllKeysInactive(t *testing.T) {
	f := newFakeKMS()
	f.addKey(t, "arn:k1")
	_, err := New(context.Background(), Config{
		API: f,
		Keys: []KeyRef{
			{KID: "old", KeyARN: "arn:k1", NotBefore: time.Now().Add(-24 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour)},
		},
	})
	if err == nil {
		t.Fatalf("expected error when all keys are inactive")
	}
}

func TestARNFromConfig(t *testing.T) {
	cases := []struct {
		in   string
		want []KeyRef
	}{
		{
			"kid1=arn:aws:kms:us-east-1:111:key/aaa",
			[]KeyRef{{KID: "kid1", KeyARN: "arn:aws:kms:us-east-1:111:key/aaa"}},
		},
		{
			"kid1=arn:aws:kms:us-east-1:111:key/aaa,kid2=arn:aws:kms:us-east-1:111:key/bbb",
			[]KeyRef{
				{KID: "kid1", KeyARN: "arn:aws:kms:us-east-1:111:key/aaa"},
				{KID: "kid2", KeyARN: "arn:aws:kms:us-east-1:111:key/bbb"},
			},
		},
	}
	for _, tc := range cases {
		got, err := ARNFromConfig(tc.in)
		if err != nil {
			t.Fatalf("ARNFromConfig(%q): %v", tc.in, err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("ARNFromConfig(%q) len = %d, want %d", tc.in, len(got), len(tc.want))
		}
		for i := range got {
			if got[i].KID != tc.want[i].KID || got[i].KeyARN != tc.want[i].KeyARN {
				t.Errorf("entry %d: got %+v, want %+v", i, got[i], tc.want[i])
			}
		}
	}
}

func TestARNFromConfig_FingerprintsBareARN(t *testing.T) {
	got, err := ARNFromConfig("arn:aws:kms:us-east-1:111:key/aaa")
	if err != nil {
		t.Fatalf("ARNFromConfig: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d", len(got))
	}
	if got[0].KeyARN != "arn:aws:kms:us-east-1:111:key/aaa" {
		t.Errorf("arn = %q", got[0].KeyARN)
	}
	if !strings.HasPrefix(got[0].KID, "k-") {
		t.Errorf("kid = %q, want k- prefix", got[0].KID)
	}
}

func TestARNFromConfig_Empty(t *testing.T) {
	if _, err := ARNFromConfig(""); err == nil {
		t.Fatalf("expected error for empty config")
	}
}

func TestKMSSigner_GetPublicKeyError(t *testing.T) {
	// The fake returns ErrNotFound for an unknown ARN; New() must
	// surface that error.
	f := newFakeKMS()
	_, err := New(context.Background(), Config{
		API:  f,
		Keys: []KeyRef{{KID: "k", KeyARN: "arn:missing"}},
	})
	if err == nil {
		t.Fatalf("expected error from GetPublicKey on missing ARN")
	}
}

func TestKMSSigner_NilAPI(t *testing.T) {
	if _, err := New(context.Background(), Config{
		API:  nil,
		Keys: []KeyRef{{KID: "k", KeyARN: "arn:k"}},
	}); err == nil {
		t.Fatalf("expected error for nil API")
	}
}

func TestKMSSigner_MissingKID(t *testing.T) {
	f := newFakeKMS()
	f.addKey(t, "arn:k")
	if _, err := New(context.Background(), Config{
		API:  f,
		Keys: []KeyRef{{KeyARN: "arn:k"}},
	}); err == nil {
		t.Fatalf("expected error for missing kid")
	}
}

func TestKMSSigner_MissingARN(t *testing.T) {
	f := newFakeKMS()
	if _, err := New(context.Background(), Config{
		API:  f,
		Keys: []KeyRef{{KID: "k"}},
	}); err == nil {
		t.Fatalf("expected error for missing ARN")
	}
}

func TestARNFromConfig_HandlesBlankEntries(t *testing.T) {
	refs, err := ARNFromConfig(", kid1=arn1 , ,kid2=arn2,")
	if err != nil {
		t.Fatalf("ARNFromConfig: %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("len = %d, want 2 (entries=%v)", len(refs), refs)
	}
}

func TestARNFromConfig_RejectsEmptyARN(t *testing.T) {
	// "kid=" leaves an empty ARN, which must be rejected.
	if _, err := ARNFromConfig("kid="); err == nil {
		t.Fatalf("expected error for empty arn")
	}
}

// badKMS satisfies API with arbitrary failure modes for negative tests.
type badKMS struct {
	usage      kmstypes.KeyUsageType
	algorithms []kmstypes.SigningAlgorithmSpec
}

func (b *badKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	algs := b.algorithms
	if algs == nil {
		algs = []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256}
	}
	usage := b.usage
	if usage == "" {
		usage = kmstypes.KeyUsageTypeSignVerify
	}
	return &kms.GetPublicKeyOutput{
		PublicKey:         der,
		KeyUsage:          usage,
		KeySpec:           kmstypes.KeySpecRsa2048,
		SigningAlgorithms: algs,
	}, nil
}

func (b *badKMS) Sign(_ context.Context, _ *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	return nil, errors.New("not used in this test")
}
