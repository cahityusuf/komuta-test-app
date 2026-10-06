package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func signIdentity(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func tamper(token string) string {
	parts := strings.Split(token, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	raw = []byte(strings.Replace(string(raw), `"sub":"u1"`, `"sub":"u2"`, 1))
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + parts[2]
}

func jwk(kid string, pub *ecdsa.PublicKey) map[string]any {
	x, y := make([]byte, 32), make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return map[string]any{"kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig",
		"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)}
}

func jwksServer(t *testing.T, keys *[]map[string]any, hits *atomic.Int32, fail *atomic.Bool) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if fail.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": *keys})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestIdentityKeySetFetchesRarelyAndKeepsKnownKeysWhenTheSourceFails(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bad := jwk("bad", &key.PublicKey)
	bad["x"] = base64.RawURLEncoding.EncodeToString([]byte("short"))
	p384 := jwk("p384", &key.PublicKey)
	p384["crv"] = "P-384"
	keys := []map[string]any{jwk("k1", &key.PublicKey), bad, p384}
	var hits atomic.Int32
	var fail atomic.Bool
	srv := jwksServer(t, &keys, &hits, &fail)
	set := &identityKeySet{url: srv.URL, client: srv.Client()}
	now := time.Unix(1_800_000_000, 0)
	ctx := context.Background()

	if k, err := set.key(ctx, "k1", now); err != nil || !k.Equal(&key.PublicKey) {
		t.Fatalf("k1: %v", err)
	}
	for _, kid := range []string{"bad", "p384", "forged", "forged2"} {
		if _, err := set.key(ctx, kid, now.Add(time.Second)); err == nil {
			t.Fatalf("%s accepted", kid)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("unknown kids refetched within the gap: %d fetches", hits.Load())
	}

	if _, err := set.key(ctx, "forged", now.Add(identityRefetchGap)); err == nil || hits.Load() != 2 {
		t.Fatalf("unknown kid after the gap: err=%v fetches=%d", err, hits.Load())
	}

	fail.Store(true)
	later := now.Add(identityKeysTTL + time.Minute)
	if _, err := set.key(ctx, "k1", later); err != nil {
		t.Fatalf("known key lost when the source failed: %v", err)
	}
	if _, err := set.key(ctx, "k1", later.Add(time.Second)); err != nil || hits.Load() != 3 {
		t.Fatalf("failed source refetched on every request: err=%v fetches=%d", err, hits.Load())
	}
}

func TestIdentityHandlerReportsAVerifiedVisitor(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keys := []map[string]any{jwk("k1", &key.PublicKey)}
	var hits atomic.Int32
	var fail atomic.Bool
	srv := jwksServer(t, &keys, &hits, &fail)
	now := time.Now()
	token := signIdentity(t, key, map[string]any{"alg": "ES256", "kid": "k1"}, map[string]any{
		"iss": "komuta-access", "aud": "shop.edge-1.komuta.app", "sub": "u1", "email": "a@b.c",
		"nbf": now.Unix() - 30, "exp": now.Unix() + 300})

	req := httptest.NewRequest(http.MethodGet, "http://Shop.Edge-1.komuta.app.:443/api/identity", nil)
	req.Header.Set("X-Komuta-User-Id", "u1")
	req.Header.Set("X-Komuta-User-Email", "a@b.c")
	req.Header.Set("X-Komuta-Identity", token)
	rec := httptest.NewRecorder()

	identityHandler(&identityKeySet{url: srv.URL, client: srv.Client()})(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["verified"] != true || body["matchesHeaders"] != true {
		t.Fatalf("unexpected body %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), token) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token echoed or response cacheable")
	}
}

func TestVerifyIdentity(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	lookup := func(_ context.Context, kid string, _ time.Time) (*ecdsa.PublicKey, error) {
		if kid == "k1" {
			return &key.PublicKey, nil
		}
		return nil, errors.New("unknown key")
	}
	header := map[string]any{"alg": "ES256", "kid": "k1", "typ": "JWT"}
	claims := func(mut func(map[string]any)) map[string]any {
		c := map[string]any{"iss": "komuta-access", "aud": "shop.edge-1.komuta.app", "sub": "u1", "email": "a@b.c",
			"iat": now.Unix(), "nbf": now.Unix() - 30, "exp": now.Unix() + 300}
		if mut != nil {
			mut(c)
		}
		return c
	}

	good := signIdentity(t, key, header, claims(nil))
	if got, err := verifyIdentity(context.Background(), good, "shop.edge-1.komuta.app", now, lookup); err != nil || got["sub"] != "u1" {
		t.Fatalf("valid token rejected: %v", err)
	}

	cases := map[string]struct {
		token string
		host  string
		at    time.Time
		want  string
	}{
		"other key":    {signIdentity(t, other, header, claims(nil)), "shop.edge-1.komuta.app", now, "does not verify"},
		"unknown kid":  {signIdentity(t, key, map[string]any{"alg": "ES256", "kid": "k2"}, claims(nil)), "shop.edge-1.komuta.app", now, "unknown key"},
		"wrong alg":    {signIdentity(t, key, map[string]any{"alg": "HS256", "kid": "k1"}, claims(nil)), "shop.edge-1.komuta.app", now, "not ES256"},
		"wrong host":   {good, "other.edge-1.komuta.app", now, "aud"},
		"wrong issuer": {signIdentity(t, key, header, claims(func(c map[string]any) { c["iss"] = "x" })), "shop.edge-1.komuta.app", now, "iss"},
		"expired":      {good, "shop.edge-1.komuta.app", now.Add(6 * time.Minute), "expired"},
		"early":        {good, "shop.edge-1.komuta.app", now.Add(-2 * time.Minute), "not yet valid"},
		"tampered":     {tamper(good), "shop.edge-1.komuta.app", now, "does not verify"},
		"garbage":      {"abc", "shop.edge-1.komuta.app", now, "compact"},
	}
	for name, tc := range cases {
		_, err := verifyIdentity(context.Background(), tc.token, tc.host, tc.at, lookup)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want error containing %q", name, err, tc.want)
		}
	}
}

func TestIdentityHandlerNeverEchoesTheAccessToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://shop.edge-1.komuta.app/api/identity", nil)
	req.Header.Set("X-Komuta-Access", "pod-lock-secret")
	req.Header.Set("X-Komuta-User-Id", "u1")
	rec := httptest.NewRecorder()

	identityHandler(newIdentityKeySet())(rec, req)

	if strings.Contains(rec.Body.String(), "pod-lock-secret") {
		t.Fatal("the pod lock token was echoed")
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["verified"] != false || body["reason"] != "no identity token" {
		t.Fatalf("unexpected body %s", rec.Body.String())
	}
}
