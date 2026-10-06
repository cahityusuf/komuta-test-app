package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	identityIssuer     = "komuta-access"
	identityDefaultURL = "https://api.komuta.io/api/devopszon/access-protection/identity-keys"
	identityKeysTTL    = 5 * time.Minute
	identityLeeway     = 30 * time.Second
	identityRefetchGap = 30 * time.Second
)

type identityKeySet struct {
	url       string
	client    *http.Client
	mu        sync.Mutex
	fetching  sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	fetched   time.Time
	attempted time.Time
}

func newIdentityKeySet() *identityKeySet {
	url := strings.TrimSpace(os.Getenv("KOMUTA_IDENTITY_JWKS_URL"))
	if url == "" {
		url = identityDefaultURL
	}
	return &identityKeySet{url: url, client: &http.Client{Timeout: 5 * time.Second}}
}

func (s *identityKeySet) cached(kid string, now time.Time) (*ecdsa.PublicKey, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[kid]
	fresh := ok && now.Sub(s.fetched) < identityKeysTTL
	due := now.Sub(s.attempted) >= identityRefetchGap
	return k, fresh, due
}

func (s *identityKeySet) key(ctx context.Context, kid string, now time.Time) (*ecdsa.PublicKey, error) {
	k, fresh, due := s.cached(kid, now)
	if fresh || !due {
		if k != nil {
			return k, nil
		}
		return nil, fmt.Errorf("unknown key %q", kid)
	}
	if k == nil {
		s.fetching.Lock()
	} else if !s.fetching.TryLock() {
		return k, nil
	}
	defer s.fetching.Unlock()
	if k, fresh, due := s.cached(kid, now); fresh || !due {
		if k != nil {
			return k, nil
		}
		return nil, fmt.Errorf("unknown key %q", kid)
	}
	fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	keys, err := s.fetch(fetchCtx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempted = now
	if err == nil {
		s.keys, s.fetched = keys, now
	}
	if k, ok := s.keys[kid]; ok {
		return k, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("unknown key %q", kid)
}

func (s *identityKeySet) fetch(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty, Crv, Kid, X, Y string
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Kid == "" {
			continue
		}
		x, errX := base64.RawURLEncoding.DecodeString(k.X)
		y, errY := base64.RawURLEncoding.DecodeString(k.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			continue
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			continue
		}
		keys[k.Kid] = pub
	}
	return keys, nil
}

type identityKeyLookup func(ctx context.Context, kid string, now time.Time) (*ecdsa.PublicKey, error)

func verifyIdentity(ctx context.Context, token, host string, now time.Time, lookup identityKeyLookup) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWT")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	var claims map[string]any
	if err := decodeSegment(parts[1], &claims); err != nil {
		return claims, fmt.Errorf("claims: %w", err)
	}
	if header.Alg != "ES256" {
		return claims, fmt.Errorf("alg %q is not ES256", header.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return claims, errors.New("signature is not a 64-byte ES256 signature")
	}
	pub, err := lookup(ctx, header.Kid, now)
	if err != nil {
		return claims, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return claims, errors.New("signature does not verify")
	}
	if iss, _ := claims["iss"].(string); iss != identityIssuer {
		return claims, fmt.Errorf("iss %q", iss)
	}
	if aud, _ := claims["aud"].(string); !strings.EqualFold(aud, host) {
		return claims, fmt.Errorf("aud %q is not %q", aud, host)
	}
	exp, okExp := claims["exp"].(float64)
	nbf, okNbf := claims["nbf"].(float64)
	if !okExp || !okNbf {
		return claims, errors.New("exp or nbf missing")
	}
	if now.After(time.Unix(int64(exp), 0).Add(identityLeeway)) {
		return claims, errors.New("expired")
	}
	if now.Add(identityLeeway).Before(time.Unix(int64(nbf), 0)) {
		return claims, errors.New("not yet valid")
	}
	return claims, nil
}

func decodeSegment(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func requestHost(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(host, ".")
}

func identityHandler(keys *identityKeySet) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		token := r.Header.Get("X-Komuta-Identity")
		body := map[string]any{
			"host": requestHost(r),
			"headers": map[string]any{
				"x-komuta-user-id":    r.Header.Values("X-Komuta-User-Id"),
				"x-komuta-user-email": r.Header.Values("X-Komuta-User-Email"),
				"x-komuta-identity":   token != "",
			},
			"identityHeaderCount": len(r.Header.Values("X-Komuta-Identity")),
		}
		if token == "" {
			body["verified"] = false
			body["reason"] = "no identity token"
			writeJSON(w, http.StatusOK, body)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
		defer cancel()
		claims, err := verifyIdentity(ctx, token, requestHost(r), time.Now(), keys.key)
		body["claims"] = claims
		body["verified"] = err == nil
		if err != nil {
			body["reason"] = err.Error()
		} else {
			sub, _ := claims["sub"].(string)
			email, _ := claims["email"].(string)
			body["matchesHeaders"] = sub == r.Header.Get("X-Komuta-User-Id") && email == r.Header.Get("X-Komuta-User-Email")
		}
		writeJSON(w, http.StatusOK, body)
	}
}
