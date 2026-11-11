// SPDX-License-Identifier: MIT
// Copyright (C) 2026 APlane Project LLC

package aplane

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWitnessKeyIDVectors(t *testing.T) {
	zeros := make([]byte, 1793)
	counting := make([]byte, 1793)
	for i := range counting {
		counting[i] = byte(i % 251)
	}
	for name, tc := range map[string]struct {
		key  []byte
		want string
	}{
		"all zero":  {zeros, "ROGAFDACF7ASC3EMZRWNKVM73NXHO4P6O4EB7ZXWER37SM63BMFQ"},
		"i mod 251": {counting, "HJPRU4QEGLKF7RD6FYHQSG4SFAADHULJYVCVFPSCMIYZLAYW5MNA"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := WitnessKeyID(KeyTypeWitnessFalcon1024, tc.key); got != tc.want || len(got) != 52 {
				t.Fatalf("WitnessKeyID() = %s, want %s", got, tc.want)
			}
		})
	}
}

// witnessRecord is a /keys record of a witness key, its address the key's
// Witness Key ID.
func witnessRecord(keyType string, publicKey []byte) KeyInfo {
	return KeyInfo{
		Address: WitnessKeyID(keyType, publicKey), PublicKeyHex: hex.EncodeToString(publicKey),
		KeyType: keyType, IsWitnessKey: true,
	}
}

// fakeCosigners stands in for the cosigner endpoints of a registry. Each
// alias's endpoint is reached at ssh://<alias>; connect either fails as told
// or returns a client of that alias's fake signer.
type fakeCosigners struct {
	t *testing.T

	mu sync.Mutex
	// connectErr fails the connection to an alias.
	connectErr map[string]error
	// keys answers an alias's /keys; answer, when set, answers it instead.
	keys   map[string][]KeyInfo
	answer map[string]http.HandlerFunc

	connects, reads     map[string]int
	inFlight, maxFlight int
	tunnels             []*sshTunnel
}

func newFakeCosigners(t *testing.T) *fakeCosigners {
	return &fakeCosigners{
		t: t, connectErr: map[string]error{}, keys: map[string][]KeyInfo{}, answer: map[string]http.HandlerFunc{},
		connects: map[string]int{}, reads: map[string]int{},
	}
}

// resolver builds a resolver over the given cosigner aliases, plus a signer
// endpoint, that connects through the fake.
func (f *fakeCosigners) resolver(aliases ...string) *EndpointCosignerResolver {
	registry := &ClientEndpointRegistry{Endpoints: map[string]ClientEndpointConfig{
		"primary": {Role: ClientEndpointRoleSigner, URL: "ssh://primary"},
	}}
	for _, alias := range aliases {
		registry.Endpoints[alias] = ClientEndpointConfig{Role: ClientEndpointRoleCosigner, URL: "ssh://" + alias}
	}
	r := NewEndpointCosignerResolverFromRegistry(registry, nil)
	r.connect = f.connect
	return r
}

func (f *fakeCosigners) connect(ctx context.Context, endpoint ClientEndpointConfig, _ EndpointCosignerResolverOptions) (*SignerClient, error) {
	alias := strings.TrimPrefix(endpoint.URL, "ssh://")
	f.mu.Lock()
	f.connects[alias]++
	err := f.connectErr[alias]
	f.mu.Unlock()
	if alias == "primary" {
		f.t.Errorf("discovery connected to the signer endpoint")
	}
	if err != nil {
		return nil, err
	}
	client, server := newTestClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys" {
			f.t.Errorf("discovery asked endpoint %s for %s", alias, r.URL.Path)
			return
		}
		f.mu.Lock()
		f.reads[alias]++
		f.inFlight++
		f.maxFlight = max(f.maxFlight, f.inFlight)
		answer, keys := f.answer[alias], f.keys[alias]
		f.mu.Unlock()
		defer func() {
			f.mu.Lock()
			f.inFlight--
			f.mu.Unlock()
		}()
		if answer != nil {
			answer(w, r)
			return
		}
		json.NewEncoder(w).Encode(KeysResponse{Count: len(keys), Keys: keys})
	})
	f.t.Cleanup(server.Close)
	// A tunnel whose closing can be seen.
	tunnel := &sshTunnel{done: make(chan struct{})}
	client.sshTunnel = tunnel
	f.mu.Lock()
	f.tunnels = append(f.tunnels, tunnel)
	f.mu.Unlock()
	return client, nil
}

// open counts the clients the resolver has not closed.
func (f *fakeCosigners) open() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	open := 0
	for _, tunnel := range f.tunnels {
		select {
		case <-tunnel.done:
		default:
			open++
		}
	}
	return open
}

func (f *fakeCosigners) count(counts map[string]int, alias string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return counts[alias]
}

var (
	witnessOne = []byte{0x01, 0xab, 0xcd}
	witnessTwo = []byte{0x02, 0xef}
)

func TestEndpointCosignerResolverUsesTheOneEndpointThatListsTheKey(t *testing.T) {
	f := newFakeCosigners(t)
	f.keys["alpha"] = []KeyInfo{
		{Address: fakeAccount(1), KeyType: "ed25519"},
		witnessRecord(KeyTypeWitnessFalcon1024, witnessOne),
	}
	f.keys["beta"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessTwo)}
	// An endpoint that failed is not reported when it was not needed.
	f.connectErr["gamma"] = errors.New("connection refused")
	r := f.resolver("alpha", "beta", "gamma")
	defer r.Close()

	// The public key is compared case-insensitively.
	client, componentKey, err := r.ResolveCosigner(context.Background(), strings.ToUpper(hex.EncodeToString(witnessOne)), KeyTypeWitnessFalcon1024)
	if err != nil {
		t.Fatalf("ResolveCosigner() error = %v", err)
	}
	if componentKey != WitnessKeyID(KeyTypeWitnessFalcon1024, witnessOne) {
		t.Fatalf("component key = %s, want the record's address", componentKey)
	}
	keys, err := client.GetKeysResponseWithContext(context.Background())
	if err != nil || len(keys.Keys) != 2 {
		t.Fatalf("the client returned is not alpha's: %+v, %v", keys, err)
	}
	if _, componentKey, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessTwo), KeyTypeWitnessFalcon1024); err != nil || componentKey != WitnessKeyID(KeyTypeWitnessFalcon1024, witnessTwo) {
		t.Fatalf("ResolveCosigner(beta's key) = %s, %v", componentKey, err)
	}
	// The same public key under another key type is another witness key.
	if _, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), "aplane.witness-other.v1"); !errors.Is(err, ErrCosignerDiscovery) {
		t.Fatalf("ResolveCosigner(other key type) error = %v", err)
	}
}

func TestEndpointCosignerResolverRefusesAKeyListedTwice(t *testing.T) {
	f := newFakeCosigners(t)
	f.keys["zeta"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessOne)}
	f.keys["alpha"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessOne), witnessRecord(KeyTypeWitnessFalcon1024, witnessOne)}
	f.keys["mid"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessTwo)}
	r := f.resolver("zeta", "alpha", "mid")
	defer r.Close()
	_, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024)
	want := fmt.Sprintf(`cosigner discovery: Witness Key ID %s (%s) is listed by endpoints "alpha", "zeta"; each witness key needs exactly one endpoint`,
		WitnessKeyID(KeyTypeWitnessFalcon1024, witnessOne), KeyTypeWitnessFalcon1024)
	if !errors.Is(err, ErrCosignerDiscovery) || err.Error() != want {
		t.Fatalf("error = %v\nwant    %s", err, want)
	}
}

// When no live endpoint lists the key, every cosigner endpoint is named with
// its state.
func TestEndpointCosignerResolverNamesEveryEndpointWhenNoneListsTheKey(t *testing.T) {
	f := newFakeCosigners(t)
	coded := func(status int, code string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { writeCodedError(w, status, code, "refused") }
	}
	f.keys["a-ok"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessTwo)}
	f.connectErr["b-down"] = errors.New("dial tcp: connection refused")
	f.answer["c-locked"] = coded(http.StatusForbidden, ErrCodeLocked)
	f.answer["d-unauthenticated"] = coded(http.StatusUnauthorized, ErrCodeUnauthorized)
	f.answer["e-forbidden"] = coded(http.StatusForbidden, ErrCodeForbidden)
	f.connectErr["f-not-enrolled"] = fmt.Errorf("failed to establish SSH tunnel: %w", ErrNotEnrolled)
	bad := witnessRecord(KeyTypeWitnessFalcon1024, witnessOne)
	bad.PublicKeyHex = "zz"
	f.keys["g-bad-hex"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessTwo), bad}
	misnamed := witnessRecord(KeyTypeWitnessFalcon1024, witnessOne)
	misnamed.Address = WitnessKeyID(KeyTypeWitnessFalcon1024, witnessTwo)
	f.keys["h-wrong-id"] = []KeyInfo{misnamed}
	f.answer["i-unreadable"] = func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"keys": [`)) }
	f.connectErr["j-no-identity"] = &sshSetupError{kind: sshSetupConfig, err: errors.New("failed to read SSH key")}
	f.answer["k-not-found"] = coded(http.StatusNotFound, ErrCodeNotFound)
	f.answer["l-broken"] = coded(http.StatusInternalServerError, ErrCodeInternal)
	r := f.resolver("l-broken", "k-not-found", "j-no-identity", "i-unreadable", "h-wrong-id", "g-bad-hex",
		"f-not-enrolled", "e-forbidden", "d-unauthenticated", "c-locked", "b-down", "a-ok")
	defer r.Close()

	_, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024)
	want := fmt.Sprintf(`cosigner discovery: no endpoint lists Witness Key ID %s (%s); endpoints: `+
		`"a-ok" ok, "b-down" unreachable, "c-locked" locked, "d-unauthenticated" authentication failed, `+
		`"e-forbidden" authentication failed, "f-not-enrolled" authentication failed, "g-bad-hex" invalid cosigner metadata, `+
		`"h-wrong-id" invalid cosigner metadata, "i-unreadable" invalid cosigner metadata, "j-no-identity" configuration invalid, `+
		`"k-not-found" configuration invalid, "l-broken" unreachable`,
		WitnessKeyID(KeyTypeWitnessFalcon1024, witnessOne), KeyTypeWitnessFalcon1024)
	if !errors.Is(err, ErrCosignerDiscovery) || err.Error() != want {
		t.Fatalf("error = %v\nwant    %s", err, want)
	}
	// g-bad-hex listed witnessTwo too, but its listing is invalid as a whole.
	if _, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessTwo), KeyTypeWitnessFalcon1024); err != nil {
		t.Fatalf("ResolveCosigner(a-ok's key) error = %v", err)
	}
	// Only the live endpoint's connection is kept.
	if open := f.open(); open != 1 {
		t.Fatalf("%d connections open, want a-ok's only", open)
	}
}

// A /keys body that is cut off, or stalls past the endpoint's time limit, is
// a failed exchange: the endpoint is unreachable, not invalid. A body read in
// full that does not decode is still invalid cosigner metadata.
func TestEndpointCosignerResolverKeysBodyFailureIsUnreachable(t *testing.T) {
	endpointTimeout := cosignerDiscoveryEndpointTimeout
	cosignerDiscoveryEndpointTimeout = 200 * time.Millisecond
	defer func() { cosignerDiscoveryEndpointTimeout = endpointTimeout }()

	f := newFakeCosigners(t)
	f.answer["a-cut-off"] = func(w http.ResponseWriter, _ *http.Request) {
		// Fewer bytes than declared: the connection ends inside the body.
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys": [`))
	}
	f.answer["b-stalled"] = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys": [`))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}
	f.answer["c-unreadable"] = func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"keys": [`)) }
	r := f.resolver("a-cut-off", "b-stalled", "c-unreadable")
	defer r.Close()
	_, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024)
	if !errors.Is(err, ErrCosignerDiscovery) || !strings.HasSuffix(err.Error(), `endpoints: "a-cut-off" unreachable, "b-stalled" unreachable, "c-unreadable" invalid cosigner metadata`) {
		t.Fatalf("error = %v", err)
	}
}

func TestEndpointCosignerResolverNonCanonicalAddressIsInvalidMetadata(t *testing.T) {
	f := newFakeCosigners(t)
	account := fakeAccount(3)
	// The same 36 bytes spelled with a trailing bit set: a non-canonical
	// spelling of the account.
	last := account[len(account)-1]
	respelled := account[:len(account)-1] + string(rune(last+1))
	if _, ok := alternateAddressSpelling(respelled); !ok {
		t.Skip("no alternate spelling of this address")
	}
	f.keys["only"] = []KeyInfo{{Address: respelled, KeyType: "ed25519"}}
	r := f.resolver("only")
	defer r.Close()
	_, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024)
	if err == nil || !strings.HasSuffix(err.Error(), `endpoints: "only" invalid cosigner metadata`) {
		t.Fatalf("error = %v", err)
	}
}

// A record is a witness key only with is_witness_key and a key type; any
// other record is not checked.
func TestEndpointCosignerResolverChecksOnlyWitnessRecords(t *testing.T) {
	f := newFakeCosigners(t)
	f.keys["only"] = []KeyInfo{
		{Address: "anything", PublicKeyHex: "not hex", KeyType: "ed25519"},
		{Address: "anything", PublicKeyHex: "not hex", IsWitnessKey: true},
		witnessRecord(KeyTypeWitnessFalcon1024, witnessOne),
	}
	r := f.resolver("only")
	defer r.Close()
	if _, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024); err != nil {
		t.Fatalf("ResolveCosigner() error = %v", err)
	}
}

func TestEndpointCosignerResolverWithNoCosignerEndpoint(t *testing.T) {
	f := newFakeCosigners(t)
	for name, r := range map[string]*EndpointCosignerResolver{
		"a signer only": f.resolver(),
		"no registry":   NewEndpointCosignerResolverFromRegistry(nil, nil),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024)
			if !errors.Is(err, ErrCosignerDiscovery) || err.Error() != "cosigner discovery: endpoints.yaml lists no cosigner endpoint" {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

// A host key that differs from the pinned one, on any cosigner endpoint,
// ends the whole discovery, even when that endpoint was not needed.
func TestEndpointCosignerResolverAbortsOnAHostKeyMismatch(t *testing.T) {
	f := newFakeCosigners(t)
	f.keys["alpha"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessOne)}
	const text = "SSH host key mismatch for beta:1127 (possible MITM attack); remove the old key from /x/known_hosts to connect"
	f.connectErr["beta"] = fmt.Errorf("failed to establish SSH tunnel: failed to connect to SSH server: ssh: handshake failed: %w",
		&sshSetupError{kind: sshSetupHostKeyMismatch, err: errors.New(text)})
	r := f.resolver("alpha", "beta")
	defer r.Close()
	_, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024)
	if want := `cosigner discovery: endpoint "beta": ` + text; !errors.Is(err, ErrCosignerDiscovery) || err.Error() != want {
		t.Fatalf("error = %v\nwant    %s", err, want)
	}
	if open := f.open(); open != 0 {
		t.Fatalf("%d connections left open after the aborted sweep", open)
	}
	// Nothing was kept: the next call sweeps again, and aborts again.
	if _, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024); !strings.Contains(err.Error(), "host key mismatch") || f.count(f.connects, "alpha") != 2 {
		t.Fatalf("second call: %v, alpha connects %d", err, f.count(f.connects, "alpha"))
	}
}

// The sweep is kept; a key it does not hold makes one fresh sweep per call,
// which reads live endpoints again on their connections and connects again
// to those that failed.
func TestEndpointCosignerResolverSweepsOncePerMiss(t *testing.T) {
	f := newFakeCosigners(t)
	f.keys["alpha"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessOne)}
	f.connectErr["beta"] = errors.New("connection refused")
	r := f.resolver("alpha", "beta")
	defer r.Close()
	ctx := context.Background()
	one, two := hex.EncodeToString(witnessOne), hex.EncodeToString(witnessTwo)

	for range 3 {
		if _, _, err := r.ResolveCosigner(ctx, one, KeyTypeWitnessFalcon1024); err != nil {
			t.Fatal(err)
		}
	}
	if r.sweeps != 1 || f.count(f.reads, "alpha") != 1 || f.count(f.connects, "beta") != 1 {
		t.Fatalf("sweeps %d, alpha reads %d, beta connects %d; want one sweep for three hits", r.sweeps, f.count(f.reads, "alpha"), f.count(f.connects, "beta"))
	}

	// A miss: exactly one more sweep, then the answer.
	if _, _, err := r.ResolveCosigner(ctx, two, KeyTypeWitnessFalcon1024); !errors.Is(err, ErrCosignerDiscovery) {
		t.Fatalf("error = %v", err)
	}
	if r.sweeps != 2 || f.count(f.connects, "alpha") != 1 || f.count(f.reads, "alpha") != 2 || f.count(f.connects, "beta") != 2 {
		t.Fatalf("after a miss: sweeps %d, alpha connects %d reads %d, beta connects %d", r.sweeps, f.count(f.connects, "alpha"), f.count(f.reads, "alpha"), f.count(f.connects, "beta"))
	}

	// beta comes up with the missing key: the next miss finds it.
	f.mu.Lock()
	delete(f.connectErr, "beta")
	f.keys["beta"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessTwo)}
	f.mu.Unlock()
	if _, componentKey, err := r.ResolveCosigner(ctx, two, KeyTypeWitnessFalcon1024); err != nil || componentKey != WitnessKeyID(KeyTypeWitnessFalcon1024, witnessTwo) {
		t.Fatalf("ResolveCosigner() = %s, %v", componentKey, err)
	}
	if r.sweeps != 3 || f.open() != 2 {
		t.Fatalf("sweeps %d, open connections %d; want 3 and 2", r.sweeps, f.open())
	}

	// A sweep made in the call answers it: an empty cache is not swept twice.
	fresh := newFakeCosigners(t)
	fresh.keys["alpha"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessOne)}
	second := fresh.resolver("alpha")
	defer second.Close()
	if _, _, err := second.ResolveCosigner(ctx, two, KeyTypeWitnessFalcon1024); !errors.Is(err, ErrCosignerDiscovery) || second.sweeps != 1 {
		t.Fatalf("first-call miss: %v, sweeps %d; want one sweep", err, second.sweeps)
	}
}

// A kept connection that was closed, or whose SSH link went down, counts as a
// miss: one fresh sweep, which connects that endpoint again without reading
// the dead connection. Telling it is dead takes no request.
func TestEndpointCosignerResolverSweepsAgainForADeadConnection(t *testing.T) {
	for name, kill := range map[string]func(*SignerClient){
		"closed":        func(client *SignerClient) { client.Close() },
		"SSH link down": func(client *SignerClient) { client.sshTunnel.down.Store(true) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeCosigners(t)
			f.keys["alpha"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessOne)}
			f.keys["beta"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessTwo)}
			r := f.resolver("alpha", "beta")
			defer r.Close()
			ctx := context.Background()
			one := hex.EncodeToString(witnessOne)

			first, _, err := r.ResolveCosigner(ctx, one, KeyTypeWitnessFalcon1024)
			if err != nil {
				t.Fatal(err)
			}
			kill(first)
			if first.connectionOpen() {
				t.Fatal("a dead connection reports itself open")
			}
			second, componentKey, err := r.ResolveCosigner(ctx, one, KeyTypeWitnessFalcon1024)
			if err != nil || componentKey != WitnessKeyID(KeyTypeWitnessFalcon1024, witnessOne) {
				t.Fatalf("ResolveCosigner() = %s, %v", componentKey, err)
			}
			if second == first || !second.connectionOpen() {
				t.Fatal("the resolver returned the dead connection")
			}
			// One fresh sweep: alpha connected again and read once on the new
			// connection, never on the dead one; beta read again on its own.
			if r.sweeps != 2 || f.count(f.connects, "alpha") != 2 || f.count(f.reads, "alpha") != 2 ||
				f.count(f.connects, "beta") != 1 || f.count(f.reads, "beta") != 2 {
				t.Fatalf("sweeps %d, alpha connects %d reads %d, beta connects %d reads %d",
					r.sweeps, f.count(f.connects, "alpha"), f.count(f.reads, "alpha"), f.count(f.connects, "beta"), f.count(f.reads, "beta"))
			}
			// The dead connection was closed; the new one is kept.
			if open := f.open(); open != 2 {
				t.Fatalf("%d connections open, want alpha's new one and beta's", open)
			}
			if third, _, err := r.ResolveCosigner(ctx, one, KeyTypeWitnessFalcon1024); err != nil || third != second || r.sweeps != 2 {
				t.Fatalf("a hit after the fresh sweep: same client %v, %v, sweeps %d", third == second, err, r.sweeps)
			}
		})
	}
}

// A client with no tunnel of its own is open until it is closed.
func TestSignerClientWithoutATunnelIsOpenUntilClosed(t *testing.T) {
	client := NewSignerClient("http://127.0.0.1:1")
	if !client.connectionOpen() {
		t.Fatal("a new client reports itself closed")
	}
	client.Close()
	if client.connectionOpen() {
		t.Fatal("a closed client reports itself open")
	}
}

func TestEndpointCosignerResolverCloseClosesItsConnections(t *testing.T) {
	f := newFakeCosigners(t)
	f.keys["alpha"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessOne)}
	f.keys["beta"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessTwo)}
	r := f.resolver("alpha", "beta")
	if _, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024); err != nil {
		t.Fatal(err)
	}
	if f.open() != 2 {
		t.Fatalf("open connections = %d, want 2", f.open())
	}
	r.Close()
	r.Close()
	if f.open() != 0 {
		t.Fatalf("open connections after Close = %d", f.open())
	}
	if _, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024); !errors.Is(err, ErrCosignerDiscovery) || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("a closed resolver resolved: %v", err)
	}
}

// Each endpoint has 10 seconds and the sweep 30 (shortened here), and at most
// four endpoints are asked at once. An endpoint the sweep's time ran out on is
// unreachable.
func TestEndpointCosignerResolverTimeLimits(t *testing.T) {
	endpointTimeout, totalTimeout := cosignerDiscoveryEndpointTimeout, cosignerDiscoveryTotalTimeout
	cosignerDiscoveryEndpointTimeout, cosignerDiscoveryTotalTimeout = 200*time.Millisecond, 400*time.Millisecond
	defer func() {
		cosignerDiscoveryEndpointTimeout, cosignerDiscoveryTotalTimeout = endpointTimeout, totalTimeout
	}()

	f := newFakeCosigners(t)
	aliases := []string{"e00", "e01", "e02", "e03", "e04", "e05", "e06", "e07", "e08", "e09", "e10", "e11"}
	for _, alias := range aliases {
		f.answer[alias] = func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	}
	r := f.resolver(aliases...)
	defer r.Close()
	started := time.Now()
	_, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024)
	elapsed := time.Since(started)
	if !errors.Is(err, ErrCosignerDiscovery) || strings.Count(err.Error(), " unreachable") != len(aliases) {
		t.Fatalf("error = %v, want every endpoint unreachable", err)
	}
	// One sweep for the call, so at most twice the sweep's limit.
	if elapsed > 2*time.Second {
		t.Fatalf("discovery took %v", elapsed)
	}
	f.mu.Lock()
	maxFlight := f.maxFlight
	f.mu.Unlock()
	if maxFlight == 0 || maxFlight > 4 {
		t.Fatalf("%d endpoints were asked at once, want at most 4", maxFlight)
	}
	// The first four waited out their own limit, so more were asked; the
	// sweep's limit ended it before all twelve were.
	asked := 0
	for _, alias := range aliases {
		asked += f.count(f.reads, alias)
	}
	if asked <= 4 || asked >= len(aliases) {
		t.Fatalf("%d endpoints were asked, want more than 4 and fewer than %d", asked, len(aliases))
	}
}

func TestEndpointCosignerResolverWithAnEndedContext(t *testing.T) {
	f := newFakeCosigners(t)
	f.keys["alpha"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessOne)}
	r := f.resolver("alpha")
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := r.ResolveCosigner(ctx, hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024)
	if !errors.Is(err, ErrCosignerDiscovery) || !errors.Is(err, context.Canceled) || f.count(f.connects, "alpha") != 0 {
		t.Fatalf("error = %v, connects %d", err, f.count(f.connects, "alpha"))
	}
}

// A client created from a data directory makes its own resolver on first use,
// keeps it, and closes it with itself. Any other client has none.
func TestDefaultCosignerResolverLifetime(t *testing.T) {
	plain := NewSignerClient("http://127.0.0.1:1")
	if plain.defaultCosignerResolver() != nil {
		t.Fatal("a client not created from a data directory has a default resolver")
	}
	client := NewSignerClient("http://127.0.0.1:1")
	client.endpoints = &ClientEndpointRegistry{Endpoints: map[string]ClientEndpointConfig{}}
	client.endpointOptions = EndpointCosignerResolverOptions{Timeout: 7, TrustOnFirstUse: true}
	first := client.defaultCosignerResolver()
	if first == nil || client.defaultCosignerResolver() != first {
		t.Fatal("the default resolver was not kept")
	}
	if first.registry != client.endpoints || first.options != client.endpointOptions {
		t.Fatalf("the default resolver does not use the client's registry and options: %+v", first.options)
	}

	f := newFakeCosigners(t)
	f.keys["alpha"] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, witnessOne)}
	client.cosignerResolver = f.resolver("alpha")
	if _, _, err := client.defaultCosignerResolver().ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024); err != nil {
		t.Fatal(err)
	}
	client.Close()
	if f.open() != 0 || !client.cosignerResolver.closed {
		t.Fatal("closing the client did not close its resolver's connections")
	}

	// A client closed before it made its resolver makes none that could open
	// a connection: a later cosigned call fails with nothing opened.
	closedFirst := NewSignerClient("http://127.0.0.1:1")
	closedFirst.endpoints = &ClientEndpointRegistry{Endpoints: map[string]ClientEndpointConfig{
		"cos": {Role: ClientEndpointRoleCosigner, URL: "ssh://127.0.0.1:1"},
	}}
	closedFirst.Close()
	resolver := closedFirst.defaultCosignerResolver()
	connects := 0
	resolver.connect = func(context.Context, ClientEndpointConfig, EndpointCosignerResolverOptions) (*SignerClient, error) {
		connects++
		return nil, errors.New("connection refused")
	}
	_, _, err := resolver.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024)
	if !errors.Is(err, ErrCosignerDiscovery) || err.Error() != "cosigner discovery: the resolver is closed" || connects != 0 || resolver.sweeps != 0 {
		t.Fatalf("after Close: %v, connects %d, sweeps %d; want the closed resolver's refusal", err, connects, resolver.sweeps)
	}
}

// After a sweep only the live endpoints' connections are open, including when
// the sweep's time ran out before it reached an endpoint that was live.
func TestEndpointCosignerResolverClosesConnectionsItNoLongerKeeps(t *testing.T) {
	endpointTimeout, totalTimeout := cosignerDiscoveryEndpointTimeout, cosignerDiscoveryTotalTimeout
	defer func() {
		cosignerDiscoveryEndpointTimeout, cosignerDiscoveryTotalTimeout = endpointTimeout, totalTimeout
	}()

	f := newFakeCosigners(t)
	aliases := []string{"e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7"}
	for _, alias := range aliases {
		f.keys[alias] = []KeyInfo{witnessRecord(KeyTypeWitnessFalcon1024, []byte(alias))}
	}
	r := f.resolver(aliases...)
	defer r.Close()
	if _, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString([]byte("e0")), KeyTypeWitnessFalcon1024); err != nil {
		t.Fatal(err)
	}
	if f.open() != len(aliases) {
		t.Fatalf("open connections = %d, want %d", f.open(), len(aliases))
	}

	// Every endpoint now hangs, and the sweep's limit is shorter than an
	// endpoint's: the first four are cut off, the rest never asked.
	cosignerDiscoveryEndpointTimeout, cosignerDiscoveryTotalTimeout = time.Second, 200*time.Millisecond
	f.mu.Lock()
	for _, alias := range aliases {
		f.answer[alias] = func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }
	}
	f.mu.Unlock()
	if _, _, err := r.ResolveCosigner(context.Background(), hex.EncodeToString(witnessOne), KeyTypeWitnessFalcon1024); !errors.Is(err, ErrCosignerDiscovery) {
		t.Fatalf("error = %v", err)
	}
	if open := f.open(); open != 0 {
		t.Fatalf("%d connections open after a sweep that found no live endpoint", open)
	}
}
