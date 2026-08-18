package qbftengine

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	istanbulcommon "github.com/electroneum/electroneum-sc/consensus/istanbul/common"
	"github.com/electroneum/electroneum-sc/consensus/istanbul/validator"
	"github.com/electroneum/electroneum-sc/core/types"
	"github.com/electroneum/electroneum-sc/crypto"
)

// buildSealedHeader builds a parent/child header pair carrying an N-validator
// set, and writes `seals` as the child's committed-seal array. The returned
// engine, child header, parent and validator set are ready for VerifyHeader.
func buildSealedHeader(t *testing.T, addrs []common.Address, seals [][]byte) (*Engine, *types.Header, *types.Header, istanbul.ValidatorSet) {
	t.Helper()

	engine := NewEngine(&istanbul.Config{}, addrs[0], func(data []byte) ([]byte, error) {
		return make([]byte, 65), nil
	})

	parent := &types.Header{
		Number:     big.NewInt(0),
		ParentHash: common.Hash{},
		MixDigest:  types.IstanbulDigest,
		Difficulty: istanbulcommon.DefaultDifficulty,
		Coinbase:   addrs[0],
		UncleHash:  types.EmptyUncleHash,
		Time:       1,
		GasLimit:   30_000_000,
		GasUsed:    0,
	}
	if err := ApplyHeaderQBFTExtra(parent, WriteValidators(addrs), writeRoundNumber(big.NewInt(0))); err != nil {
		t.Fatalf("apply extra parent: %v", err)
	}

	hdr := &types.Header{
		Number:     big.NewInt(1),
		ParentHash: parent.Hash(),
		MixDigest:  types.IstanbulDigest,
		Difficulty: istanbulcommon.DefaultDifficulty,
		Coinbase:   addrs[0],
		UncleHash:  types.EmptyUncleHash,
		Time:       2,
		GasLimit:   30_000_000,
		GasUsed:    0,
	}
	// writeCommittedSeals rejects an empty array, so only write seals when the
	// caller supplied some. Callers that pass no seals just want the header shell
	// (e.g. to compute the commit payload before signing).
	applies := []ApplyQBFTExtra{WriteValidators(addrs), writeRoundNumber(big.NewInt(1))}
	if len(seals) > 0 {
		applies = append(applies, writeCommittedSeals(seals))
	}
	if err := ApplyHeaderQBFTExtra(hdr, applies...); err != nil {
		t.Fatalf("apply extra hdr: %v", err)
	}

	valSet := validator.NewSet(addrs, istanbul.NewProposerPolicy(istanbul.RoundRobin))
	return engine, hdr, parent, valSet
}

func genValidators(t *testing.T, n int) ([]*ecdsa.PrivateKey, []common.Address) {
	t.Helper()
	keys := make([]*ecdsa.PrivateKey, n)
	addrs := make([]common.Address, n)
	for i := 0; i < n; i++ {
		k, err := crypto.GenerateKey()
		if err != nil {
			t.Fatalf("keygen failed: %v", err)
		}
		keys[i] = k
		addrs[i] = crypto.PubkeyToAddress(k.PublicKey)
	}
	return keys, addrs
}

// TestCommittedSealAmplificationRejected is the regression test for the
// committed-seal amplification DoS: a header carrying far more committed seals
// than there are validators must be rejected by verifyCommittedSeals BEFORE
// Signers() pays one ecrecover per seal.
//
// The attack header sets Coinbase to a real validator (the only pre-fork gate)
// and stuffs the committed-seal array with thousands of well-formed throwaway
// signatures. Before the fix, verifyCommittedSeals recovered every one of them;
// after the fix the length cap rejects the header structurally.
func TestCommittedSealAmplificationRejected(t *testing.T) {
	const N = 4
	_, addrs := genValidators(t, N)

	// One throwaway key produces many well-formed, non-validator seals. Each is a
	// valid secp256k1 signature, so none short-circuits the recovery loop -- the
	// only thing that stops them is the length cap.
	attacker, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// Build the header once to get the exact commit payload it will be signed over.
	_, hdr, _, _ := buildSealedHeader(t, addrs, [][]byte{})
	payload := PrepareCommittedSeal(hdr, 1)

	const fatCount = 1500 // ~ the 100 KB SanityCheck ceiling; >> N
	seals := make([][]byte, fatCount)
	for i := 0; i < fatCount; i++ {
		sig, err := crypto.Sign(payload, attacker)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		seals[i] = sig
	}

	engine, fatHdr, parent, valSet := buildSealedHeader(t, addrs, seals)

	err = engine.VerifyHeader(nil, fatHdr, []*types.Header{parent}, valSet)
	if err == nil {
		t.Fatalf("oversized committed-seal array (%d seals, %d validators) was ACCEPTED; expected rejection", fatCount, N)
	}
	if err != istanbulcommon.ErrInvalidCommittedSeals {
		t.Fatalf("expected ErrInvalidCommittedSeals, got %v", err)
	}

	// Signers() must independently refuse the oversized array rather than
	// recovering every entry, protecting the debug_* signer JSON-RPC callers.
	if _, sErr := engine.Signers(fatHdr); sErr != istanbulcommon.ErrInvalidCommittedSeals {
		t.Fatalf("Signers() should reject oversized array with ErrInvalidCommittedSeals, got %v", sErr)
	}
}

// TestCommittedSealAtValidatorCountPasses guards against a false positive: a
// legitimate header signed by all N validators has exactly N seals, which sits
// right at the cap boundary (len(seals) == N) and must still pass.
func TestCommittedSealAtValidatorCountPasses(t *testing.T) {
	const N = 4
	keys, addrs := genValidators(t, N)

	_, hdr, _, _ := buildSealedHeader(t, addrs, [][]byte{})
	payload := PrepareCommittedSeal(hdr, 1)

	seals := make([][]byte, N)
	for i := 0; i < N; i++ {
		sig, err := crypto.Sign(payload, keys[i])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		seals[i] = sig
	}

	engine, fullHdr, parent, valSet := buildSealedHeader(t, addrs, seals)
	if err := engine.VerifyHeader(nil, fullHdr, []*types.Header{parent}, valSet); err != nil {
		t.Fatalf("header with exactly N=%d seals (all validators) was rejected: %v", N, err)
	}
}
