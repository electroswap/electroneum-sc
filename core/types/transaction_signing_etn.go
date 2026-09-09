// Copyright 2022 Electroneum Ltd
// This file is part of the electroneum-sc library.

package types

// Priority-transaction signing. A PriorityTx carries a SECOND signature, made
// by a key on the on-chain priority-transactor allowlist, over the same body
// hash the sender signs.
//
// PrioritySender is deliberately NOT added to the Signer interface: only the
// London signer is ever selected on Electroneum (London at block 0, no Cancun),
// so widening the interface would force empty stubs onto every other signer for
// no benefit.

import (
	"errors"
	"math/big"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/crypto"
)

// ErrTxIsNotPriorityType is returned when a priority operation is attempted on
// an ordinary transaction.
var ErrTxIsNotPriorityType = errors.New("tx is not priority transaction")

// prioritySigner is implemented by signers that understand PriorityTx.
type prioritySigner interface {
	PrioritySender(tx *Transaction) (common.PublicKey, error)
}

// PrioritySender recovers the priority public key that signed tx, verifying the
// signature in the process.
func PrioritySender(signer Signer, tx *Transaction) (common.PublicKey, error) {
	if tx.Type() != PriorityTxType {
		return common.PublicKey{}, ErrTxIsNotPriorityType
	}
	if pk, ok := tx.priorityPubkey.Load().(common.PublicKey); ok {
		return pk, nil
	}
	ps, ok := signer.(prioritySigner)
	if !ok {
		return common.PublicKey{}, ErrTxTypeNotSupported
	}
	pk, err := ps.PrioritySender(tx)
	if err != nil {
		return common.PublicKey{}, err
	}
	tx.priorityPubkey.Store(pk)
	return pk, nil
}

func (s londonSigner) PrioritySender(tx *Transaction) (common.PublicKey, error) { //this will actually verify the sig too, as the sender() function does for the regular tx sigs
	switch inner := tx.inner.(type) {
	case *PriorityTx:
		V, R, S := inner.rawPrioritySignatureValues()
		// DynamicFee txs are defined to use 0 and 1 as their recovery
		// id, add 27 to become equivalent to unprotected Homestead signatures.
		V = new(big.Int).Add(V, big.NewInt(27))
		if tx.ChainId().Cmp(s.chainId) != 0 {
			return common.PublicKey{}, ErrInvalidChainId
		}
		return recoverPublicKey(s.Hash(tx), V, R, S, true)
	default:
		return common.PublicKey{}, ErrTxTypeNotSupported
	}
}

func recoverPublicKey(sighash common.Hash, Vb, R, S *big.Int, homestead bool) (common.PublicKey, error) {
	if Vb.BitLen() > 8 {
		return common.PublicKey{}, ErrInvalidSig
	}
	V := byte(Vb.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, R, S, homestead) {
		return common.PublicKey{}, ErrInvalidSig
	}
	// encode the signature in uncompressed format
	r, s := R.Bytes(), S.Bytes()
	sig := make([]byte, crypto.SignatureLength)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V
	// recover the public key from the signature
	pub, err := crypto.Ecrecover(sighash[:], sig)
	if err != nil {
		return common.PublicKey{}, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return common.PublicKey{}, errors.New("invalid public key")
	}
	var pubkey common.PublicKey
	copy(pubkey[:], pub[:65])
	return pubkey, nil
}
