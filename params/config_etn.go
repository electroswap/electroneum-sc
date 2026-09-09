// Copyright 2022 Electroneum Ltd
// This file is part of the electroneum-sc library.

package params

// Electroneum-specific chain configuration: the IBFT/QBFT consensus parameters,
// the Transitions mechanism that lets them change at a given height, and the
// priority-transactors contract lookup.
//
// Kept out of config.go so the ETN delta against upstream go-ethereum stays
// isolated and future rebases stay mechanical.

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/electroneum/electroneum-sc/common"
)

// IBFTConfig is the consensus engine configs for Istanbul based sealing.
type IBFTConfig struct {
	EpochLength              uint64 `json:"epochlength"`              // Number of blocks that should pass before pending validator votes are reset
	BlockPeriodSeconds       uint64 `json:"blockperiodseconds"`       // Minimum time between two consecutive IBFT or QBFT blocks’ timestamps in seconds
	RequestTimeoutSeconds    uint64 `json:"requesttimeoutseconds"`    // Minimum request timeout for each IBFT or QBFT round in seconds
	MaxRequestTimeoutSeconds uint64 `json:"maxrequesttimeoutseconds"` // Maximum request timeout for each IBFT or QBFT round in seconds
	ProposerPolicy           uint64 `json:"policy"`                   // The policy for proposer selection
	AllowedFutureBlockTime   uint64 `json:"allowedfutureblocktime"`   //Allowed number of seconds a timestamp can be in the future before it's considered a future block'
}

func (c IBFTConfig) String() string {
	return "IBFT"
}

type Transition struct {
	Block                              *big.Int       `json:"block"`
	EpochLength                        uint64         `json:"epochlength,omitempty"`              // Number of blocks that should pass before pending validator votes are reset
	BlockPeriodSeconds                 uint64         `json:"blockperiodseconds,omitempty"`       // Minimum time between two consecutive IBFT or QBFT blocks’ timestamps in seconds
	RequestTimeoutSeconds              uint64         `json:"requesttimeoutseconds,omitempty"`    // Minimum request timeout for each IBFT or QBFT round in seconds
	MaxRequestTimeoutSeconds           uint64         `json:"maxrequesttimeoutseconds,omitempty"` // Maximum request timeout for each IBFT or QBFT round in seconds
	PriorityTransactorsContractAddress common.Address `json:"prioritytransactorscontractaddress"` // Smart contract address for priority transactors
	AllowedFutureBlockTime             uint64         `json:"allowedfutureblocktime,omitempty"`
}

// IsFutureFork returns whether num is either equal to the Future fork block or greater.
func (c *ChainConfig) IsFutureFork(num *big.Int) bool {
	return isBlockForked(c.FutureForkBlock, num)
}

func (c *ChainConfig) GetPriorityTransactorsContractAddress(blockNumber *big.Int) common.Address {
	if c.Transitions != nil {
		for i := len(c.Transitions) - 1; i >= 0; i-- {
			if c.Transitions[i].Block.Cmp(blockNumber) <= 0 && c.Transitions[i].PriorityTransactorsContractAddress != (common.Address{}) {
				return c.Transitions[i].PriorityTransactorsContractAddress
			}
		}
	}
	return c.PriorityTransactorsContractAddress
}

func (c *ChainConfig) CheckTransitionsData() error {
	prevBlock := big.NewInt(0)
	for _, transition := range c.Transitions {
		if transition.Block == nil {
			return ErrBlockNumberMissing
		}
		if transition.Block.Cmp(prevBlock) < 0 {
			return ErrBlockOrder
		}
		prevBlock = transition.Block
	}
	return nil
}

func isTransitionsConfigCompatible(c1, c2 *ChainConfig, head *big.Int) (*big.Int, *big.Int, error) {
	if len(c1.Transitions) == 0 && len(c2.Transitions) == 0 {
		// maxCodeSizeConfig not used. return
		return big.NewInt(0), big.NewInt(0), nil
	}

	// existing config had Transitions and new one does not have the same return error
	if len(c1.Transitions) > 0 && len(c2.Transitions) == 0 {
		return head, head, fmt.Errorf("genesis file missing transitions information")
	}

	if len(c2.Transitions) > 0 && len(c1.Transitions) == 0 {
		return big.NewInt(0), big.NewInt(0), nil
	}

	// check the number of records below current head in both configs
	// if they do not match throw an error
	c1RecsBelowHead := 0
	for _, data := range c1.Transitions {
		if data.Block.Cmp(head) <= 0 {
			c1RecsBelowHead++
		} else {
			break
		}
	}

	c2RecsBelowHead := 0
	for _, data := range c2.Transitions {
		if data.Block.Cmp(head) <= 0 {
			c2RecsBelowHead++
		} else {
			break
		}
	}

	// if the count of past records is not matching return error
	if c1RecsBelowHead != c2RecsBelowHead {
		return head, head, errors.New("transitions data incompatible. updating transitions for past")
	}

	// validate that each past record is matching exactly. if not return error
	for i := 0; i < c1RecsBelowHead; i++ {
		isDifferentBlock := c1.Transitions[i].Block.Cmp(c2.Transitions[i].Block) != 0

		if isDifferentBlock {
			return head, head, fmt.Errorf("Block mismatch for transition %d", i)
		}

		if c1.Transitions[i].BlockPeriodSeconds != c2.Transitions[i].BlockPeriodSeconds {
			return head, head, ErrTransitionIncompatible("BlockPeriodSeconds")
		}
		if c1.Transitions[i].RequestTimeoutSeconds != c2.Transitions[i].RequestTimeoutSeconds {
			return head, head, ErrTransitionIncompatible("RequestTimeoutSeconds")
		}
		if c1.Transitions[i].MaxRequestTimeoutSeconds != c2.Transitions[i].MaxRequestTimeoutSeconds {
			return head, head, ErrTransitionIncompatible("MaxRequestTimeoutSeconds")
		}
		if c1.Transitions[i].AllowedFutureBlockTime != c2.Transitions[i].AllowedFutureBlockTime {
			return head, head, ErrTransitionIncompatible("AllowedFutureBlockTime")
		}
		if c1.Transitions[i].EpochLength != c2.Transitions[i].EpochLength {
			return head, head, ErrTransitionIncompatible("EpochLength")
		}
		if c1.Transitions[i].PriorityTransactorsContractAddress != c2.Transitions[i].PriorityTransactorsContractAddress {
			return head, head, ErrTransitionIncompatible("PriorityTransactorsContractAddress")
		}
	}

	return big.NewInt(0), big.NewInt(0), nil
}

// ETNMaxSupply is the maximum amount of ETN that can ever exist, in wei.
// GetBaseBlockReward clamps against it: once circulating supply reaches this
// value the block reward is zero.
const ETNMaxSupply = "21000000000000000000000000000"
