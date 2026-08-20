// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"math/big"

	"github.com/electroneum/electroneum-sc/common"
	"github.com/electroneum/electroneum-sc/common/prque"
	"github.com/electroneum/electroneum-sc/consensus/istanbul"
	qbfttypes "github.com/electroneum/electroneum-sc/consensus/istanbul/types"
)

const (
	// === Future Window Limits ===

	// 32 blocks ahead is far beyond any legitimate async delivery.
	// If you're 32 blocks behind, you need chain sync, not backlog.
	MaxFutureSequenceGap uint64 = 32

	// 50 rounds covers hours of continuous failed consensus.
	// No legitimate scenario exceeds this.
	MaxFutureRoundGap uint64 = 15

	// === Memory Protection Limits ===
	//
	// NOTE: the message-count caps below are a coarse first line of defence. They
	// do NOT by themselves bound retained memory, because a single PRE-PREPARE
	// carries a full decoded block proposal that can be far larger than the ~1KB a
	// count cap implicitly assumes. The per-message ceiling below bounds the worst
	// single message; the aggregate byte budget is a separate follow-up.

	// Per-validator message count cap. Generous enough for legitimate traffic
	// bursts.
	MaxBacklogPerValidator = 1024

	// MinBacklogTotal: floor on the message count for small validator sets.
	// Ensures small networks (e.g., 4 validators) still have reasonable capacity.
	MinBacklogTotal = 4096

	// MaxBacklogTotalCeiling: hard ceiling on message count regardless of
	// validator count. Prevents entry-count blowup in very large networks.
	MaxBacklogTotalCeiling = 131072

	// MaxFuturePreprepareBytes bounds the encoded wire size of a single future
	// PRE-PREPARE we are willing to retain in the backlog.
	//
	// A legitimate block is bounded by gas, not by the 10 MiB transport frame
	// (eth/handler.go protocolMaxMsgSize). At a 30,000,000 gas limit and 16 gas
	// per non-zero calldata byte, the largest data-carrying block is ~1.9 MiB, and
	// real blocks are far smaller. 4 MiB leaves ~2x headroom over that hard bound
	// (covering RLP framing and PRE-PREPARE justification arrays) while rejecting
	// the near-10-MiB proposals that make the count-only cap a DoS vector.
	//
	// If the network gas limit is raised substantially, revisit this constant so
	// legitimate large blocks are not rejected (which would be a liveness bug).
	MaxFuturePreprepareBytes = 4 * 1024 * 1024
)

// backlogEntry is a backlogged message together with its encoded wire size, so
// that byte-budget accounting stays exact across push, pop, requeue and
// whole-backlog eviction without re-encoding the message.
type backlogEntry struct {
	msg  qbfttypes.QBFTMessage
	size int
}

var (
	// msgPriority is defined for calculating processing priority to speedup consensus
	// msgPreprepare > msgCommit > msgPrepare
	msgPriority = map[uint64]int{
		qbfttypes.PreprepareCode: 1,
		qbfttypes.CommitCode:     2,
		qbfttypes.PrepareCode:    3,
	}
)

// checkMessage checks that a message matches our current QBFT state
//
// In particular it ensures that
// - message has the expected round
// - message has the expected sequence
// - message type is expected given our current state

// return errInvalidMessage if the message is invalid
// return errFutureMessage if the message view is larger than current view
// return errOldMessage if the message view is smaller than current view
func (c *core) checkMessage(msgCode uint64, view *istanbul.View) error {
	if view == nil || view.Sequence == nil || view.Round == nil {
		return errInvalidMessage
	}

	if msgCode == qbfttypes.RoundChangeCode {
		// if ROUND-CHANGE message
		// check that
		// - sequence matches our current sequence
		// - round is in the future
		if view.Sequence.Cmp(c.currentView().Sequence) > 0 {
			return errFutureMessage
		} else if view.Cmp(c.currentView()) < 0 {
			return errOldMessage
		}
		return nil
	}

	// If not ROUND-CHANGE
	// check that round and sequence equals our current round and sequence
	if view.Cmp(c.currentView()) > 0 {
		return errFutureMessage
	}

	if view.Cmp(c.currentView()) < 0 {
		return errOldMessage
	}

	switch c.state {
	case StateAcceptRequest:
		// StateAcceptRequest only accepts msgPreprepare and msgRoundChange
		// other messages are future messages
		if msgCode > qbfttypes.PreprepareCode {
			return errFutureMessage
		}
		return nil
	case StatePreprepared:
		// StatePreprepared only accepts msgPrepare and msgRoundChange
		// message less than msgPrepare are invalid and greater are future messages
		if msgCode < qbfttypes.PrepareCode {
			return errInvalidMessage
		} else if msgCode > qbfttypes.PrepareCode {
			return errFutureMessage
		}
		return nil
	case StatePrepared:
		// StatePrepared only accepts msgCommit and msgRoundChange
		// other messages are invalid messages
		if msgCode < qbfttypes.CommitCode {
			return errInvalidMessage
		}
		return nil
	case StateCommitted:
		// StateCommit rejects all messages other than msgRoundChange
		return errInvalidMessage
	}
	return nil
}

// isValidatorAddress checks if the given address is a current validator.
func (c *core) isValidatorAddress(addr common.Address) bool {
	if c.valSet == nil {
		return false
	}
	_, v := c.valSet.GetByAddress(addr)
	return v != nil
}

// withinBacklogFutureWindow checks if a message is within acceptable future bounds.
func (c *core) withinBacklogFutureWindow(msgCode uint64, view istanbul.View) bool {
	if c.current == nil {
		return false // not ready yet, drop message
	}

	cur := c.currentView()

	// Same-sequence messages are commonly received early and should be allowed.
	if view.Sequence.Cmp(cur.Sequence) == 0 {
		// ROUND-CHANGE at same sequence can be spammed with huge future rounds. Cap it.
		if msgCode == qbfttypes.RoundChangeCode {
			maxRound := new(big.Int).Add(cur.Round, new(big.Int).SetUint64(MaxFutureRoundGap))
			if view.Round.Cmp(maxRound) > 0 {
				return false
			}
		}
		return true
	}

	// Not a backlog candidate if it's behind.
	if view.Sequence.Cmp(cur.Sequence) < 0 {
		return false
	}

	// Cap how far ahead by sequence we will backlog.
	maxSeq := new(big.Int).Add(cur.Sequence, new(big.Int).SetUint64(MaxFutureSequenceGap))
	if view.Sequence.Cmp(maxSeq) > 0 {
		return false
	}

	return true
}

// addToBacklog stores a future message for later processing, subject to
// validator verification, future window limits, and capacity caps. encodedSize
// is the message's encoded wire size, used to enforce the backlog byte budgets.
func (c *core) addToBacklog(msg qbfttypes.QBFTMessage, encodedSize int) {
	logger := c.currentLogger(true, msg)

	src := msg.Source()
	if src == c.Address() {
		logger.Warn("IBFT: backlog from self")
		return
	}

	// Drop messages that claim to be from non-validators.
	// This prevents filling the backlogs map with arbitrary addresses.
	if !c.isValidatorAddress(src) {
		logger.Trace("IBFT: dropping backlog message from non-validator", "src", src)
		return
	}

	view := msg.View()

	// Drop far-future messages (including huge ROUND-CHANGE rounds at current sequence).
	if !c.withinBacklogFutureWindow(msg.Code(), view) {
		logger.Trace("IBFT: dropping far-future backlog message",
			"src", src, "code", msg.Code(),
			"view_seq", view.Sequence, "view_round", view.Round,
			"cur_seq", c.currentView().Sequence, "cur_round", c.currentView().Round,
		)
		return
	}

	// Reject any single future PRE-PREPARE whose encoded size exceeds the
	// per-message ceiling before it is retained. A legitimate proposal is bounded
	// by gas well below this; anything larger is either malformed or an attempt to
	// pin large proposals in the backlog, and the proposal is not validated until
	// the message becomes current, so we must bound it here.
	if msg.Code() == qbfttypes.PreprepareCode && encodedSize > MaxFuturePreprepareBytes {
		logger.Warn("IBFT: dropping oversized future PRE-PREPARE",
			"src", src, "size", encodedSize, "cap", MaxFuturePreprepareBytes,
		)
		return
	}

	c.backlogsMu.Lock()
	defer c.backlogsMu.Unlock()

	// Global count cap (dynamic based on validator count)
	maxTotal := c.maxBacklogTotal()
	if c.backlogsTotal >= maxTotal {
		logger.Trace("IBFT: dropping backlog message (global cap reached)",
			"cap", maxTotal, "total", c.backlogsTotal,
		)
		return
	}

	backlog := c.backlogs[src]
	if backlog == nil {
		backlog = prque.New(nil)
		c.backlogs[src] = backlog
	}

	// Per-validator count cap
	if backlog.Size() >= MaxBacklogPerValidator {
		logger.Trace("IBFT: dropping backlog message (per-validator cap reached)",
			"src", src, "cap", MaxBacklogPerValidator, "size", backlog.Size(),
		)
		return
	}

	backlog.Push(&backlogEntry{msg: msg, size: encodedSize}, toPriority(msg.Code(), &view))
	c.backlogsTotal++

	logger.Trace("IBFT: new backlog message", "backlogs_total", c.backlogsTotal, "src_backlog_size", backlog.Size())
}

// processBacklog looks up future messages that have been backlogged and posts them on
// the event channel so the main handler loop can handle them.
// It is called on every state change.
func (c *core) processBacklog() {
	c.backlogsMu.Lock()
	defer c.backlogsMu.Unlock()

	for srcAddress, backlog := range c.backlogs {
		if backlog == nil {
			continue
		}

		// If the address is no longer a validator, drop its entire backlog.
		_, src := c.valSet.GetByAddress(srcAddress)
		if src == nil {
			c.backlogsTotal -= backlog.Size()
			delete(c.backlogs, srcAddress)
			continue
		}

		logger := c.logger.New("from", src, "state", c.state)
		logger.Trace("IBFT: process backlog")

		// Process until:
		//  1) backlog is empty, OR
		//  2) the next message is still a future message (we requeue it and stop)
		for !backlog.Empty() {
			m, prio := backlog.Pop()
			entry := m.(*backlogEntry)
			c.backlogsTotal--

			msg := entry.msg
			code := msg.Code()
			view := msg.View()

			// Push back if it's still a future message
			err := c.checkMessage(code, &view)
			if err != nil {
				// Use errors.Is to be robust to wrapped errors.
				if errors.Is(err, errFutureMessage) {
					logger.Trace("IBFT: stop processing backlog", "msg", msg)

					// Requeue only if it still fits our window/caps (defensive).
					if c.withinBacklogFutureWindow(code, view) &&
						backlog.Size() < MaxBacklogPerValidator &&
						c.backlogsTotal < c.maxBacklogTotal() {
						backlog.Push(entry, prio)
						c.backlogsTotal++
					}
					break
				}

				// Old/invalid messages are dropped permanently.
				logger.Trace("IBFT: skip backlog message", "msg", msg, "err", err)
				continue
			}

			logger.Trace("IBFT: post backlog event", "msg", msg)

			// Post backlog event for main handler loop
			event := backlogEvent{
				src:  src,
				msg:  msg,
				size: entry.size,
			}
			go c.sendEvent(event)
		}

		// Clean up empty queues
		if backlog.Empty() {
			delete(c.backlogs, srcAddress)
		}
	}
}

// maxBacklogTotal returns the dynamic maximum backlog size based on validator count.
// This ensures fair allocation per validator while maintaining a hard memory ceiling.
func (c *core) maxBacklogTotal() int {
	if c.valSet == nil {
		return MinBacklogTotal
	}

	// Allow 2x headroom so validators can burst while others are quiet
	dynamic := c.valSet.Size() * MaxBacklogPerValidator * 2

	if dynamic < MinBacklogTotal {
		return MinBacklogTotal
	}
	if dynamic > MaxBacklogTotalCeiling {
		return MaxBacklogTotalCeiling
	}
	return dynamic
}

func toPriority(msgCode uint64, view *istanbul.View) int64 {
	if msgCode == qbfttypes.RoundChangeCode {
		// For msgRoundChange, set the message priority based on its sequence
		return -int64(view.Sequence.Uint64() * 1000)
	}
	// FIXME: round will be reset as 0 while new sequence
	// 10 * Round limits the range of message code is from 0 to 9
	// 1000 * Sequence limits the range of round is from 0 to 99
	return -int64(view.Sequence.Uint64()*1000 + view.Round.Uint64()*10 + uint64(msgPriority[msgCode]))
}
