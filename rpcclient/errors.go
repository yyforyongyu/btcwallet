package rpcclient

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrBitcoindVersion is returned when running against a bitcoind that
	// is older than the minimum version supported by the rpcclient.
	ErrBitcoindVersion = errors.New("bitcoind version too low")

	// ErrInvalidParam is returned when the caller provides an invalid
	// parameter to an RPC method.
	ErrInvalidParam = errors.New("invalid param")

	// ErrUndefined is used when an error returned is not recognized. We
	// should gradually increase our error types to avoid returning this
	// error.
	ErrUndefined = errors.New("undefined")
)

var (
	// This section defines all possible errors or reject reasons returned
	// from bitcoind's `sendrawtransaction` or `testmempoolaccept` RPC. The
	// dashes used in the original error string is removed, e.g.
	// "missing-inputs" is now "missing inputs". This is ok since we will
	// normalize the errors before matching.
	//
	// A transaction that conflicts with an unconfirmed tx. Happens when
	// RBF is not enabled.
	//
	// NOTE: BIP rule 1.
	ErrMempoolConflict = errors.New("txn mempool conflict")

	// When a transaction adds new unconfirmed inputs.
	//
	// NOTE: BIP rule 2.
	ErrReplacementAddsUnconfirmed = errors.New("replacement adds unconfirmed")

	// When fee rate used or fees paid doesn't meet the requirements.
	//
	// NOTE: BIP rule 3 or 4.
	ErrInsufficientFee = errors.New("insufficient fee")

	// When a transaction causes too many transactions being replaced. This
	// is set by `MAX_REPLACEMENT_CANDIDATES` in `bitcoind` and defaults to
	// 100.
	//
	// NOTE: BIP rule 5.
	ErrTooManyReplacements = errors.New("too many potential replacements")

	// A transaction that spends conflicting tx outputs that are rejected.
	ErrConflictingTx = errors.New("bad txns spends conflicting tx")

	// A transaction with no outputs.
	ErrEmptyOutput = errors.New("bad txns vout empty")

	// A transaction with no inputs.
	ErrEmptyInput = errors.New("bad txns vin empty")

	// A tiny transaction(in non-witness bytes) that is disallowed.
	ErrTxTooSmall = errors.New("tx size small")

	// A transaction with duplicate inputs.
	ErrDuplicateInput = errors.New("bad txns inputs duplicate")

	// A non-coinbase transaction with coinbase-like outpoint.
	ErrEmptyPrevOut = errors.New("bad txns prevout null")

	// A transaction pays too little fee.
	ErrBelowOutValue = errors.New("bad txns in belowout")

	// A transaction with negative output value.
	ErrNegativeOutput = errors.New("bad txns vout negative")

	// A transaction with too large output value.
	ErrLargeOutput = errors.New("bad txns vout toolarge")

	// A transaction with too large sum of output values.
	ErrLargeTotalOutput = errors.New("bad txns txouttotal toolarge")

	// (Invalid OP_IF construction)
	ErrScriptVerifyFlag = errors.New("mandatory script verify flag failed")

	// A transaction with too many sigops.
	ErrTooManySigOps = errors.New("bad txns too many sigops")

	// A transaction with invalid OP codes.
	ErrInvalidOpcode = errors.New("disabled opcode")

	// A transaction already in the blockchain.
	ErrTxAlreadyKnown = errors.New("txn already known")

	// // A transaction in the mempool.
	ErrTxAlreadyInMempool = errors.New("txn already in mempool")

	// A transaction with missing inputs, that never existed or only
	// existed once in the past.
	ErrMissingInputs = errors.New("missing inputs")

	// A really large transaction.
	ErrOversizeTx = errors.New("bad txns oversize")

	// A coinbase transaction.
	ErrCoinbaseTx = errors.New("coinbase")

	// Some nonstandard transactions - a version currently non-standard.
	ErrNonStandardVersion = errors.New("version")

	// Some nonstandard transactions - non-standard script.
	ErrNonStandardScript = errors.New("scriptpubkey")

	// Some nonstandard transactions - bare multisig script (2-of-3).
	ErrBareMultiSig = errors.New("bare multisig")

	// Some nonstandard transactions - not-pushonly scriptSig.
	ErrScriptSigNotPushOnly = errors.New("scriptsig not pushonly")

	// Some nonstandard transactions - too large scriptSig (>1650 bytes).
	ErrScriptSigSize = errors.New("scriptsig size")

	// Some nonstandard transactions - too large tx size.
	ErrTxTooLarge = errors.New("tx size")

	// Some nonstandard transactions - output too small.
	ErrDust = errors.New("dust")

	// Some nonstandard transactions - muiltiple OP_RETURNs.
	ErrMultiOpReturn = errors.New("multi op return")

	// A timelocked transaction.
	ErrNonFinal = errors.New("non final")

	// A transaction that is locked by BIP68 sequence logic.
	ErrNonBIP68Final = errors.New("non BIP68 final")

	// Minimally-small transaction(in non-witness bytes) that is allowed.
	ErrSameNonWitnessData = errors.New("txn same nonwitness data in mempools")

	// Happens when passing a raw tx to `testmempoolaccept`, which gives
	// the error followed by (Witness program hash mismatch).
	ErrNonMandatoryScriptVerifyFlag = errors.New("non-mandatory-script-verify-flag")

	// Happens when passing a signed tx to `testmempoolaccept`, but the tx
	// pays more fees than specified.
	ErrMaxFeeExceeded = errors.New("max-fee-exceeded")
)

var BitcoindErrors = []error{
	ErrMempoolConflict,
	ErrReplacementAddsUnconfirmed,
	ErrInsufficientFee,
	ErrTooManyReplacements,
	ErrConflictingTx,
	ErrEmptyOutput,
	ErrEmptyInput,
	ErrTxTooSmall,
	// NOTE: ErrTxTooLarge must be put after ErrTxTooSmall because it's a
	// subset of ErrTxTooSmall. Otherwise, if bitcoind returns
	// `tx-size-small`, it will be matched to ErrTxTooLarge.
	ErrTxTooLarge,
	ErrDuplicateInput,
	ErrEmptyPrevOut,
	ErrBelowOutValue,
	ErrNegativeOutput,
	ErrLargeOutput,
	ErrLargeTotalOutput,
	ErrScriptVerifyFlag,
	ErrTooManySigOps,
	ErrInvalidOpcode,
	ErrTxAlreadyKnown,
	ErrTxAlreadyInMempool,
	ErrMissingInputs,
	ErrOversizeTx,
	ErrCoinbaseTx,
	ErrNonStandardVersion,
	ErrNonStandardScript,
	ErrBareMultiSig,
	ErrScriptSigNotPushOnly,
	ErrScriptSigSize,
	ErrDust,
	ErrMultiOpReturn,
	ErrNonFinal,
	ErrNonBIP68Final,
	ErrSameNonWitnessData,
	ErrNonMandatoryScriptVerifyFlag,
	ErrMaxFeeExceeded,
}

// BtcdErrMap takes the errors returned from btcd's `testmempoolaccept` and
// `sendrawtransaction` RPCs and map them to the errors defined above, which
// are results from calling either `testmempoolaccept` or `sendrawtransaction`
// in `bitcoind`.
// references:
// - https://github.com/bitcoin/bitcoin/blob/master/test/functional/data/invalid_txs.py
// - https://github.com/bitcoin/bitcoin/blob/master/test/functional/mempool_accept.py
// - https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp
//
// Errors not mapped in `btcd`:
//   - deployment error from `validateSegWitDeployment`.
//   - the error when total inputs is higher than max allowed value from
//     `CheckTransactionInputs`.
//   - the error when total outputs is higher than total inputs from
//     `CheckTransactionInputs`.
//   - errors from `CalcSequenceLock`.
//
// NOTE: This is not an exhaustive list of errors, but it covers the
// usage case of LND.
//
//nolint:lll
var BtcdErrMap = map[string]error{
	// BIP125 related errors.
	//
	// When fee rate used or fees paid doesn't meet the requirements.
	"replacement transaction has an insufficient fee rate":     ErrInsufficientFee,
	"replacement transaction has an insufficient absolute fee": ErrInsufficientFee,

	// When a transaction causes too many transactions being replaced. This
	// is set by `MAX_REPLACEMENT_CANDIDATES` in `bitcoind` and defaults to
	// 100.
	"replacement transaction evicts more transactions than permitted": ErrTooManyReplacements,

	// When a transaction adds new unconfirmed inputs.
	"replacement transaction spends new unconfirmed input": ErrReplacementAddsUnconfirmed,

	// A transaction that spends conflicting tx outputs that are rejected.
	"replacement transaction spends parent transaction": ErrConflictingTx,

	// A transaction that conflicts with an unconfirmed tx. Happens when
	// RBF is not enabled.
	"output already spent in mempool": ErrMempoolConflict,

	// A transaction with no outputs.
	"transaction has no outputs": ErrEmptyOutput,

	// A transaction with no inputs.
	"transaction has no inputs": ErrEmptyInput,

	// A transaction with duplicate inputs.
	"transaction contains duplicate inputs": ErrDuplicateInput,

	// A non-coinbase transaction with coinbase-like outpoint.
	"transaction input refers to previous output that is null": ErrEmptyPrevOut,

	// A transaction pays too little fee.
	"fees which is under the required amount":               ErrBelowOutValue,
	"has insufficient priority":                             ErrBelowOutValue,
	"has been rejected by the rate limiter due to low fees": ErrBelowOutValue,

	// A transaction with negative output value.
	"transaction output has negative value": ErrNegativeOutput,

	// A transaction with too large output value.
	"transaction output value is higher than max allowed value": ErrLargeOutput,

	// A transaction with too large sum of output values.
	"total value of all transaction outputs exceeds max allowed value": ErrLargeTotalOutput,

	// A transaction with too many sigops.
	"sigop cost is too hight": ErrTooManySigOps,

	// A transaction already in the blockchain.
	"database contains entry for spent tx output": ErrTxAlreadyKnown,
	"transaction already exists in blockchain":    ErrTxAlreadyKnown,

	// A transaction in the mempool.
	"already have transaction in mempool": ErrTxAlreadyInMempool,

	// A transaction with missing inputs, that never existed or only
	// existed once in the past.
	"either does not exist or has already been spent": ErrMissingInputs,
	"orphan transaction":                              ErrMissingInputs,

	// A really large transaction.
	"serialized transaction is too big": ErrOversizeTx,

	// A coinbase transaction.
	"transaction is an invalid coinbase": ErrCoinbaseTx,

	// Some nonstandard transactions - a version currently non-standard.
	"transaction version": ErrNonStandardVersion,

	// Some nonstandard transactions - non-standard script.
	"non-standard script form": ErrNonStandardScript,
	"has a non-standard input": ErrNonStandardScript,

	// Some nonstandard transactions - bare multisig script
	// (2-of-3).
	"milti-signature script": ErrBareMultiSig,

	// Some nonstandard transactions - not-pushonly scriptSig.
	"signature script is not push only": ErrScriptSigNotPushOnly,

	// Some nonstandard transactions - too large scriptSig (>1650
	// bytes).
	"signature script size is larger than max allowed": ErrScriptSigSize,

	// Some nonstandard transactions - too large tx size.
	"weight of transaction is larger than max allowed": ErrTxTooLarge,

	// Some nonstandard transactions - output too small.
	"payment is dust": ErrDust,

	// Some nonstandard transactions - muiltiple OP_RETURNs.
	"more than one transaction output in a nulldata script": ErrMultiOpReturn,

	// A timelocked transaction.
	"transaction is not finalized":               ErrNonFinal,
	"tried to spend coinbase transaction output": ErrNonFinal,

	// A transaction that is locked by BIP68 sequence logic.
	"transaction's sequence locks on inputs not met": ErrNonBIP68Final,

	// TODO(yy): find/return the following errors in `btcd`.
	//
	// A tiny transaction(in non-witness bytes) that is disallowed.
	// "unmatched btcd error 1": ErrTxTooSmall,
	// "unmatched btcd error 2": ErrScriptVerifyFlag,
	// // A transaction with invalid OP codes.
	// "unmatched btcd error 3": ErrInvalidOpcode,
	// // Minimally-small transaction(in non-witness bytes) that is
	// // allowed.
	// "unmatched btcd error 4": ErrSameNonWitnessData,
}

// MapRPCErr takes an error returned from calling RPC methods from various
// chain backend and map it to an defined error here. It uses the `TxErrMap`
// defined above, whose keys are btcd error strings and values are errors made
// from bitcoind error strings.
//
// NOTE: we assume neutrino shares the same error strings as btcd.
func MapRPCErr(rpcErr error) error {
	// Iterate the map and find the matching error.
	for btcdErr, err := range BtcdErrMap {
		// Match it against btcd's error first.
		if matchErrStr(rpcErr, btcdErr) {
			return err
		}
	}

	// If not found, try to match it against bitcoind's error.
	for _, err := range BitcoindErrors {
		if matchErrStr(rpcErr, err.Error()) {
			return err
		}
	}

	// If not matched, return the original error wrapped.
	return fmt.Errorf("%w: %v", ErrUndefined, rpcErr)
}

// matchErrStr takes an error returned from RPC client and matches it against
// the specified string. If the expected string pattern is found in the error
// passed, return true. Both the error strings are normalized before matching.
func matchErrStr(err error, s string) bool {
	// Replace all dashes found in the error string with spaces.
	strippedErrStr := strings.Replace(err.Error(), "-", " ", -1)

	// Replace all dashes found in the error string with spaces.
	strippedMatchStr := strings.Replace(s, "-", " ", -1)

	// Match against the lowercase.
	return strings.Contains(
		strings.ToLower(strippedErrStr),
		strings.ToLower(strippedMatchStr),
	)
}
