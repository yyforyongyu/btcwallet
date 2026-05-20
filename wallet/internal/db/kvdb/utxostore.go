// Package kvdb provides a walletdb (kvdb) backed implementation of the
// wallet/internal/db UTXO store interface.
package kvdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wallet/internal/db"
	"github.com/btcsuite/btcwallet/walletdb"
	"github.com/btcsuite/btcwallet/wtxmgr"
)

var (
	// errNotImplemented is returned for unimplemented kvdb store methods.
	errNotImplemented = errors.New("not implemented")

	// errMissingTxmgrNamespace is returned when the legacy transaction manager
	// bucket is not available in the kvdb wallet database.
	errMissingTxmgrNamespace = errors.New("missing wtxmgr namespace")

	// wtxmgrNamespaceKey is the walletdb top-level bucket key used by the
	// transaction manager.
	//
	// NOTE: This must match the namespace used by the wallet package.
	wtxmgrNamespaceKey = []byte("wtxmgr")
)

// notImplemented returns a consistent error for kvdb methods that still need a
// legacy-backed implementation.
func notImplemented(_ context.Context, method string) error {
	return fmt.Errorf("kvdb.Store.%s: %w", method, errNotImplemented)
}

// GetUtxo retrieves one current wallet-owned UTXO through the legacy wtxmgr
// query path.
func (s *Store) GetUtxo(_ context.Context,
	query db.GetUtxoQuery) (*db.UtxoInfo, error) {

	var utxo *db.UtxoInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		ns := tx.ReadBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return errMissingTxmgrNamespace
		}

		credit, err := s.txStore.GetUtxo(ns, query.OutPoint)
		if err != nil {
			if errors.Is(err, wtxmgr.ErrUtxoNotFound) {
				return db.ErrUtxoNotFound
			}

			return fmt.Errorf("get utxo: %w", err)
		}

		utxo = utxoInfo(credit)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.GetUtxo: %w", err)
	}

	return utxo, nil
}

// ListUTXOs lists current wallet-owned UTXOs through the legacy wtxmgr query
// path.
func (s *Store) ListUTXOs(_ context.Context,
	query db.ListUtxosQuery) ([]db.UtxoInfo, error) {

	if s.addrStore == nil {
		return nil, fmt.Errorf("kvdb.Store.ListUTXOs: %w",
			errMissingAddrStore)
	}

	var utxos []db.UtxoInfo

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		return s.listUTXOsInView(tx, query, &utxos)
	})
	if err != nil {
		return nil, fmt.Errorf("kvdb.Store.ListUTXOs: %w", err)
	}

	if len(utxos) == 0 {
		return []db.UtxoInfo{}, nil
	}

	return utxos, nil
}

// LeaseOutput is not yet implemented for kvdb.
func (s *Store) LeaseOutput(ctx context.Context,
	_ db.LeaseOutputParams) (*db.LeasedOutput, error) {

	return nil, notImplemented(ctx, "LeaseOutput")
}

// ReleaseOutput releases a previously leased output.
//
// How it works:
// The method executes a single walletdb update transaction that deletes the
// lock record associated with the specified outpoint.
//
// Database Actions:
//   - Performs exactly one write transaction (walletdb.Update).
//   - Writes to the `wtxmgr` namespace.
//
// NOTE: The legacy kvdb backend only supports a single wallet instance, so the
// WalletID field is ignored.
func (s *Store) ReleaseOutput(_ context.Context,
	params db.ReleaseOutputParams) error {

	lockID := wtxmgr.LockID(params.ID)
	op := params.OutPoint

	err := walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if ns == nil {
			return fmt.Errorf(
				"wtxmgr namespace: %w", walletdb.ErrBucketNotFound,
			)
		}

		err := s.txStore.UnlockOutput(ns, lockID, op)
		if err != nil {
			return fmt.Errorf("unlock output: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("kvdb.Store.ReleaseOutput: %w", err)
	}

	return nil
}

// ListLeasedOutputs is not yet implemented for kvdb.
func (s *Store) ListLeasedOutputs(ctx context.Context,
	_ uint32) ([]db.LeasedOutput, error) {

	return nil, notImplemented(ctx, "ListLeasedOutputs")
}

// Balance sums the wallet's unspent outputs that satisfy the supplied
// filters. The walk iterates every UTXO owned by the address manager
// and applies Scope, Account, MinConfs, MaxConfs, and CoinbaseMaturity
// in turn. Outputs whose script does not extract to a recognized
// address, or that waddrmgr cannot map to an account, are skipped.
func (s *Store) Balance(_ context.Context,
	params db.BalanceParams) (db.BalanceResult, error) {

	err := params.Validate()
	if err != nil {
		return db.BalanceResult{}, err
	}

	var scopeFilter *waddrmgr.KeyScope
	if params.Scope != nil {
		scopeFilter = &waddrmgr.KeyScope{
			Purpose: params.Scope.Purpose,
			Coin:    params.Scope.Coin,
		}
	}

	var result db.BalanceResult

	err = walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgr.NamespaceKey)
		if addrmgrNs == nil {
			return nil
		}

		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)

		total, locked, err := s.walkBalanceUTXOs(
			addrmgrNs, txmgrNs, params, scopeFilter,
		)
		if err != nil {
			return err
		}

		result.Total = total
		result.Locked = locked

		return nil
	})
	if err != nil {
		return db.BalanceResult{}, fmt.Errorf("balance: %w", err)
	}

	return result, nil
}

// walkBalanceUTXOs iterates the wallet's unspent outputs and sums total and
// locked amounts for those that satisfy the BalanceParams filters. The caller
// holds the wallet db read transaction.
func (s *Store) walkBalanceUTXOs(addrmgrNs, txmgrNs walletdb.ReadBucket,
	params db.BalanceParams,
	scopeFilter *waddrmgr.KeyScope) (btcutil.Amount, btcutil.Amount, error) {

	if s.txStore == nil || txmgrNs == nil {
		return 0, 0, nil
	}

	nameFound, err := s.resolveBalanceNameFilter(
		addrmgrNs, &params, scopeFilter,
	)
	if err != nil {
		return 0, 0, err
	}

	if !nameFound {
		return 0, 0, nil
	}

	syncBlock := s.addrStore.SyncedTo()
	chainParams := s.addrStore.ChainParams()

	unspent, err := s.txStore.UnspentOutputsIncludingLocked(txmgrNs)
	if err != nil {
		return 0, 0, fmt.Errorf("unspent outputs: %w", err)
	}

	var total, locked btcutil.Amount
	for i := range unspent {
		output := &unspent[i]

		owner, account, ok := s.classifyBalanceUTXO(
			addrmgrNs, output, chainParams,
		)
		if !ok {
			continue
		}

		if !balanceFilterAllows(
			scopeFilter, owner, params, account,
		) {

			continue
		}

		if !confsAllowed(
			output, syncBlock.Height, params,
		) {

			continue
		}

		total, locked = addBalanceOutput(total, locked, output)
	}

	return total, locked, nil
}

// addBalanceOutput adds an accepted output to the total balance and, when the
// output is locked, the locked subset.
func addBalanceOutput(total, locked btcutil.Amount,
	output *wtxmgr.Credit) (btcutil.Amount, btcutil.Amount) {

	total += output.Amount
	if output.Locked {
		locked += output.Amount
	}

	return total, locked
}

// resolveBalanceNameFilter resolves BalanceParams.Name into the real waddrmgr
// account number before the UTXO walk. A missing name means no UTXOs match,
// so the caller should return a zero balance without an error.
func (s *Store) resolveBalanceNameFilter(addrmgrNs walletdb.ReadBucket,
	params *db.BalanceParams, scopeFilter *waddrmgr.KeyScope) (bool, error) {

	if params.Name == nil {
		return true, nil
	}

	scopedMgr, err := s.addrStore.FetchScopedKeyManager(*scopeFilter)
	if err != nil {
		return false, fmt.Errorf("fetch scoped manager: %w", err)
	}

	acctNum, err := scopedMgr.LookupAccount(addrmgrNs, *params.Name)
	if err != nil {
		if waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound) {
			return false, nil
		}

		return false, fmt.Errorf("lookup account: %w", err)
	}

	// Internal filtering stays on the real account number; the public
	// AccountInfo.AccountNumber masking only applies at the read API boundary.
	params.Account = &acctNum

	return true, nil
}

// classifyBalanceUTXO maps an unspent output to its owning address and
// wallet account. It returns ok=false when the script does not extract
// to a recognized address or waddrmgr cannot map it to an account; the
// caller should skip such outputs.
func (s *Store) classifyBalanceUTXO(addrmgrNs walletdb.ReadBucket,
	output *wtxmgr.Credit,
	chainParams *chaincfg.Params) (waddrmgr.AccountStore, uint32, bool) {

	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
		output.PkScript, chainParams,
	)
	if err != nil || len(addrs) == 0 {
		return nil, 0, false
	}

	owner, account, err := s.addrStore.AddrAccount(addrmgrNs, addrs[0])
	if err != nil {
		return nil, 0, false
	}

	return owner, account, true
}

// balanceFilterAllows reports whether an output's owning address and
// account survive the Scope and Account filters from BalanceParams.
func balanceFilterAllows(scopeFilter *waddrmgr.KeyScope,
	owner waddrmgr.AccountStore, params db.BalanceParams,
	account uint32) bool {

	if scopeFilter != nil && *scopeFilter != owner.Scope() {
		return false
	}

	if params.Account != nil && *params.Account != account {
		return false
	}

	return true
}

// confsAllowed reports whether an unspent output's confirmation depth
// passes the BalanceParams filters (MinConfs, MaxConfs, and the
// CoinbaseMaturity gate that applies to coinbase outputs).
func confsAllowed(output *wtxmgr.Credit, syncHeight int32,
	params db.BalanceParams) bool {

	confs := calcConfs(output.Height, syncHeight)

	if params.MinConfs != nil && confs < *params.MinConfs {
		return false
	}

	if params.MaxConfs != nil && confs > *params.MaxConfs {
		return false
	}

	if output.FromCoinBase && params.CoinbaseMaturity != nil &&
		confs < *params.CoinbaseMaturity {

		return false
	}

	return true
}

// calcConfs returns the number of confirmations for an output at
// outputHeight given a chain tip of curHeight. Unconfirmed outputs
// (height == -1) return 0; future-dated outputs (height > tip) clamp
// to 0.
func calcConfs(outputHeight, curHeight int32) int32 {
	if outputHeight <= 0 || outputHeight > curHeight {
		return 0
	}

	return curHeight - outputHeight + 1
}

// utxoInfo maps one legacy wtxmgr credit into the db-native UTXO shape.
func utxoInfo(credit *wtxmgr.Credit) *db.UtxoInfo {
	height := db.UnminedHeight
	if credit.Height >= 0 {
		height = nonNegativeInt32ToUint32(credit.Height)
	}

	return &db.UtxoInfo{
		OutPoint:     credit.OutPoint,
		Amount:       credit.Amount,
		PkScript:     credit.PkScript,
		Received:     credit.Received.UTC(),
		FromCoinBase: credit.FromCoinBase,
		Height:       height,
	}
}

// listUTXOsInView performs the legacy UTXO scan using one walletdb view.
func (s *Store) listUTXOsInView(tx walletdb.ReadTx,
	query db.ListUtxosQuery, utxos *[]db.UtxoInfo) error {

	txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
	if txmgrNs == nil {
		return errMissingTxmgrNamespace
	}

	addrmgrNs := tx.ReadBucket(waddrmgr.NamespaceKey)
	if addrmgrNs == nil {
		return errMissingAddrmgrNamespace
	}

	credits, err := s.txStore.UnspentOutputs(txmgrNs)
	if err != nil {
		return fmt.Errorf("list unspent outputs: %w", err)
	}

	currentHeight := s.addrStore.SyncedTo().Height
	chainParams := s.addrStore.ChainParams()

	for i := range credits {
		credit := &credits[i]

		include, err := s.shouldIncludeUtxo(
			addrmgrNs, credit, currentHeight, chainParams, query,
		)
		if err != nil {
			return err
		}

		if include {
			*utxos = append(*utxos, *utxoInfo(credit))
		}
	}

	return nil
}

// utxoMatchesConfirmations applies the optional db.ListUtxosQuery confirmation
// filters using legacy current-height state.
func utxoMatchesConfirmations(txHeight int32, currentHeight int32,
	query db.ListUtxosQuery) bool {

	confs := calcConfirmations(txHeight, currentHeight)

	if query.MinConfs != nil && confs < *query.MinConfs {
		return false
	}

	if query.MaxConfs != nil && confs > *query.MaxConfs {
		return false
	}

	return true
}

// shouldIncludeUtxo applies the legacy confirmation and optional account
// filters to one credit before it is adapted to db.UtxoInfo.
func (s *Store) shouldIncludeUtxo(addrmgrNs walletdb.ReadBucket,
	credit *wtxmgr.Credit, currentHeight int32,
	chainParams *chaincfg.Params,
	query db.ListUtxosQuery) (bool, error) {

	if !utxoMatchesConfirmations(credit.Height, currentHeight, query) {
		return false, nil
	}

	if query.Account == nil {
		return true, nil
	}

	return s.utxoMatchesAccount(
		addrmgrNs, credit.PkScript, chainParams, *query.Account,
	)
}

// utxoMatchesAccount checks whether one legacy UTXO belongs to the caller's
// requested account number.
func (s *Store) utxoMatchesAccount(addrmgrNs walletdb.ReadBucket,
	pkScript []byte, chainParams *chaincfg.Params,
	account uint32) (bool, error) {

	addr, err := addressFromPkScript(pkScript, chainParams)
	if err != nil {
		return false, err
	}

	_, utxoAccount, err := s.addrStore.AddrAccount(addrmgrNs, addr)
	if err != nil {
		return false, fmt.Errorf("lookup utxo account: %w", err)
	}

	return utxoAccount == account, nil
}

// calcConfirmations mirrors the wallet confirmation calculation used by the
// public UTXO manager.
func calcConfirmations(txHeight, currentHeight int32) int32 {
	switch {
	case txHeight == -1:
		return 0

	case txHeight > currentHeight:
		return 0

	default:
		return currentHeight - txHeight + 1
	}
}
