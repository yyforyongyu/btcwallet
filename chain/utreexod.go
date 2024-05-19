package chain

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs"
	"github.com/btcsuite/btcd/btcutil/gcs/builder"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/waddrmgr"
	"github.com/btcsuite/btcwallet/wtxmgr"
	utreexobtcjson "github.com/utreexo/utreexod/btcjson"
	utreexobtcutil "github.com/utreexo/utreexod/btcutil"
	utreexochainhash "github.com/utreexo/utreexod/chaincfg/chainhash"
	utreexorpc "github.com/utreexo/utreexod/rpcclient"
	utreexowire "github.com/utreexo/utreexod/wire"
)

type UtreexoRPCClient struct {
	client *utreexorpc.Client

	connConfig        *utreexorpc.ConnConfig // Work around unexported field
	chainParams       *chaincfg.Params
	reconnectAttempts int

	enqueueNotification chan interface{}
	dequeueNotification chan interface{}
	currentBlock        chan *waddrmgr.BlockStamp

	quit    chan struct{}
	wg      sync.WaitGroup
	started bool
	quitMtx sync.Mutex
}

// A compile-time check to ensure that RPCClient satisfies the chain.Interface
// interface.
var _ Interface = (*UtreexoRPCClient)(nil)

// UtreexodRPCClientConfig defines the config options used when initializing
// the RPC Client.
type UtreexodRPCClientConfig struct {
	// Conn describes the connection configuration parameters for the
	// client.
	Conn *utreexorpc.ConnConfig

	// Params defines a Bitcoin network by its parameters.
	Chain *chaincfg.Params

	// NotificationHandlers defines callback function pointers to invoke
	// with notifications. If not set, the default handlers defined in this
	// client will be used.
	NotificationHandlers *utreexorpc.NotificationHandlers

	// ReconnectAttempts defines the number to reties (each after an
	// increasing backoff) if the connection can not be established.
	ReconnectAttempts int
}

// validate checks the required config options are set.
func (r *UtreexodRPCClientConfig) validate() error {
	if r == nil {
		return errors.New("missing rpc config")
	}

	// Make sure retry attempts is positive.
	if r.ReconnectAttempts < 0 {
		return errors.New("reconnectAttempts must be positive")
	}

	// Make sure the chain params are configed.
	if r.Chain == nil {
		return errors.New("missing chain params config")
	}

	// Make sure connection config is supplied.
	if r.Conn == nil {
		return errors.New("missing conn config")
	}

	// If disableTLS is false, the remote RPC certificate must be provided
	// in the certs slice.
	if !r.Conn.DisableTLS && r.Conn.Certificates == nil {
		return errors.New("must provide certs when TLS is enabled")
	}

	return nil
}

// NewUtreexodRPCClientWithConfig creates a client connection to the server
// based on the config options supplised.
//
// The connection is not established immediately, but must be done using the
// Start method.  If the remote server does not operate on the same bitcoin
// network as described by the passed chain parameters, the connection will be
// disconnected.
func NewUtreexodRPCClientWithConfig(cfg *UtreexodRPCClientConfig) (
	*UtreexoRPCClient, error) {

	// Make sure the config is valid.
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	// Mimic the old behavior defined in `NewRPCClient`. We will remove
	// these hard-codings once this package is more properly refactored.
	cfg.Conn.DisableAutoReconnect = false
	cfg.Conn.DisableConnectOnNew = true

	client := &UtreexoRPCClient{
		connConfig:          cfg.Conn,
		chainParams:         cfg.Chain,
		reconnectAttempts:   cfg.ReconnectAttempts,
		enqueueNotification: make(chan interface{}),
		dequeueNotification: make(chan interface{}),
		currentBlock:        make(chan *waddrmgr.BlockStamp),
		quit:                make(chan struct{}),
	}

	// Use the configed notification callbacks, if not set, default to the
	// callbacks defined in this package.
	ntfnCallbacks := cfg.NotificationHandlers
	if ntfnCallbacks == nil {
		ntfnCallbacks = &utreexorpc.NotificationHandlers{
			OnClientConnected:   client.onClientConnect,
			OnBlockConnected:    client.onBlockConnected,
			OnBlockDisconnected: client.onBlockDisconnected,
			OnRecvTx:            client.onRecvTx,
			OnRedeemingTx:       client.onRedeemingTx,
			OnRescanFinished:    client.onRescanFinished,
			OnRescanProgress:    client.onRescanProgress,
		}
	}

	// Create the RPC client using the above config.
	rpcClient, err := utreexorpc.New(client.connConfig, ntfnCallbacks)
	if err != nil {
		return nil, err
	}

	client.client = rpcClient
	return client, nil
}

// BackEnd returns the name of the driver.
func (c *UtreexoRPCClient) BackEnd() string {
	return "btcd"
}

func (c *UtreexoRPCClient) GetBestBlock() (*chainhash.Hash, int32, error) {
	uHash, height, err := c.client.GetBestBlock()
	if err != nil {
		return nil, height, err
	}

	var hash chainhash.Hash
	copy(hash[:], uHash[:])
	return &hash, height, nil
}

func (c *UtreexoRPCClient) GetBlockHash(blockHeight int64) (*chainhash.Hash, error) {
	uHash, err := c.client.GetBlockHash(blockHeight)
	if err != nil {
		return nil, err
	}

	var hash chainhash.Hash
	copy(hash[:], uHash[:])
	return &hash, nil
}

func (c *UtreexoRPCClient) GetBlock(hash *chainhash.Hash) (
	*wire.MsgBlock, error) {

	var uHash utreexochainhash.Hash
	copy(hash[:], uHash[:])

	uBlock, err := c.client.GetBlock(&uHash)
	if err != nil {
		return nil, err
	}

	// TODO(yy): interface wire.Block
	//
	// double check uBlock.UData
	var b []byte
	buf := bytes.NewBuffer(b)
	err = uBlock.Serialize(buf)
	if err != nil {
		return nil, err
	}

	var block wire.MsgBlock
	err = block.Deserialize(buf)
	if err != nil {
		return nil, err
	}

	return &block, nil
}

func (c *UtreexoRPCClient) GetBlockHeader(hash *chainhash.Hash) (
	*wire.BlockHeader, error) {

	var uHash utreexochainhash.Hash
	copy(hash[:], uHash[:])

	uHeader, err := c.client.GetBlockHeader(&uHash)
	if err != nil {
		return nil, err
	}

	// double check uHeader.UData
	var b []byte
	buf := bytes.NewBuffer(b)
	err = uHeader.Serialize(buf)
	if err != nil {
		return nil, err
	}

	var header wire.BlockHeader
	err = header.Deserialize(buf)
	if err != nil {
		return nil, err
	}

	return &header, nil
}

func (c *UtreexoRPCClient) GetBlockHeaderVerbose(hash *chainhash.Hash) (
	*btcjson.GetBlockHeaderVerboseResult, error) {

	var uHash utreexochainhash.Hash
	copy(hash[:], uHash[:])

	uResult, err := c.client.GetBlockHeaderVerbose(&uHash)
	if err != nil {
		return nil, err
	}

	result := &btcjson.GetBlockHeaderVerboseResult{
		Hash:          uResult.Hash,
		Confirmations: uResult.Confirmations,
		Height:        uResult.Height,
		Version:       uResult.Version,
		VersionHex:    uResult.VersionHex,
		MerkleRoot:    uResult.MerkleRoot,
		Time:          uResult.Time,
		Nonce:         uResult.Nonce,
		Bits:          uResult.Bits,
		Difficulty:    uResult.Difficulty,
		PreviousHash:  uResult.PreviousHash,
		NextHash:      uResult.NextHash,
	}

	return result, nil
}

func (c *UtreexoRPCClient) GetRawTransactionVerbose(txHash *chainhash.Hash) (
	*btcjson.TxRawResult, error) {

	var uHash utreexochainhash.Hash
	copy(txHash[:], uHash[:])

	uResult, err := c.client.GetRawTransactionVerbose(&uHash)
	if err != nil {
		return nil, err
	}

	result := &btcjson.TxRawResult{
		Hex:           uResult.Hex,
		Txid:          uResult.Txid,
		Hash:          uResult.Hash,
		Size:          uResult.Size,
		Vsize:         uResult.Vsize,
		Version:       uResult.Version,
		LockTime:      uResult.LockTime,
		BlockHash:     uResult.BlockHash,
		Confirmations: uResult.Confirmations,
		Time:          uResult.Time,
		Blocktime:     uResult.Blocktime,
	}

	vins := make([]btcjson.Vin, len(uResult.Vin))
	for _, vin := range uResult.Vin {
		txIn := btcjson.Vin{
			Coinbase: vin.Coinbase,
			Txid:     vin.Txid,
			Vout:     vin.Vout,
			ScriptSig: &btcjson.ScriptSig{
				Asm: vin.ScriptSig.Asm,
				Hex: vin.ScriptSig.Hex,
			},
			Sequence: vin.Sequence,
			Witness:  vin.Witness,
		}
		vins = append(vins, txIn)
	}

	vouts := make([]btcjson.Vout, len(uResult.Vout))
	for _, vout := range uResult.Vout {
		txOut := btcjson.Vout{
			Value: vout.Value,
			N:     vout.N,
			ScriptPubKey: btcjson.ScriptPubKeyResult{
				Asm:       vout.ScriptPubKey.Asm,
				Hex:       vout.ScriptPubKey.Hex,
				ReqSigs:   vout.ScriptPubKey.ReqSigs,
				Type:      vout.ScriptPubKey.Type,
				Addresses: vout.ScriptPubKey.Addresses,
			},
		}
		vouts = append(vouts, txOut)
	}

	result.Vin = vins
	result.Vout = vouts

	return result, nil
}

func (c *UtreexoRPCClient) NotifyBlocks() error {
	return c.client.NotifyBlocks()
}

func (c *UtreexoRPCClient) NotifyReceived(addresses []btcutil.Address) error {
	uAddresses := make([]utreexobtcutil.Address, len(addresses))
	for i, addr := range addresses {
		uAddresses[i] = addr.(utreexobtcutil.Address)
	}

	return c.client.NotifyReceived(uAddresses)
}
func (c *UtreexoRPCClient) SendRawTransaction(tx *wire.MsgTx, allowHighFees bool) (
	*chainhash.Hash, error) {

	// double check tx.UData
	var b []byte
	buf := bytes.NewBuffer(b)
	err := tx.Serialize(buf)
	if err != nil {
		return nil, err
	}

	var uTx utreexowire.MsgTx
	err = uTx.Deserialize(buf)
	if err != nil {
		return nil, err
	}

	uHash, err := c.client.SendRawTransaction(&uTx, allowHighFees)
	if err != nil {
		return nil, err
	}

	var hash chainhash.Hash
	copy(hash[:], uHash[:])
	return &hash, nil
}

func (c *UtreexoRPCClient) TestMempoolAccept(txns []*wire.MsgTx,
	maxFeeRate float64) ([]*btcjson.TestMempoolAcceptResult, error) {

	return nil, ErrUnimplemented
}

func (c *UtreexoRPCClient) Connect(reconnectAttempts int) error {
	return c.client.Connect(reconnectAttempts)
}

// Start attempts to establish a client connection with the remote server.
// If successful, handler goroutines are started to process notifications
// sent by the server.  After a limited number of connection attempts, this
// function gives up, and therefore will not block forever waiting for the
// connection to be established to a server that may not exist.
func (c *UtreexoRPCClient) Start() error {
	err := c.client.Connect(c.reconnectAttempts)
	if err != nil {
		return err
	}

	// Verify that the server is running on the expected network.
	net, err := c.client.GetCurrentNet()
	if err != nil {
		c.client.Disconnect()
		return err
	}
	if net.String() != c.chainParams.Net.String() {
		c.client.Disconnect()
		return errors.New("mismatched networks")
	}

	c.quitMtx.Lock()
	c.started = true
	c.quitMtx.Unlock()

	c.wg.Add(1)
	go c.handler()
	return nil
}

// Stop disconnects the client and signals the shutdown of all goroutines
// started by Start.
func (c *UtreexoRPCClient) Stop() {
	c.quitMtx.Lock()
	select {
	case <-c.quit:
	default:
		close(c.quit)
		c.client.Shutdown()

		if !c.started {
			close(c.dequeueNotification)
		}
	}
	c.quitMtx.Unlock()
}

// IsCurrent returns whether the chain backend considers its view of the network
// as "current".
func (c *UtreexoRPCClient) IsCurrent() bool {
	bestHash, _, err := c.client.GetBestBlock()
	if err != nil {
		return false
	}
	bestHeader, err := c.client.GetBlockHeader(bestHash)
	if err != nil {
		return false
	}
	return bestHeader.Timestamp.After(time.Now().Add(-isCurrentDelta))
}

// Rescan wraps the normal Rescan command with an additional parameter that
// allows us to map an outpoint to the address in the chain that it pays to.
// This is useful when using BIP 158 filters as they include the prev pkScript
// rather than the full outpoint.
func (c *UtreexoRPCClient) Rescan(startHash *chainhash.Hash, addrs []btcutil.Address,
	outPoints map[wire.OutPoint]btcutil.Address) error {

	flatOutpoints := make([]*wire.OutPoint, 0, len(outPoints))
	for ops := range outPoints {
		ops := ops

		flatOutpoints = append(flatOutpoints, &ops)
	}

	// return c.Client.Rescan(startHash, addrs, flatOutpoints) // nolint:staticcheck
	return nil
}

// WaitForShutdown blocks until both the client has finished disconnecting
// and all handlers have exited.
func (c *UtreexoRPCClient) WaitForShutdown() {
	c.client.WaitForShutdown()
	c.wg.Wait()
}

// Notifications returns a channel of parsed notifications sent by the remote
// bitcoin RPC server.  This channel must be continually read or the process
// may abort for running out memory, as unread notifications are queued for
// later reads.
func (c *UtreexoRPCClient) Notifications() <-chan interface{} {
	return c.dequeueNotification
}

// BlockStamp returns the latest block notified by the client, or an error
// if the client has been shut down.
func (c *UtreexoRPCClient) BlockStamp() (*waddrmgr.BlockStamp, error) {
	select {
	case bs := <-c.currentBlock:
		return bs, nil
	case <-c.quit:
		return nil, errors.New("disconnected")
	}
}

func (c *UtreexoRPCClient) GetCFilter(hash *chainhash.Hash,
	filterType wire.FilterType) (*wire.MsgCFilter, error) {

	var uHash utreexochainhash.Hash
	copy(hash[:], uHash[:])

	uFilterType := utreexowire.FilterType(filterType)

	uFilter, err := c.client.GetCFilter(&uHash, uFilterType)
	if err != nil {
		return nil, err
	}

	filter := &wire.MsgCFilter{
		FilterType: filterType,
		BlockHash:  *hash,
		Data:       uFilter.Data,
	}

	return filter, nil
}

// FilterBlocks scans the blocks contained in the FilterBlocksRequest for any
// addresses of interest. For each requested block, the corresponding compact
// filter will first be checked for matches, skipping those that do not report
// anything. If the filter returns a positive match, the full block will be
// fetched and filtered. This method returns a FilterBlocksResponse for the first
// block containing a matching address. If no matches are found in the range of
// blocks requested, the returned response will be nil.
func (c *UtreexoRPCClient) FilterBlocks(
	req *FilterBlocksRequest) (*FilterBlocksResponse, error) {

	blockFilterer := NewBlockFilterer(c.chainParams, req)

	// Construct the watchlist using the addresses and outpoints contained
	// in the filter blocks request.
	watchList, err := buildFilterBlocksWatchList(req)
	if err != nil {
		return nil, err
	}

	// Iterate over the requested blocks, fetching the compact filter for
	// each one, and matching it against the watchlist generated above. If
	// the filter returns a positive match, the full block is then requested
	// and scanned for addresses using the block filterer.
	for i, blk := range req.Blocks {
		rawFilter, err := c.GetCFilter(&blk.Hash, wire.GCSFilterRegular)
		if err != nil {
			return nil, err
		}

		// Ensure the filter is large enough to be deserialized.
		if len(rawFilter.Data) < 4 {
			continue
		}

		filter, err := gcs.FromNBytes(
			builder.DefaultP, builder.DefaultM, rawFilter.Data,
		)
		if err != nil {
			return nil, err
		}

		// Skip any empty filters.
		if filter.N() == 0 {
			continue
		}

		key := builder.DeriveKey(&blk.Hash)
		matched, err := filter.MatchAny(key, watchList)
		if err != nil {
			return nil, err
		} else if !matched {
			continue
		}

		log.Infof("Fetching block height=%d hash=%v",
			blk.Height, blk.Hash)

		rawBlock, err := c.GetBlock(&blk.Hash)
		if err != nil {
			return nil, err
		}

		if !blockFilterer.FilterBlock(rawBlock) {
			continue
		}

		// If any external or internal addresses were detected in this
		// block, we return them to the caller so that the rescan
		// windows can widened with subsequent addresses. The
		// `BatchIndex` is returned so that the caller can compute the
		// *next* block from which to begin again.
		resp := &FilterBlocksResponse{
			BatchIndex:         uint32(i),
			BlockMeta:          blk,
			FoundExternalAddrs: blockFilterer.FoundExternal,
			FoundInternalAddrs: blockFilterer.FoundInternal,
			FoundOutPoints:     blockFilterer.FoundOutPoints,
			RelevantTxns:       blockFilterer.RelevantTxns,
		}

		return resp, nil
	}

	// No addresses were found for this range.
	return nil, nil
}

func (c *UtreexoRPCClient) onClientConnect() {
	select {
	case c.enqueueNotification <- ClientConnected{}:
	case <-c.quit:
	}
}

func (c *UtreexoRPCClient) onBlockConnected(uhash *utreexochainhash.Hash, height int32, time time.Time) {
	select {
	case c.enqueueNotification <- BlockConnected{
		Block: wtxmgr.Block{
			Hash:   chainhash.Hash(*uhash),
			Height: height,
		},
		Time: time,
	}:
	case <-c.quit:
	}
}

func (c *UtreexoRPCClient) onBlockDisconnected(uhash *utreexochainhash.Hash, height int32, time time.Time) {
	select {
	case c.enqueueNotification <- BlockDisconnected{
		Block: wtxmgr.Block{
			Hash:   chainhash.Hash(*uhash),
			Height: height,
		},
		Time: time,
	}:
	case <-c.quit:
	}
}

func (c *UtreexoRPCClient) onRecvTx(utx *utreexobtcutil.Tx,
	ublock *utreexobtcjson.BlockDetails) {

	block := &btcjson.BlockDetails{
		Hash:   ublock.Hash,
		Height: ublock.Height,
		Index:  ublock.Index,
		Time:   ublock.Time,
	}

	blk, err := parseBlock(block)
	if err != nil {
		// Log and drop improper notification.
		log.Errorf("recvtx notification bad block: %v", err)
		return
	}

	var b []byte
	buf := bytes.NewBuffer(b)
	if err := utx.MsgTx().Serialize(buf); err != nil {
		log.Errorf("Failed to serialize tx: %v", err)
		return
	}

	var msgTx *wire.MsgTx
	if err := msgTx.Deserialize(buf); err != nil {
		log.Errorf("Failed to deserialize tx: %v", err)
		return
	}

	rec, err := wtxmgr.NewTxRecordFromMsgTx(msgTx, time.Now())
	if err != nil {
		log.Errorf("Cannot create transaction record for relevant "+
			"tx: %v", err)
		return
	}
	select {
	case c.enqueueNotification <- RelevantTx{rec, blk}:
	case <-c.quit:
	}
}

func (c *UtreexoRPCClient) onRedeemingTx(utx *utreexobtcutil.Tx,
	ublock *utreexobtcjson.BlockDetails) {

	// Handled exactly like recvtx notifications.
	c.onRecvTx(utx, ublock)
}

func (c *UtreexoRPCClient) onRescanProgress(uhash *utreexochainhash.Hash,
	height int32, blkTime time.Time) {

	hash := chainhash.Hash(*uhash)

	select {
	case c.enqueueNotification <- &RescanProgress{hash, height, blkTime}:
	case <-c.quit:
	}
}

func (c *UtreexoRPCClient) onRescanFinished(uhash *utreexochainhash.Hash,
	height int32, blkTime time.Time) {

	hash := chainhash.Hash(*uhash)

	select {
	case c.enqueueNotification <- &RescanFinished{&hash, height, blkTime}:
	case <-c.quit:
	}

}

// handler maintains a queue of notifications and the current state (best
// block) of the chain.
func (c *UtreexoRPCClient) handler() {
	uHash, height, err := c.GetBestBlock()
	if err != nil {
		log.Errorf("Failed to receive best block from chain server: %v", err)
		c.Stop()
		c.wg.Done()
		return
	}

	var hash chainhash.Hash
	copy(hash[:], uHash[:])

	bs := &waddrmgr.BlockStamp{Hash: hash, Height: height}

	// TODO: Rather than leaving this as an unbounded queue for all types of
	// notifications, try dropping ones where a later enqueued notification
	// can fully invalidate one waiting to be processed.  For example,
	// blockconnected notifications for greater block heights can remove the
	// need to process earlier blockconnected notifications still waiting
	// here.

	var notifications []interface{}
	enqueue := c.enqueueNotification
	var dequeue chan interface{}
	var next interface{}
out:
	for {
		select {
		case n, ok := <-enqueue:
			if !ok {
				// If no notifications are queued for handling,
				// the queue is finished.
				if len(notifications) == 0 {
					break out
				}
				// nil channel so no more reads can occur.
				enqueue = nil
				continue
			}
			if len(notifications) == 0 {
				next = n
				dequeue = c.dequeueNotification
			}
			notifications = append(notifications, n)

		case dequeue <- next:
			if n, ok := next.(BlockConnected); ok {
				bs = &waddrmgr.BlockStamp{
					Height: n.Height,
					Hash:   n.Hash,
				}
			}

			notifications[0] = nil
			notifications = notifications[1:]
			if len(notifications) != 0 {
				next = notifications[0]
			} else {
				// If no more notifications can be enqueued, the
				// queue is finished.
				if enqueue == nil {
					break out
				}
				dequeue = nil
			}

		case c.currentBlock <- bs:

		case <-c.quit:
			break out
		}
	}

	c.Stop()
	close(c.dequeueNotification)
	c.wg.Done()
}

// POSTClient creates the equivalent HTTP POST rpcclient.Client.
func (c *UtreexoRPCClient) POSTClient() (*utreexorpc.Client, error) {
	configCopy := *c.connConfig
	configCopy.HTTPPostMode = true
	return utreexorpc.New(&configCopy, nil)
}

// LookupInputMempoolSpend returns the transaction hash and true if the given
// input is found being spent in mempool, otherwise it returns nil and false.
func (c *UtreexoRPCClient) LookupInputMempoolSpend(op wire.OutPoint) (
	chainhash.Hash, bool) {

	// TODO: interface c.Client
	// return getTxSpendingPrevOut(op, c.Client)
	return chainhash.Hash{}, false
}

func (u *UtreexoRPCClient) NotifySpent(outPoints []*wire.OutPoint) error {
	uOutpoints := make([]*utreexowire.OutPoint, len(outPoints))
	for i, op := range outPoints {
		uOutpoints[i] = &utreexowire.OutPoint{
			Hash:  utreexochainhash.Hash(op.Hash),
			Index: op.Index,
		}
	}

	return u.client.NotifySpent(uOutpoints)
}

// func (u *UtreexoRPCClient) RescanAsync(startBlock *chainhash.Hash,
// 	addresses []btcutil.Address,
// 	outpoints []*wire.OutPoint) rpcclient.FutureRescanResult {

// 	uStartBlock := utreexochainhash.Hash(*startBlock)

// 	uAddresses := make([]utreexobtcutil.Address, len(addresses))
// 	// for i, addr := range addresses {
// 	// 	uAddresses[i] = utreexobtcutil.Address(addr)
// 	// }

// 	uOutpoints := make([]*utreexowire.OutPoint, len(outpoints))
// 	for i, op := range outpoints {
// 		uOutpoints[i] = &utreexowire.OutPoint{
// 			Hash:  utreexochainhash.Hash(op.Hash),
// 			Index: op.Index,
// 		}
// 	}
// 	result := u.client.RescanAsync(&uStartBlock, uAddresses, uOutpoints)
// }

func (u *UtreexoRPCClient) GetTxOut(txHash *chainhash.Hash, index uint32,
	mempool bool) (*btcjson.GetTxOutResult, error) {

	uTxHash := utreexochainhash.Hash(*txHash)
	uResult, err := u.client.GetTxOut(&uTxHash, index, mempool)
	if err != nil {
		return nil, err
	}

	result := &btcjson.GetTxOutResult{
		BestBlock:     uResult.BestBlock,
		Confirmations: uResult.Confirmations,
		Value:         uResult.Value,
		ScriptPubKey: btcjson.ScriptPubKeyResult{
			Asm:       uResult.ScriptPubKey.Asm,
			Hex:       uResult.ScriptPubKey.Hex,
			ReqSigs:   uResult.ScriptPubKey.ReqSigs,
			Type:      uResult.ScriptPubKey.Type,
			Addresses: uResult.ScriptPubKey.Addresses,
		},
		Coinbase: uResult.Coinbase,
	}

	return result, nil
}

func (u *UtreexoRPCClient) GetRawTransaction(txHash *chainhash.Hash) (
	*btcutil.Tx, error) {

	uTxHash := utreexochainhash.Hash(*txHash)
	uTx, err := u.client.GetRawTransaction(&uTxHash)
	if err != nil {
		return nil, err
	}

	var b []byte
	buf := bytes.NewBuffer(b)
	if err := uTx.MsgTx().Serialize(buf); err != nil {
		return nil, err
	}

	return btcutil.NewTxFromBytes(buf.Bytes())
}

// LoadTxFilter loads, reloads, or adds data to a websocket client's transaction
// filter.  The filter is consistently updated based on inspected transactions
// during mempool acceptance, block acceptance, and for all rescanned blocks.
func (u *UtreexoRPCClient) LoadTxFilter(reload bool,
	addresses []btcutil.Address, outPoints []wire.OutPoint) error {

	uAddresses := make([]utreexobtcutil.Address, len(addresses))
	for i, addr := range addresses {
		uAddresses[i] = addr.(utreexobtcutil.Address)
	}

	uOutpoints := make([]utreexowire.OutPoint, len(outPoints))
	for i, op := range outPoints {
		uOutpoints[i] = utreexowire.OutPoint{
			Hash:  utreexochainhash.Hash(op.Hash),
			Index: op.Index,
		}
	}

	return u.client.LoadTxFilter(reload, uAddresses, uOutpoints)
}

func (u *UtreexoRPCClient) RescanBlocks(
	blockHashes []chainhash.Hash) ([]btcjson.RescannedBlock, error) {

	uBlockHashes := make([]utreexochainhash.Hash, len(blockHashes))
	for i, hash := range blockHashes {
		uBlockHashes[i] = utreexochainhash.Hash(hash)
	}

	uBlocks, err := u.client.RescanBlocks(uBlockHashes)
	if err != nil {
		return nil, err
	}

	blocks := make([]btcjson.RescannedBlock, len(uBlocks))
	for i, uBlock := range uBlocks {
		blocks[i] = btcjson.RescannedBlock{
			Hash:         uBlock.Hash,
			Transactions: uBlock.Transactions,
		}
	}

	return blocks, nil
}
