package txfuzz

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"math/big"
	"math/rand"

	"github.com/MariusVanDerWijden/FuzzyVM/filler"
	"github.com/MariusVanDerWijden/FuzzyVM/generator"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/holiman/uint256"
)

// RandomCode creates a random byte code from the passed filler.
func RandomCode(f *filler.Filler) []byte {
	_, code := generator.GenerateProgram(f)
	return code
}

// RandomTx creates a random transaction.
func RandomTx(f *filler.Filler) (*types.Transaction, error) {
	nonce := uint64(rand.Int63())
	gasPrice := big.NewInt(rand.Int63())
	chainID := big.NewInt(rand.Int63())
	return RandomValidTx(nil, f, common.Address{}, nonce, gasPrice, chainID, false, 1.0)
}

type txConf struct {
	rpc      *rpc.Client
	nonce    uint64
	sender   common.Address
	to       *common.Address
	value    *big.Int
	gasLimit uint64
	gasPrice *big.Int
	chainID  *big.Int
	code     []byte
}

// EstimateGas estimates gas for a transaction with optional multiplier and fallback default.
// If estimation fails, it logs a warning and returns defaultGas.
// If estimation succeeds, it applies the multiplier and returns the adjusted value.
func EstimateGas(backend *ethclient.Client, msg ethereum.CallMsg, defaultGas uint64, multiplier float64) uint64 {
	gas, err := backend.EstimateGas(context.Background(), msg)
	if err != nil {
		slog.Warn(fmt.Sprintf("Failed to estimate gas, using default %d: %v", defaultGas, err))
		return defaultGas
	}

	// Apply multiplier
	adjustedGas := uint64(float64(gas) * multiplier)
	if multiplier != 1.0 {
		slog.Debug(fmt.Sprintf("Estimated gas: %d, adjusted: %d (multiplier: %.2f)", gas, adjustedGas, multiplier))
	}
	return adjustedGas
}

// SendTransaction sends a transaction with debug logging before and after.
func SendTransaction(ctx context.Context, backend *ethclient.Client, tx *types.Transaction) error {
	// Extract transaction details
	var from common.Address
	var signer types.Signer

	// Determine signer based on transaction type
	if tx.Type() == types.BlobTxType || tx.Type() == types.DynamicFeeTxType {
		signer = types.LatestSignerForChainID(tx.ChainId())
	} else if tx.Type() == types.SetCodeTxType {
		signer = types.NewPragueSigner(tx.ChainId())
	} else {
		signer = types.LatestSignerForChainID(tx.ChainId())
	}

	from, err := types.Sender(signer, tx)
	if err != nil {
		from = common.Address{} // Use zero address if we can't recover sender
	}

	to := "contract_creation"
	if tx.To() != nil {
		to = tx.To().Hex()
	}

	// Format gas price based on transaction type
	gasPrice := "unknown"
	if tx.GasPrice() != nil && tx.GasPrice().Sign() > 0 {
		gasPrice = tx.GasPrice().String()
	} else if tx.GasFeeCap() != nil {
		gasPrice = fmt.Sprintf("tip=%s/cap=%s", tx.GasTipCap().String(), tx.GasFeeCap().String())
	}

	// Log before sending
	slog.Debug(fmt.Sprintf("Sending transaction: from=%s to=%s nonce=%d gas=%d gasPrice=%s value=%s dataLen=%d type=%d",
		from.Hex(), to, tx.Nonce(), tx.Gas(), gasPrice, tx.Value().String(), len(tx.Data()), tx.Type()))

	// Send transaction
	err = backend.SendTransaction(ctx, tx)
	if err != nil {
		slog.Warn(fmt.Sprintf("Transaction failed: %v (from=%s to=%s nonce=%d)", err, from.Hex(), to, tx.Nonce()))
		return err
	}

	// Log success
	slog.Debug(fmt.Sprintf("Transaction sent: hash=%s nonce=%d", tx.Hash().Hex(), tx.Nonce()))
	return nil
}

// GetPendingNonce gets the pending nonce for an address with debug logging.
// If local nonce tracking is enabled, checks the cache first before querying RPC.
func GetPendingNonce(ctx context.Context, backend *ethclient.Client, sender common.Address) (uint64, error) {
	// Check cache first (if enabled)
	if nonceManager != nil && nonceManager.enabled {
		if nonce, exists := nonceManager.Get(sender); exists {
			slog.Debug(fmt.Sprintf("Using cached nonce: %d (sender=%s)", nonce, sender.Hex()))
			return nonce, nil
		}
	}

	// Query network (first time or disabled)
	nonce, err := backend.PendingNonceAt(ctx, sender)
	if err != nil {
		return 0, err
	}

	// Cache for next time (if enabled)
	// Store the nonce as-is; Get() will increment it for subsequent calls
	if nonceManager != nil && nonceManager.enabled {
		nonceManager.Set(sender, nonce)
	}

	slog.Debug(fmt.Sprintf("Got pending nonce from RPC: %d (sender=%s)", nonce, sender.Hex()))
	return nonce, nil
}

func initDefaultTxConf(rpc *rpc.Client, f *filler.Filler, sender common.Address, nonce uint64, gasPrice, chainID *big.Int, gasMultiplier float64) *txConf {
	// defaults
	gasCost := uint64(100000)
	to := randomAddress()
	code := RandomCode(f)
	value := big.NewInt(0)
	if len(code) > 128 {
		code = code[:128]
	}
	// Set fields if non-nil
	if rpc != nil {
		client := ethclient.NewClient(rpc)
		var err error
		if gasPrice == nil {
			gasPrice, err = client.SuggestGasPrice(context.Background())
			if err != nil {
				slog.Warn(fmt.Sprintf("Failed to suggest gas price, using default 1: %v", err))
				gasPrice = big.NewInt(1)
			}
		}
		if chainID == nil {
			chainID, err = client.ChainID(context.Background())
			if err != nil {
				slog.Warn(fmt.Sprintf("Failed to fetch chain ID, using default 1: %v", err))
				chainID = big.NewInt(1)
			}
		}
		// Try to estimate gas
		gasCost = EstimateGas(client, ethereum.CallMsg{
			From:      sender,
			To:        &to,
			Gas:       30_000_000,
			GasPrice:  gasPrice,
			GasFeeCap: gasPrice,
			GasTipCap: gasPrice,
			Value:     value,
			Data:      code,
		}, gasCost, gasMultiplier)
	}

	return &txConf{
		rpc:      rpc,
		nonce:    nonce,
		sender:   sender,
		to:       &to,
		value:    value,
		gasLimit: gasCost,
		gasPrice: gasPrice,
		chainID:  chainID,
		code:     code,
	}
}

// RandomValidTx creates a random valid transaction.
// It does not mean that the transaction will succeed, but that it is well-formed.
// If gasPrice is not set, we will try to get it from the rpc
// If chainID is not set, we will try to get it from the rpc
func RandomValidTx(rpc *rpc.Client, f *filler.Filler, sender common.Address, nonce uint64, gasPrice, chainID *big.Int, al bool, gasMultiplier float64) (*types.Transaction, error) {
	conf := initDefaultTxConf(rpc, f, sender, nonce, gasPrice, chainID, gasMultiplier)
	var index int
	if al {
		index = rand.Intn(len(alStrategies))
		return alStrategies[index](conf)
	} else {
		index = rand.Intn(len(noAlStrategies))
		return noAlStrategies[index](conf)
	}
}

func RandomBlobTx(rpc *rpc.Client, f *filler.Filler, sender common.Address, nonce uint64, gasPrice, chainID *big.Int, al bool, gasMultiplier float64) (*types.Transaction, error) {
	conf := initDefaultTxConf(rpc, f, sender, nonce, gasPrice, chainID, gasMultiplier)
	if al {
		return fullAlBlobTx(conf)
	} else {
		return emptyAlBlobTx(conf)
	}
}

func RandomAuthTx(rpc *rpc.Client, f *filler.Filler, sender common.Address, nonce uint64, gasPrice, chainID *big.Int, al bool, aList []types.SetCodeAuthorization, gasMultiplier float64) (*types.Transaction, error) {
	conf := initDefaultTxConf(rpc, f, sender, nonce, gasPrice, chainID, gasMultiplier)
	tx := types.NewTransaction(conf.nonce, *conf.to, conf.value, conf.gasLimit, conf.gasPrice, conf.code)
	var list types.AccessList
	if al {
		l, err := CreateAccessList(conf.rpc, tx, conf.sender)
		if err != nil {
			return nil, err
		}
		list = *l
	}
	tip, feecap, err := getCaps(conf.rpc, conf.gasPrice)
	if err != nil {
		return nil, err
	}
	return New7702Tx(conf.nonce, *conf.to, conf.gasLimit, conf.chainID, tip, feecap, conf.value, conf.code, big.NewInt(1000000), list, aList), nil
}

type txCreationStrategy func(conf *txConf) (*types.Transaction, error)

var noAlStrategies = []txCreationStrategy{
	legacyContractCreation,
	legacyTx,
	emptyAlContractCreation,
	emptyAlTx,
	contractCreation1559,
	tx1559,
}

var alStrategies = append(noAlStrategies, []txCreationStrategy{
	fullAl1559ContractCreation,
	fullAl1559Tx,
	fullAlContractCreation,
	fullAlTx,
}...)

func legacyContractCreation(conf *txConf) (*types.Transaction, error) {
	// Legacy contract creation
	return types.NewContractCreation(conf.nonce, conf.value, conf.gasLimit, conf.gasPrice, conf.code), nil
}

func legacyTx(conf *txConf) (*types.Transaction, error) {
	// Legacy transaction
	return types.NewTransaction(conf.nonce, *conf.to, conf.value, conf.gasLimit, conf.gasPrice, conf.code), nil
}

func emptyAlContractCreation(conf *txConf) (*types.Transaction, error) {
	// AccessList contract creation
	return newALTx(conf.nonce, nil, conf.gasLimit, conf.chainID, conf.gasPrice, conf.value, conf.code, make(types.AccessList, 0)), nil
}

func emptyAlTx(conf *txConf) (*types.Transaction, error) {
	// AccessList transaction
	return newALTx(conf.nonce, conf.to, conf.gasLimit, conf.chainID, conf.gasPrice, conf.value, conf.code, make(types.AccessList, 0)), nil
}

func contractCreation1559(conf *txConf) (*types.Transaction, error) {
	// 1559 contract creation
	tip, feecap, err := getCaps(conf.rpc, conf.gasPrice)
	if err != nil {
		return nil, err
	}
	return new1559Tx(conf.nonce, nil, conf.gasLimit, conf.chainID, tip, feecap, conf.value, conf.code, make(types.AccessList, 0)), nil
}

func tx1559(conf *txConf) (*types.Transaction, error) {
	// 1559 transaction
	tip, feecap, err := getCaps(conf.rpc, conf.gasPrice)
	if err != nil {
		return nil, err
	}
	return new1559Tx(conf.nonce, conf.to, conf.gasLimit, conf.chainID, tip, feecap, conf.value, conf.code, make(types.AccessList, 0)), nil
}

func fullAlContractCreation(conf *txConf) (*types.Transaction, error) {
	// AccessList contract creation with AL
	tx := types.NewContractCreation(conf.nonce, conf.value, conf.gasLimit, conf.gasPrice, conf.code)
	al, err := CreateAccessList(conf.rpc, tx, conf.sender)
	if err != nil {
		return nil, err
	}
	return newALTx(conf.nonce, nil, conf.gasLimit, conf.chainID, conf.gasPrice, conf.value, conf.code, *al), nil
}

func fullAlTx(conf *txConf) (*types.Transaction, error) {
	// AccessList transaction with AL
	tx := types.NewTransaction(conf.nonce, *conf.to, conf.value, conf.gasLimit, conf.gasPrice, conf.code)
	al, err := CreateAccessList(conf.rpc, tx, conf.sender)
	if err != nil {
		return nil, err
	}
	return newALTx(conf.nonce, conf.to, conf.gasLimit, conf.chainID, conf.gasPrice, conf.value, conf.code, *al), nil
}

func fullAl1559ContractCreation(conf *txConf) (*types.Transaction, error) {
	// 1559 contract creation with AL
	tx := types.NewContractCreation(conf.nonce, conf.value, conf.gasLimit, conf.gasPrice, conf.code)
	al, err := CreateAccessList(conf.rpc, tx, conf.sender)
	if err != nil {
		return nil, err
	}
	tip, feecap, err := getCaps(conf.rpc, conf.gasPrice)
	if err != nil {
		return nil, err
	}
	return new1559Tx(conf.nonce, nil, conf.gasLimit, conf.chainID, tip, feecap, conf.value, conf.code, *al), nil
}

func fullAl1559Tx(conf *txConf) (*types.Transaction, error) {
	// 1559 tx with AL
	tx := types.NewTransaction(conf.nonce, *conf.to, conf.value, conf.gasLimit, conf.gasPrice, conf.code)
	al, err := CreateAccessList(conf.rpc, tx, conf.sender)
	if err != nil {
		return nil, err
	}
	tip, feecap, err := getCaps(conf.rpc, conf.gasPrice)
	if err != nil {
		return nil, err
	}
	return new1559Tx(conf.nonce, conf.to, conf.gasLimit, conf.chainID, tip, feecap, conf.value, conf.code, *al), nil
}

func emptyAlBlobTx(conf *txConf) (*types.Transaction, error) {
	// 4844 transaction without AL
	tip, feecap, err := getCaps(conf.rpc, conf.gasPrice)
	if err != nil {
		return nil, err
	}
	data, err := randomBlobData()
	if err != nil {
		return nil, err
	}
	return New4844Tx(conf.nonce, conf.to, conf.gasLimit, conf.chainID, tip, feecap, conf.value, conf.code, big.NewInt(1000000), data, make(types.AccessList, 0)), nil
}

func fullAlBlobTx(conf *txConf) (*types.Transaction, error) {
	// 4844 transaction with AL
	tx := types.NewTransaction(conf.nonce, *conf.to, conf.value, conf.gasLimit, conf.gasPrice, conf.code)
	al, err := CreateAccessList(conf.rpc, tx, conf.sender)
	if err != nil {
		return nil, err
	}
	tip, feecap, err := getCaps(conf.rpc, conf.gasPrice)
	if err != nil {
		return nil, err
	}
	data, err := randomBlobData()
	if err != nil {
		return nil, err
	}
	return New4844Tx(conf.nonce, conf.to, conf.gasLimit, conf.chainID, tip, feecap, conf.value, conf.code, big.NewInt(1000000), data, *al), nil
}

func newALTx(nonce uint64, to *common.Address, gasLimit uint64, chainID, gasPrice, value *big.Int, code []byte, al types.AccessList) *types.Transaction {
	return types.NewTx(&types.AccessListTx{
		ChainID:    chainID,
		Nonce:      nonce,
		GasPrice:   gasPrice,
		Gas:        gasLimit,
		To:         to,
		Value:      value,
		Data:       code,
		AccessList: al,
	})
}

func new1559Tx(nonce uint64, to *common.Address, gasLimit uint64, chainID, tip, feeCap, value *big.Int, code []byte, al types.AccessList) *types.Transaction {
	return types.NewTx(&types.DynamicFeeTx{
		ChainID:    chainID,
		Nonce:      nonce,
		GasTipCap:  tip,
		GasFeeCap:  feeCap,
		Gas:        gasLimit,
		To:         to,
		Value:      value,
		Data:       code,
		AccessList: al,
	})
}

func New4844Tx(nonce uint64, to *common.Address, gasLimit uint64, chainID, tip, feeCap, value *big.Int, code []byte, blobFeeCap *big.Int, blobData []byte, al types.AccessList) *types.Transaction {
	blobs, commits, aggProof, versionedHashes, err := EncodeBlobs(blobData)
	if err != nil {
		panic(err)
	}
	return types.NewTx(&types.BlobTx{
		ChainID:    uint256.MustFromBig(chainID),
		Nonce:      nonce,
		GasTipCap:  uint256.MustFromBig(tip),
		GasFeeCap:  uint256.MustFromBig(feeCap),
		Gas:        gasLimit,
		To:         *to,
		Value:      uint256.MustFromBig(value),
		Data:       code,
		AccessList: al,
		BlobFeeCap: uint256.MustFromBig(blobFeeCap),
		BlobHashes: versionedHashes,
		Sidecar:    &types.BlobTxSidecar{Blobs: blobs, Commitments: commits, Proofs: aggProof},
	})
}

func getCaps(rpc *rpc.Client, defaultGasPrice *big.Int) (*big.Int, *big.Int, error) {
	if rpc == nil {
		tip := new(big.Int).Mul(big.NewInt(1), big.NewInt(params.GWei))
		if defaultGasPrice.Cmp(tip) >= 0 {
			feeCap := new(big.Int).Sub(defaultGasPrice, tip)
			return tip, feeCap, nil
		}
		return big.NewInt(0), defaultGasPrice, nil
	}
	client := ethclient.NewClient(rpc)
	tip, err := client.SuggestGasTipCap(context.Background())
	if err != nil {
		return nil, nil, err
	}
	feeCap, err := client.SuggestGasPrice(context.Background())
	return tip, feeCap, err
}

func encodeBlobs(data []byte) []kzg4844.Blob {
	blobs := []kzg4844.Blob{{}}
	blobIndex := 0
	fieldIndex := -1
	for i := 0; i < len(data); i += 31 {
		fieldIndex++
		if fieldIndex == params.BlobTxFieldElementsPerBlob {
			blobs = append(blobs, kzg4844.Blob{})
			blobIndex++
			fieldIndex = 0
		}
		max := i + 31
		if max > len(data) {
			max = len(data)
		}
		copy(blobs[blobIndex][fieldIndex*32+1:], data[i:max])
	}
	return blobs
}

func EncodeBlobs(data []byte) ([]kzg4844.Blob, []kzg4844.Commitment, []kzg4844.Proof, []common.Hash, error) {
	var (
		blobs           = encodeBlobs(data)
		commits         []kzg4844.Commitment
		proofs          []kzg4844.Proof
		versionedHashes []common.Hash
	)
	for _, blob := range blobs {
		commit, err := kzg4844.BlobToCommitment(&blob)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		commits = append(commits, commit)

		proof, err := kzg4844.ComputeBlobProof(&blob, commit)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		proofs = append(proofs, proof)

		versionedHashes = append(versionedHashes, kZGToVersionedHash(commit))
	}
	return blobs, commits, proofs, versionedHashes, nil
}

var blobCommitmentVersionKZG uint8 = 0x01

// kZGToVersionedHash implements kzg_to_versioned_hash from EIP-4844
func kZGToVersionedHash(kzg kzg4844.Commitment) common.Hash {
	h := sha256.Sum256(kzg[:])
	h[0] = blobCommitmentVersionKZG

	return h
}

func New7702Tx(nonce uint64, to common.Address, gasLimit uint64, chainID, tip, feeCap, value *big.Int, code []byte, blobFeeCap *big.Int, al types.AccessList, auth []types.SetCodeAuthorization) *types.Transaction {
	return types.NewTx(
		&types.SetCodeTx{
			ChainID:    uint256.MustFromBig(chainID),
			Nonce:      nonce,
			To:         to,
			GasTipCap:  uint256.MustFromBig(tip),
			GasFeeCap:  uint256.MustFromBig(feeCap),
			Gas:        gasLimit,
			Value:      uint256.MustFromBig(value),
			Data:       code,
			AuthList:   auth,
			AccessList: al,
		},
	)
}
