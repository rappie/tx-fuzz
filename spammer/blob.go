package spammer

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/MariusVanDerWijden/FuzzyVM/filler"
	txfuzz "github.com/MariusVanDerWijden/tx-fuzz"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func SendBlobTransactions(config *Config, key *ecdsa.PrivateKey, f *filler.Filler) error {
	backend := ethclient.NewClient(config.backend)
	sender := crypto.PubkeyToAddress(key.PublicKey)
	chainID := txfuzz.GetChainID(backend)

	var lastTx *types.Transaction
	for i := uint64(0); i < config.N; i++ {
		nonce, err := txfuzz.GetPendingNonce(context.Background(), backend, sender)
		if err != nil {
			return err
		}
		tx, originalGasEstimate, gasMultiplier, err := txfuzz.RandomBlobTx(config.backend, f, sender, nonce, nil, nil, config.accessList, config.GasMultiplier)
		if err != nil {
			config.Logger.Warn(fmt.Sprintf("Failed to create valid blob transaction (nonce=%d): %v", nonce, err))
			return err
		}
		signedTx, err := types.SignTx(tx, types.NewCancunSigner(chainID), key)
		if err != nil {
			return err
		}
		if err := txfuzz.SendTransaction(context.Background(), backend, signedTx, originalGasEstimate, gasMultiplier); err != nil {
			return err
		}
		lastTx = signedTx
		time.Sleep(time.Duration(config.TxDelay) * time.Millisecond)
	}

	if lastTx != nil {
		ctx, cancel := context.WithTimeout(context.Background(), TX_TIMEOUT)
		defer cancel()
		if _, err := bind.WaitMined(ctx, backend, lastTx); err != nil {
			config.Logger.Warn(fmt.Sprintf("Waiting for blob transactions to be mined failed: %v", err))

			// Save transaction that timed out waiting to be mined
			txfuzz.SaveFailedTransaction(context.Background(), backend, lastTx, err, 0, 0)
		}
	}
	return nil
}
