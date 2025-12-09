package spammer

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/rand"
	"time"

	"github.com/MariusVanDerWijden/FuzzyVM/filler"
	txfuzz "github.com/MariusVanDerWijden/tx-fuzz"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/holiman/uint256"
)

func Send7702Transactions(config *Config, key *ecdsa.PrivateKey) error {
	backend := ethclient.NewClient(config.backend)
	sender := crypto.PubkeyToAddress(key.PublicKey)
	chainID := txfuzz.GetChainID(backend)

	var deployedContracts []common.Address
	var lastTx *types.Transaction

	for i := uint64(0); i < config.N; i++ {
		// Create fresh filler with context for each transaction
		f := CreateFiller(config)
		f.Ctx = &filler.Context{
			InterestingAddresses: append(
				[]common.Address{sender},
				deployedContracts...,
			),
		}

		nonce, err := txfuzz.GetPendingNonce(context.Background(), backend, sender)
		if err != nil {
			return err
		}

		authorizer := config.keys[rand.Intn(len(config.keys))]
		nonceAuth, err := txfuzz.GetPendingNonce(context.Background(), backend, crypto.PubkeyToAddress(authorizer.PublicKey))
		if err != nil {
			return err
		}

		auth := types.SetCodeAuthorization{
			ChainID: *uint256.MustFromBig(chainID),
			Address: sender,
			Nonce:   nonceAuth,
		}

		auth, err = types.SignSetCode(authorizer, auth)
		if err != nil {
			return err
		}

		tx, originalGasEstimate, gasMultiplier, err := txfuzz.RandomAuthTx(config.backend, f, sender, nonce, nil, nil, config.accessList, []types.SetCodeAuthorization{auth}, config.GasMultiplier)
		if err != nil {
			config.Logger.Warn(fmt.Sprintf("Failed to create valid EIP-7702 transaction (nonce=%d): %v", nonce, err))
			return err
		}

		// Track contract deployments
		if tx.To() == nil {
			contractAddr := crypto.CreateAddress(sender, nonce)
			deployedContracts = append(deployedContracts, contractAddr)
			config.Logger.Debug(fmt.Sprintf("Tracking deployed contract: %s", contractAddr.Hex()))
		}

		signedTx, err := types.SignTx(tx, types.NewPragueSigner(chainID), key)
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
			config.Logger.Warn(fmt.Sprintf("Waiting for EIP-7702 transactions to be mined failed: %v", err))

			// Save transaction that timed out waiting to be mined
			txfuzz.SaveFailedTransaction(context.Background(), backend, lastTx, err, 0, 0)
		}
	}
	return nil
}
