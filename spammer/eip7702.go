package spammer

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"math/rand"
	"time"

	"github.com/MariusVanDerWijden/FuzzyVM/filler"
	txfuzz "github.com/MariusVanDerWijden/tx-fuzz"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/holiman/uint256"
)

func Send7702Transactions(config *Config, key *ecdsa.PrivateKey, f *filler.Filler) error {
	backend := ethclient.NewClient(config.backend)
	sender := crypto.PubkeyToAddress(key.PublicKey)
	chainID, err := backend.ChainID(context.Background())
	if err != nil {
		config.Logger.Warn("failed to get chain ID, using default", "error", err, "default_chain_id", "0x01000666")
		chainID = big.NewInt(0x01000666)
	}

	var lastTx *types.Transaction
	for i := uint64(0); i < config.N; i++ {
		nonce, err := backend.NonceAt(context.Background(), sender, big.NewInt(-1))
		if err != nil {
			return err
		}

		authorizer := config.keys[rand.Intn(len(config.keys))]
		nonceAuth, err := backend.NonceAt(context.Background(), crypto.PubkeyToAddress(authorizer.PublicKey), big.NewInt(-1))
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

		tx, err := txfuzz.RandomAuthTx(config.backend, f, sender, nonce, nil, nil, config.accessList, []types.SetCodeAuthorization{auth})
		if err != nil {
			config.Logger.Warn("failed to create valid EIP-7702 transaction", "error", err, "nonce", nonce)
			return err
		}
		signedTx, err := types.SignTx(tx, types.NewPragueSigner(chainID), key)
		if err != nil {
			return err
		}
		if err := backend.SendTransaction(context.Background(), signedTx); err != nil {
			config.Logger.Warn("failed to submit EIP-7702 transaction", "error", err)
			return err
		}
		lastTx = signedTx
		time.Sleep(10 * time.Millisecond)
	}
	if lastTx != nil {
		ctx, cancel := context.WithTimeout(context.Background(), TX_TIMEOUT)
		defer cancel()
		if _, err := bind.WaitMined(ctx, backend, lastTx); err != nil {
			config.Logger.Warn("waiting for EIP-7702 transactions to be mined failed", "error", err)
		}
	}
	return nil
}
