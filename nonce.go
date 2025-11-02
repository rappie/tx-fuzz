package txfuzz

import (
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// NonceManager provides thread-safe local nonce tracking for accounts.
// It caches nonces to reduce RPC calls while maintaining correctness.
type NonceManager struct {
	mu      sync.Mutex
	nonces  map[common.Address]uint64
	enabled bool
}

// nonceManager is the package-level global instance
var nonceManager *NonceManager

// SetNonceManager initializes or disables the global nonce manager.
// If enabled is true, creates a new manager for local nonce tracking.
// If enabled is false, disables local tracking (all GetPendingNonce calls query RPC).
func SetNonceManager(enabled bool) {
	if enabled {
		nonceManager = &NonceManager{
			nonces:  make(map[common.Address]uint64),
			enabled: true,
		}
	} else {
		nonceManager = nil
	}
}

// Get retrieves the cached nonce for an address.
// Returns (nonce, true) if cached, (0, false) if not found.
// Thread-safe.
func (nm *NonceManager) Get(addr common.Address) (uint64, bool) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nonce, exists := nm.nonces[addr]
	if exists {
		// Increment cached value for next call
		nm.nonces[addr] = nonce + 1
	}
	return nonce, exists
}

// Set stores a nonce for an address in the cache.
// Thread-safe.
func (nm *NonceManager) Set(addr common.Address, nonce uint64) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.nonces[addr] = nonce
}
