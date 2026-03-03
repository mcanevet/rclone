package protonapi

// user.go contains ProtonClient methods for user, address, key-salt, and
// SRP-moduli endpoints — all of which live under /core/v4 or /auth/v4 and
// are not specific to any single Proton product.

import (
	"context"
	"fmt"
)

// GetUser returns the current user.
func (c *ProtonClient) GetUser(ctx context.Context) (*User, error) {
	var resp UserResp
	if err := c.CallJSON(ctx, "GET", "/core/v4/users", nil, &resp, false); err != nil {
		return nil, fmt.Errorf("getUser: %w", err)
	}
	return &resp.User, nil
}

// GetAddresses returns the current user's addresses.
func (c *ProtonClient) GetAddresses(ctx context.Context) ([]Address, error) {
	var resp AddressesResp
	if err := c.CallJSON(ctx, "GET", "/core/v4/addresses", nil, &resp, false); err != nil {
		return nil, fmt.Errorf("getAddresses: %w", err)
	}
	return resp.Addresses, nil
}

// GetKeySalts returns the key salts for the current user.
func (c *ProtonClient) GetKeySalts(ctx context.Context) ([]KeySalt, error) {
	var resp KeySaltsResp
	if err := c.CallJSON(ctx, "GET", "/core/v4/keys/salts", nil, &resp, false); err != nil {
		return nil, fmt.Errorf("getKeySalts: %w", err)
	}
	return resp.KeySalts, nil
}

// GetSRPModuli fetches a fresh SRP modulus from the Proton API.
func (c *ProtonClient) GetSRPModuli(ctx context.Context) (*SRPModuliResp, error) {
	var resp SRPModuliResp
	if err := c.CallJSON(ctx, "GET", "/auth/v4/modulus", nil, &resp, false); err != nil {
		return nil, fmt.Errorf("getSRPModuli: %w", err)
	}
	return &resp, nil
}
