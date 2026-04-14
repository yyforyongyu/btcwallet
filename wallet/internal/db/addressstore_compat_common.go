package db

import (
	"errors"
	"fmt"
)

var errAddressManagerCompatNotImplemented = errors.New(
	"address-manager compatibility method not implemented",
)

var errAccountManagerCompatNotImplemented = errors.New(
	"account-manager compatibility method not implemented",
)

// AddressManagerCompatNotImplemented returns the shared placeholder error used
// by SQL backends for transitional address-manager compatibility methods.
func AddressManagerCompatNotImplemented(method string) error {
	return fmt.Errorf("%s: %w", method, errAddressManagerCompatNotImplemented)
}

// AccountManagerCompatNotImplemented returns the shared placeholder error used
// by backends for transitional account-manager compatibility methods.
func AccountManagerCompatNotImplemented(method string) error {
	return fmt.Errorf("%s: %w", method, errAccountManagerCompatNotImplemented)
}
