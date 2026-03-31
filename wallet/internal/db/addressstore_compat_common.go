package db

import (
	"errors"
	"fmt"
)

var errAddressManagerCompatNotImplemented = errors.New(
	"address-manager compatibility method not implemented",
)

// AddressManagerCompatNotImplemented returns the shared placeholder error used
// by SQL backends for transitional address-manager compatibility methods.
func AddressManagerCompatNotImplemented(method string) error {
	return fmt.Errorf("%s: %w", method, errAddressManagerCompatNotImplemented)
}
