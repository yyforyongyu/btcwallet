// Copyright (c) 2025 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package waddrmgr

import "fmt"

// AccountName returns the account name for a given account number.
func AccountName(account uint32) string {
	return fmt.Sprintf("account-%d", account)
}
