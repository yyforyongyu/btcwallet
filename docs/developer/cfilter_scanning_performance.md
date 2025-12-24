# CFilter Scanning Performance Analysis

This document details the performance characteristics of the `scanBatchWithCFilters` algorithm used in `btcwallet` for synchronizing the wallet using Compact Filters (BIP 157/158).

## Overview

The algorithm employs an "Optimistic Batch Fetching with In-Place Resume" strategy. It attempts to fetch all relevant data in parallel batches but falls back to a re-matching loop if processing a block reveals new information (horizon expansion) that invalidates the initial filter check.

## Scenarios

### 1. Best Case (No Matches)

**Scenario:** A batch of blocks where **none** contain relevant transactions (or at least none that trigger a horizon expansion). This is typical for a wallet that receives funds infrequently.

**Execution Flow:**
1.  **Headers/Filters:** Fetched in 2 parallel-ish RPC batches. (Fast).
2.  **Initial Match:** 0 matches found.
3.  **Fetch Blocks:** 0 blocks fetched.
4.  **Processing Loop:** Iterates through the batch. `blockMap` is empty. Loop continues immediately.
5.  **Resume Logic:** Never triggered (no blocks processed -> no expansion).

**Performance:**
*   **RPCs:** 2 (GetHeaders, GetCFilters).
*   **Bandwidth:** Minimal (Headers + Filters only).
*   **CPU:** `O(N * M)` where N=BatchSize, M=WatchlistSize. (Filter matching only).
*   **Latency:** Dominated by 1 RTT for filters. **Extremely Fast.**

### 2. Normal Case (Matches without Expansion)

**Scenario:** One or more blocks contain relevant transactions, but they are to **already known/used addresses** (no horizon expansion). This occurs when receiving funds to an old address or within the existing gap limit.

**Execution Flow:**
1.  **Initial Match:** Finds K matches.
2.  **Fetch Blocks:** Fetches K blocks in 1 batch RPC.
3.  **Processing Loop:** Processes K blocks.
4.  **Resume Logic:** Never triggered (ProcessBlock returns `Expanded=false`).

**Performance:**
*   **RPCs:** 3 (Headers, Filters, Blocks).
*   **Bandwidth:** Headers + Filters + K Blocks.
*   **CPU:** Matching + Processing K blocks.
*   **Latency:** Very Fast (Parallel fetch of all needed blocks).

### 3. Worst Case (Sequential Expansion)

**Scenario:** **Every single block** in the batch contains a transaction that triggers a **Horizon Expansion**. This typically happens during an initial wallet restore where the user received funds in a tight sequence of new addresses (Block 1 uses Addr 1, Block 2 uses Addr 2, etc.), and the Gap Limit is small.

**Execution Flow:**
1.  **Initial Match:** Matches Block 0 (Addr 0). Misses Block 1 (Addr 20) because Addr 20 isn't in the watchlist yet.
2.  **Processing Block 0:** Finds Addr 0. **Expands.**
3.  **Resume Logic (Loop 0):** Re-matches Filters 1..N. Finds Block 1 (Addr 20). Fetches Block 1.
4.  **Processing Block 1:** Finds Addr 20. **Expands.**
5.  **Resume Logic (Loop 1):** Re-matches Filters 2..N. Finds Block 2. Fetches Block 2.
6.  ... (Repeats for every block)

**Performance:**
*   **RPCs:** 2 (Headers/Filters) + **N (Blocks)**.
    *   We are forced to fetch blocks serially because we only discover the need for Block `i` after processing Block `i-1`.
*   **CPU:** **O(N^2 * M)**.
    *   We match filters 0..N, then 1..N, then 2..N.
    *   Sum of 1..N is N^2/2. With N=2000, this results in ~2,000,000 passes over the watchlist.
*   **Latency:** **Very Slow.** The process degrades to serial block-by-block processing, waiting for a network round-trip for *each* block.

## Summary

*   **Best/Normal:** 2-3 RPCs, parallel I/O, near-instant.
*   **Worst:** N RPCs, serial I/O, slow (comparable to syncing a full node without lookahead).

The algorithm is optimized for the **Best** and **Normal** cases, which represent 99% of wallet operation. The "Worst Case" is handled correctly (safely) but sacrifices performance for correctness in edge cases.
