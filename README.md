# libwallet

[![Build Status](https://github.com/decred/libwallet/workflows/Build%20and%20Test/badge.svg)](https://github.com/decred/libwallet/actions)
[![Blue Oak Model License 1.0.0](https://img.shields.io/badge/license-Blue_Oak-007788.svg)](https://blueoakcouncil.org/license/1.0.0)
[![Doc](https://img.shields.io/badge/doc-reference-blue.svg)](https://pkg.go.dev/github.com/decred/libwallet)

libwallet is a Go library for dcr. It includes features for creating new wallets,
restoring wallets from seed and synchronizing using SPV (Simple Payment Verification).
SPV is a simple, lightweight but privacy-preserving means of fetching blockchain
information that is relevant to a wallet.
