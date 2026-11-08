# internal/qr

QR encoder copied from [rsc.io/qr](https://github.com/rsc/qr) (commit `b6857d426aa506d5bf7efb8f73928d72bcf4e73d`), BSD-3-Clause, see `LICENSE` in this folder. Only `qr.go`, `coding/` and `gf256/` are kept; the import paths point here, `gofmt` was applied. Copied so the program needs no extra module (the vault code stays small and auditable).
