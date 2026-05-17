// Package file implements the default file-backed [jwt.Signer] for the
// identity service. Private RSA keys live in a JSON document on disk;
// the running process reads it at startup and on SIGHUP, with each
// entry carrying its own not_before / expires_at envelope so multiple
// generations of keys can coexist during rotation.
//
// The on-disk format is intentionally human-editable so a small
// deployer can rotate keys by writing one extra entry and sending
// SIGHUP, without bringing the process down. KMS-backed deployments
// use [pkg/jwt/kmsaws] instead.
package file
