package idv

import "errors"

// ErrSessionNotFound is returned by Provider.GetVerification when the
// provider has no record of the requested ProviderSessionID. The
// service layer maps this to a 404 to the client.
var ErrSessionNotFound = errors.New("idv: provider session not found")

// ErrProviderUnavailable indicates the provider could not be reached
// (network failure, upstream 5xx, expired credentials). Distinct from
// "no such session" so the service layer can choose to surface a
// retryable error to the client rather than a 404.
var ErrProviderUnavailable = errors.New("idv: provider unavailable")
