package controlplane

import "errors"

// ErrV2CommandContractUnavailable is returned while the Contracts authority
// lacks the typed desired mutation payload needed by the host executor. The
// Updater must fail closed instead of decoding a consumer-local wire shape.
var ErrV2CommandContractUnavailable = errors.New("v2 updater command contract is not executable")
