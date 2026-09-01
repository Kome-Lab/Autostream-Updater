package controlplane

import "testing"

func TestV2CommandBoundaryFailsClosed(t *testing.T) {
	if ErrV2CommandContractUnavailable == nil || ErrV2CommandContractUnavailable.Error() == "" {
		t.Fatal("v2 command boundary must expose a stable fail-closed error")
	}
}
