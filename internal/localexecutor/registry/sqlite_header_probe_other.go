//go:build !linux

package registry

import "os"

// No live-descriptor guarantee is selected for other platforms. Unavailable
// metadata remains Unknown instead of inferring FD validity from bookkeeping.
func registryProbeHeader(_ int, _ os.FileInfo) registryHeaderProbeResult {
	return registryHeaderProbeResult{}
}
