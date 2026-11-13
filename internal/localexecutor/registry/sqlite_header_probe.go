package registry

// registryHeaderProbeResult is internal descriptor metadata, never a handle,
// permission or a public diagnostic. No raw descriptor number or error escapes.
type registryHeaderProbeResult struct {
	known  bool
	valid  bool
	closed bool
}
