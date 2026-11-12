//go:build linux

package registry

import (
	"os"
	"syscall"
)

// registryProbeHeader observes an already owned descriptor without an os.File
// reference. File.Stat's runtime incref/decref could finish a concurrent Close
// after lease handoff on blocking files. Raw Fstat cannot schedule such a later
// Go descriptor Close. The caller performs one owner-frame recheck and does not
// call this after confirmed header release; FD reuse is not an identity proof.
func registryProbeHeader(fd int, identity os.FileInfo) registryHeaderProbeResult {
	if fd < 0 || identity == nil {
		return registryHeaderProbeResult{}
	}
	expected, ok := identity.Sys().(*syscall.Stat_t)
	if !ok || expected == nil {
		return registryHeaderProbeResult{}
	}
	var observed syscall.Stat_t
	err := syscall.Fstat(fd, &observed)
	if err == syscall.EBADF {
		return registryHeaderProbeResult{known: true, closed: true}
	}
	if err != nil {
		return registryHeaderProbeResult{}
	}
	return registryHeaderProbeResult{
		known: true,
		valid: observed.Mode&syscall.S_IFMT == syscall.S_IFREG &&
			observed.Dev == expected.Dev && observed.Ino == expected.Ino,
	}
}
