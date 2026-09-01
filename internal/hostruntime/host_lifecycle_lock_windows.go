//go:build windows

package hostruntime

import "sync"

var windowsHostLifecycleLock sync.Mutex

func acquireHostLifecycleLock() (func(), error) {
	windowsHostLifecycleLock.Lock()
	return windowsHostLifecycleLock.Unlock, nil
}
