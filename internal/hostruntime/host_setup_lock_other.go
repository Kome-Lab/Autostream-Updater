//go:build !linux

package hostruntime

import "errors"

func AcquireHostRuntimeSetupLock() (func(), error) {
	return func() {}, errors.New("Host runtime setup lock is supported only on Linux")
}

func AcquireHostRuntimeSetupAndLifecycleLocks() (func(), error) {
	return func() {}, errors.New("Host runtime setup and lifecycle locks are supported only on Linux")
}

func AcquireHostConfigurationTargetLocks() (func(), error) {
	return func() {}, errors.New("Host configuration target locks are supported only on Linux")
}
