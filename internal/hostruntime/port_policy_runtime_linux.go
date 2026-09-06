//go:build linux

package hostruntime

import "time"

func (r *linuxSystemdPortRuntime) PortPolicyStore() portPolicyStore { return r.policyStore }
func (r *linuxSystemdPortRuntime) PortNow() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}
func (r *linuxDockerPortRuntime) PortPolicyStore() portPolicyStore { return r.policyStore }
func (r *linuxDockerPortRuntime) PortNow() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}
func (r *linuxDockerPortRuntime) PortCheckpoint() (dockerPortMappingCheckpoint, error) {
	return checkpointDockerPortMapping(r.adapter.PortEnvFile, r.requireRootOwned)
}
