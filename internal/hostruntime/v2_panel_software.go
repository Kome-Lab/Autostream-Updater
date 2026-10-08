package hostruntime

import (
	"errors"
	"time"
)

// BindSoftwareUpdateClaim updates only the internal policy projection. The
// original lease/command/authorization and their canonical digest stay intact.
func (c *V2PanelClient) BindSoftwareUpdateClaim(job UpdateJob) error {
	if c == nil || !isV2SoftwareJob(job) || job.SoftwareUpdate == nil || job.SoftwareUpdate.Validate() != nil ||
		job.PolicyRevision != job.SoftwareUpdate.ProjectionRevision {
		return errors.New("software lease policy binding is invalid")
	}
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	if c.lease == nil || !sameSoftwareJobIdentity(c.lease.job, job) || c.lease.job.CommandID != job.CommandID ||
		c.lease.job.LeaseGeneration != job.LeaseGeneration || c.lease.job.LeaseExpiresAt != job.LeaseExpiresAt ||
		c.lease.job.SoftwareUpdate == nil || c.lease.job.SoftwareUpdate.ConfigRevision != job.SoftwareUpdate.ConfigRevision ||
		c.lease.job.SoftwareUpdate.CommandSHA256 != job.SoftwareUpdate.CommandSHA256 {
		return errors.New("software lease intent changed during policy binding")
	}
	if saved := c.lease.job.SoftwareUpdate; saved.ProjectionRevision != 0 && *saved != *job.SoftwareUpdate {
		return errors.New("software lease policy projection cannot be replaced")
	}
	c.lease.job = cloneV2PanelJob(job)
	return nil
}

func (c *V2PanelClient) HasActiveLease(job UpdateJob) bool {
	if c == nil {
		return false
	}
	c.leaseMu.Lock()
	defer c.leaseMu.Unlock()
	return c.lease != nil && c.lease.job.ID == job.ID && c.lease.job.CommandID == job.CommandID &&
		c.lease.job.LeaseGeneration == job.LeaseGeneration && c.lease.lease.LeaseExpiresAt.After(c.now().Add(time.Second))
}
