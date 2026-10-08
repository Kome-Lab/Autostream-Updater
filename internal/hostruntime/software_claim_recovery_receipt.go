package hostruntime

import (
	"context"
	"errors"
	"time"
)

// A receipt retains the actual authenticated clear request, not a lease or a
// guess derived from the adapter's synthetic canceled cursor. A terminal clear
// alone does not identify the central job's terminal status or error code.
type softwareClaimRecoveryTerminalClearReceipt struct {
	ClaimRequest   HostPullClaimRequest             `json:"claim_request"`
	RootNoMutation SoftwareClaimRecoveryProof       `json:"root_no_mutation"`
	ObservedAt     time.Time                        `json:"observed_at"`
	AcceptedResult *softwareClaimRecoveryWireResult `json:"accepted_result,omitempty"`
}

type softwareClaimRecoveryWireResult struct {
	Status string `json:"status"`
	Code   string `json:"code"`
}

func (r softwareClaimRecoveryTerminalClearReceipt) validate(intent softwareClaimRecoveryIntent) error {
	claim := r.ClaimRequest
	if claim.ActiveJobID != intent.Original.JobID || claim.UpdaterID != intent.UpdaterID || claim.HostID != intent.HostID ||
		claim.Fence != intent.Original.OwnershipEpoch || claim.LeaseGeneration < 1 ||
		(uint64(claim.LeaseGeneration) != intent.Request.LeaseGeneration && uint64(claim.LeaseGeneration) != intent.Request.LeaseGeneration+1) ||
		!softwareClaimRecoveryProofMatchesIntent(r.RootNoMutation, intent) || r.ObservedAt.IsZero() ||
		r.ObservedAt.Before(r.RootNoMutation.ObservedAt) ||
		(r.AcceptedResult != nil && (r.AcceptedResult.Status != "failed" || r.AcceptedResult.Code != "execution_failed")) {
		return errors.New("software claim recovery terminal clear receipt is invalid")
	}
	return nil
}

func softwareClaimRecoveryProofMatchesIntent(proof SoftwareClaimRecoveryProof, intent softwareClaimRecoveryIntent) bool {
	return proof.Validate() == nil && proof.RequestSHA256 == intent.Request.sha256() &&
		proof.UpdaterID == intent.UpdaterID && proof.HostID == intent.HostID &&
		proof.SourcePolicyRevision == intent.SourcePolicyRevision && proof.ProjectionRevision == intent.ProjectionRevision &&
		proof.ExecutorPolicyRevision == intent.ExecutorPolicyRevision && proof.ExecutorPolicySHA256 == intent.ExecutorPolicySHA256 &&
		proof.OwnershipEpoch == intent.Original.OwnershipEpoch && proof.PriorSettledRawSHA256 == intent.PreviousSettledRawSHA256
}

func (a *HostPullAgent) settleSoftwareClaimRecovery(ctx context.Context, binding HostAgentBinding, policy HostAgentPolicy,
	intent softwareClaimRecoveryIntent, terminal *UpdateJob, clearRequest HostPullClaimRequest, failedReportAccepted bool) error {
	anchor := UpdateJob{ProtocolVersion: 2, ID: intent.Original.JobID, AgentServiceID: intent.UpdaterID}
	if terminal == nil || validateV2RecoveryClear(anchor, *terminal, intent.UpdaterID) != nil {
		return errors.New("software claim recovery clear does not prove the exact requested job")
	}
	proof, err := a.inspectSoftwareClaimRecovery(ctx, intent.Request, binding, policy)
	if err != nil {
		return err
	}
	receipt := softwareClaimRecoveryTerminalClearReceipt{ClaimRequest: clearRequest, RootNoMutation: proof, ObservedAt: time.Now().UTC()}
	if failedReportAccepted {
		receipt.AcceptedResult = &softwareClaimRecoveryWireResult{Status: "failed", Code: "execution_failed"}
	}
	if receipt.validate(intent) != nil {
		return errors.New("software claim recovery actual terminal clear or root proof disagrees with the intent")
	}
	if a.Journal == nil || a.Journal.ActivePlan() != nil || a.Journal.ActivePortPlan() != nil {
		return errors.New("software claim recovery cannot clear a journal with execution state")
	}
	active := a.Journal.Active()
	if active != nil && !softwareClaimRecoveryCursorMatches(intent, *active) {
		return errors.New("software claim recovery cannot clear another active cursor")
	}
	pending := a.Journal.Pending()
	data, err := readSoftwareClaimRecoveryJournal(a.StateDir)
	if err != nil || !softwareClaimRecoveryPendingAllowed(data) || len(data.Pending) != len(pending) {
		return errors.New("software claim recovery cannot clear unrelated or terminal pending reports")
	}
	if len(pending) != 0 {
		if err := a.Journal.DropJobReports(intent.Original.JobID); err != nil {
			return err
		}
	}
	if err := a.Journal.ClearActive(); err != nil {
		return err
	}
	previous := softwareClaimRecoveryIntentSHA256(intent)
	intent.Settled, intent.SettledAt = true, receipt.ObservedAt
	if intent.SchemaVersion == 2 {
		intent.TerminalClear = &receipt
	}
	return saveSoftwareClaimRecoveryIntent(a.StateDir, previous, intent)
}

// The ordinary recovery loop supplies the exact request whose authenticated
// response cleared this same job. A clear-only recovery records no public code.
func (a *HostPullAgent) CompleteSoftwareClaimRecoveryClear(ctx context.Context, binding HostAgentBinding, policy HostAgentPolicy,
	terminal *UpdateJob, clearRequest HostPullClaimRequest) error {
	intent, exists, err := loadSoftwareClaimRecoveryIntent(a.StateDir, managedSnapshotOwnedByCurrentUser)
	if err != nil || !exists || intent.Settled {
		if err != nil {
			return err
		}
		return errors.New("software claim recovery clear has no durable intent")
	}
	return a.settleSoftwareClaimRecovery(ctx, binding, policy, intent, terminal, clearRequest, false)
}
