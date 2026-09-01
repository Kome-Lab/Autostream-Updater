package hostruntime

import "context"

// ReleaseArtifactDownloader is the narrow, outbound-only artifact boundary
// used by the updater agent. Implementations verify immutable release metadata
// before any root-owned mutation is requested from the Local Executor.
type ReleaseArtifactDownloader interface {
	Download(context.Context, string, string, string, string) (DownloadedArtifact, error)
	ResolveDockerReleaseForArch(context.Context, string, string, string, string, string, string) (ResolvedDockerRelease, error)
}
