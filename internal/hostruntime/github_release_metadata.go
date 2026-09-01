package hostruntime

import "regexp"

var immutableReleaseAssetDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var updaterReleaseCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// The provenance verifier is pinned to the independent updater repository.
var updaterReleaseRepository = RepoSpec{
	Owner: "Kome-Lab",
	Repo:  "Autostream-Updater",
}

type immutableReleaseAsset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Digest string `json:"digest"`
	State  string `json:"state"`
}

type updaterReleaseGitHubRelease struct {
	TagName   string                  `json:"tag_name"`
	Draft     bool                    `json:"draft"`
	Immutable bool                    `json:"immutable"`
	Assets    []immutableReleaseAsset `json:"assets"`
}

type gitObject struct {
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

type gitRef struct {
	Object gitObject `json:"object"`
}

type gitTag struct {
	Object gitObject `json:"object"`
}

type resolvedImmutableRelease struct {
	Archive          immutableReleaseAsset
	ArchiveChecksum  immutableReleaseAsset
	Manifest         immutableReleaseAsset
	ManifestChecksum immutableReleaseAsset
	TagCommit        string
}
