package hostruntime

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func (d ReleaseDownloader) validateUpdaterReleaseAssetURL(
	asset immutableReleaseAsset,
	base string,
) error {
	if asset.ID <= 0 {
		return fmt.Errorf("GitHub returned an invalid id for release asset %q", asset.Name)
	}
	if err := d.validateAssetURL(asset.URL, base); err != nil {
		return err
	}
	assetURL, assetErr := url.Parse(asset.URL)
	baseURL, baseErr := url.Parse(base)
	if assetErr != nil || baseErr != nil {
		return errors.New("GitHub returned an invalid release asset API URL")
	}
	expectedPath := strings.TrimRight(baseURL.EscapedPath(), "/") + fmt.Sprintf(
		"/repos/%s/%s/releases/assets/%d",
		url.PathEscape(updaterReleaseRepository.Owner),
		url.PathEscape(updaterReleaseRepository.Repo),
		asset.ID,
	)
	if assetURL.EscapedPath() != expectedPath ||
		assetURL.RawQuery != "" ||
		assetURL.Fragment != "" ||
		assetURL.User != nil {
		return fmt.Errorf("release asset %q does not use its canonical GitHub asset API URL", asset.Name)
	}
	return nil
}

func (d ReleaseDownloader) resolveUpdaterReleaseTagCommit(
	ctx context.Context,
	base string,
	version string,
) (string, error) {
	endpoint := fmt.Sprintf(
		"%s/repos/%s/%s/git/ref/tags/%s",
		base,
		url.PathEscape(updaterReleaseRepository.Owner),
		url.PathEscape(updaterReleaseRepository.Repo),
		url.PathEscape(version),
	)
	var ref gitRef
	if err := d.getJSON(ctx, endpoint, &ref); err != nil {
		return "", fmt.Errorf("resolve updater release tag: %w", err)
	}
	object := ref.Object
	seenTags := make(map[string]struct{}, 8)
	for depth := 0; object.Type == "tag"; depth++ {
		if depth >= 8 {
			return "", errors.New("updater release tag exceeds the dereference limit")
		}
		if !updaterReleaseCommitPattern.MatchString(object.SHA) {
			return "", errors.New("updater release tag object is invalid")
		}
		if _, seen := seenTags[object.SHA]; seen {
			return "", errors.New("updater release tag contains a cycle")
		}
		seenTags[object.SHA] = struct{}{}
		tagEndpoint := fmt.Sprintf(
			"%s/repos/%s/%s/git/tags/%s",
			base,
			url.PathEscape(updaterReleaseRepository.Owner),
			url.PathEscape(updaterReleaseRepository.Repo),
			url.PathEscape(object.SHA),
		)
		var tag gitTag
		if err := d.getJSON(ctx, tagEndpoint, &tag); err != nil {
			return "", fmt.Errorf("dereference updater release tag: %w", err)
		}
		object = tag.Object
	}
	if object.Type != "commit" || !updaterReleaseCommitPattern.MatchString(object.SHA) {
		return "", errors.New("updater release tag does not resolve to a valid commit")
	}
	return object.SHA, nil
}

func (d ReleaseDownloader) downloadUpdaterReleaseAsset(
	ctx context.Context,
	asset immutableReleaseAsset,
	destination string,
	maxBytes int64,
) (string, error) {
	digest, err := d.downloadFile(ctx, asset.URL, destination, maxBytes)
	if err != nil {
		return "", err
	}
	if asset.Digest != "sha256:"+digest {
		_ = os.Remove(destination)
		return "", fmt.Errorf("release asset %q does not match the GitHub API digest", asset.Name)
	}
	return digest, nil
}
