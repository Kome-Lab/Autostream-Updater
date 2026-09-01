package hostruntime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"testing"
)

type bootstrapTarEntry struct {
	name string
	body []byte
}

type bootstrapProvenanceVerifierFunc func(
	context.Context,
	ReleaseDownloader,
	string,
	string,
	string,
) error

func (f bootstrapProvenanceVerifierFunc) Verify(
	ctx context.Context,
	downloader ReleaseDownloader,
	version string,
	manifestDigest string,
	tagCommit string,
) error {
	return f(ctx, downloader, version, manifestDigest, tagCommit)
}

func makeBootstrapTarGz(t *testing.T, entries []bootstrapTarEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	gzipWriter := gzip.NewWriter(&out)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{
			Name: entry.name, Typeflag: tar.TypeReg, Mode: 0o755,
			Size: int64(len(entry.body)),
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
