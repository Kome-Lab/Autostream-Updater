package version

// These values are overridden by release and Docker builds with -ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func Current() string {
	if Version == "" {
		return "dev"
	}
	return Version
}
