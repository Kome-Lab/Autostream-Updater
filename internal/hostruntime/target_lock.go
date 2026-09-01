package hostruntime

import (
	"os"
	"path/filepath"
)

func acquireTargetLock(target Target) (func(), error) {
	dir := privilegedLockDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return func() {}, err
	}
	_ = os.Chmod(dir, 0o700)
	key := target.TargetID
	if target.DeploymentMode == ModeDocker && target.Docker != nil {
		key = filepath.Clean(target.Docker.ProjectDir) + "\x00" + target.Docker.ComposeProject
	} else if target.DeploymentMode == ModeSystemd && target.Systemd != nil {
		key = target.Systemd.Unit
	}
	return lockFile(filepath.Join(dir, ".autostream-updater-"+shortID(key)+".lock"))
}
