package sdk

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLogInventoryFindsEveryProcessAndSkipsSymlinks pins two things that the
// naive implementation gets wrong: logs live under one subdirectory per
// process, and glog puts a <program>.<SEVERITY> SYMLINK beside every real file
// (glog/glog_file.go:124-140), which would otherwise be counted twice.
func TestLogInventoryFindsEveryProcessAndSkipsSymlinks(t *testing.T) {
	root := t.TempDir()

	appDir := filepath.Join(root, "app")
	extensionDir := filepath.Join(root, "extension")
	for _, dir := range []string{appDir, extensionDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatalf("MkdirAll(%q): %v", dir, err)
		}
	}

	realName := "urnetwork.host.user.log.INFO.20260830-101112.4242"
	writeTestingLogFile(t, appDir, realName)
	writeTestingLogFile(t, extensionDir, "urnetwork.host.user.log.ERROR.20260830-101112.4243")

	// the symlink glog maintains next to the real file
	if err := os.Symlink(filepath.Join(appDir, realName), filepath.Join(appDir, "urnetwork.INFO")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	// A symlink whose name ALSO matches the ".log."+SEVERITY filename filter,
	// unlike glog's real "urnetwork.INFO" symlink above. This is what makes
	// the type check (entry.Type()&os.ModeSymlink) load-bearing: the filename
	// filter alone would let this one through, so if the type check were
	// dropped or broken, it would be double-counted as a real log file.
	spoofedName := "urnetwork.host.user.log.INFO.20260830-101112.9999"
	if err := os.Symlink(filepath.Join(appDir, realName), filepath.Join(appDir, spoofedName)); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	if err := SetLogDirForProcess(root, "app"); err != nil {
		t.Fatalf("SetLogDirForProcess: %v", err)
	}

	inventory := LogInventory()

	bySource := map[string]*LogFileInfo{}
	for i := 0; i < inventory.Len(); i += 1 {
		info := inventory.Get(i)
		if info.Name == "urnetwork.INFO" || info.Name == spoofedName {
			t.Fatalf("inventory included a symlink (%s); it must list real files only", info.Name)
		}
		bySource[info.Source] = info
	}

	app, ok := bySource["app"]
	if !ok {
		t.Fatal("inventory missing the app source")
	}
	if app.Severity != "INFO" {
		t.Fatalf("app severity = %q, want INFO", app.Severity)
	}
	if app.ByteCount <= 0 {
		t.Fatalf("app ByteCount = %d, want > 0", app.ByteCount)
	}

	extension, ok := bySource["extension"]
	if !ok {
		t.Fatal("inventory missing the extension source -- it only scanned this process's directory")
	}
	if extension.Severity != "ERROR" {
		t.Fatalf("extension severity = %q, want ERROR", extension.Severity)
	}
}
