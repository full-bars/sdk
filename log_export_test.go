package sdk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGetLogDirReturnsTheDirectoryGlogWritesTo pins the readback contract.
// glog.SetLogDir mutates only glog's internal logDirs/dirSet and never the
// `log_dir` flag, and sdk.SetLogDir stopped setting that flag in 9f41a00, so
// GetLogDir returned "" in every process -- silently breaking UploadLogs and
// both platforms' export buttons, all of which os.ReadDir(GetLogDir()).
func TestGetLogDirReturnsTheDirectoryGlogWritesTo(t *testing.T) {
	dir := t.TempDir()

	if err := SetLogDir(dir); err != nil {
		t.Fatalf("SetLogDir(%q) = %v, want nil", dir, err)
	}

	if got := GetLogDir(); got != dir {
		t.Fatalf("GetLogDir() = %q, want %q", got, dir)
	}

	// the actual failure mode: what every caller does with the result
	entries, err := os.ReadDir(GetLogDir())
	if err != nil {
		t.Fatalf("os.ReadDir(GetLogDir()) = %v, want nil", err)
	}
	if len(entries) == 0 {
		t.Fatal("os.ReadDir(GetLogDir()) found no files, but glog wrote its INFO file there")
	}
}

// TestSetLogDirForProcessScopesRetentionPerProcess is the reason per-process
// subdirectories exist. clearOldLogs keeps the 4 newest files in whatever
// directory it is handed, so two processes sharing one directory delete each
// other's history. Under a root, each process prunes only its own.
func TestSetLogDirForProcessScopesRetentionPerProcess(t *testing.T) {
	root := t.TempDir()

	if err := SetLogDirForProcess(root, "extension"); err != nil {
		t.Fatalf("SetLogDirForProcess(root, \"extension\") = %v, want nil", err)
	}
	extensionDir := GetLogDir()
	if extensionDir != filepath.Join(root, "extension") {
		t.Fatalf("GetLogDir() = %q, want %q", extensionDir, filepath.Join(root, "extension"))
	}
	if got := GetLogRoot(); got != root {
		t.Fatalf("GetLogRoot() = %q, want %q", got, root)
	}

	// six files in the extension's directory: retention keeps the newest 4
	for i := 0; i < 6; i += 1 {
		writeTestingLogFile(t, extensionDir, "urnetwork.host.user.log.INFO.2026083"+string(rune('0'+i))+"-000000.100")
	}

	// the app's own history must survive the extension's pruning
	if err := SetLogDirForProcess(root, "app"); err != nil {
		t.Fatalf("SetLogDirForProcess(root, \"app\") = %v, want nil", err)
	}
	appDir := GetLogDir()
	writeTestingLogFile(t, appDir, "urnetwork.host.user.log.INFO.20260830-000000.200")
	// SetLogDirForProcess("app") already routed through SetLogDir, whose own
	// clearOldLogs/Infof housekeeping writes created one file of its own here
	// (glog only opens a file in the newly-targeted directory on its next log
	// write, and that write is this pipeline's own bookkeeping -- see
	// SetLogDir and clearOldLogs, neither of which this task may change).
	// Snapshot the count now so the assertion below tests the real intent --
	// that pruning extensionDir must not touch appDir at all -- rather than
	// hardcoding a total that depends on that incidental write.
	appDirCountBeforePrune := countTestingLogFiles(t, appDir)

	// prune the extension's directory again, as its next launch would
	clearOldLogs(extensionDir)

	if got := countTestingLogFiles(t, extensionDir); got > 4 {
		t.Fatalf("extension dir kept %d log files, want at most 4", got)
	}
	if got := countTestingLogFiles(t, appDir); got != appDirCountBeforePrune {
		t.Fatalf("app dir has %d log files, want %d (unchanged) -- the extension's pruning deleted the app's history", got, appDirCountBeforePrune)
	}
}

func writeTestingLogFile(t *testing.T, dir string, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("I0830 00:00:00.000000 1 x.go:1] test\n"), 0600); err != nil {
		t.Fatalf("WriteFile(%q): %v", name, err)
	}
}

func countTestingLogFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	n := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), ".log.") {
			n += 1
		}
	}
	return n
}
