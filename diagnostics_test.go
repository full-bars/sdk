package sdk

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
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

// TestExportDiagnosticBundleWritesEverySelectedSource covers the zip layout and
// that a source which cannot be read is REPORTED, never fatal -- an ios build
// whose provisioning profile lacks the app group must still export its own
// logs.
func TestExportDiagnosticBundleWritesEverySelectedSource(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	if err := os.MkdirAll(appDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	writeTestingLogFile(t, appDir, "urnetwork.host.user.log.INFO.20260830-101112.4242")
	if err := SetLogDirForProcess(root, "app"); err != nil {
		t.Fatalf("SetLogDirForProcess: %v", err)
	}

	// SetLogDirForProcess's own SetLogDir call writes one incidental
	// bookkeeping entry ("New glog initialized") into appDir before this test
	// ever calls ExportDiagnosticBundle (see log_export_test.go's identical
	// note; SetLogDir/clearOldLogs are out of this task's scope to change).
	// LogInventory correctly counts that real file alongside the fixture one,
	// so the expected count is taken from the inventory itself rather than
	// hardcoded, keeping the assertion honest about what is actually on disk.
	wantFileCount := LogInventory().Len()

	destPath := filepath.Join(t.TempDir(), "bundle.zip")

	opts := NewExportOptions()
	opts.IncludeManifest = true
	opts.MissingSourceReason("extension", "app group container unavailable")

	result, err := ExportDiagnosticBundle(destPath, opts)
	if err != nil {
		t.Fatalf("ExportDiagnosticBundle = %v, want nil", err)
	}
	if result.FileCount != wantFileCount {
		t.Fatalf("FileCount = %d, want %d", result.FileCount, wantFileCount)
	}
	if result.MissingSources.Len() != 1 {
		t.Fatalf("MissingSources.Len() = %d, want 1", result.MissingSources.Len())
	}

	reader, err := zip.OpenReader(destPath)
	if err != nil {
		t.Fatalf("zip.OpenReader: %v", err)
	}
	defer reader.Close()

	names := map[string]bool{}
	for _, f := range reader.File {
		names[f.Name] = true
	}
	for _, want := range []string{
		"README.txt",
		"manifest.json",
		"logs/app/urnetwork.host.user.log.INFO.20260830-101112.4242",
	} {
		if !names[want] {
			t.Errorf("bundle missing %q; has %v", want, names)
		}
	}
}

// A redacted export must not carry the raw value anywhere in the archive.
func TestExportDiagnosticBundleRedactsWhenAsked(t *testing.T) {
	root := t.TempDir()
	appDir := filepath.Join(root, "app")
	if err := os.MkdirAll(appDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	name := "urnetwork.host.user.log.INFO.20260830-101112.4242"
	if err := os.WriteFile(filepath.Join(appDir, name),
		[]byte("I0830 10:11:12.131415 1 x.go:1] peer 203.0.113.7:443\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := SetLogDirForProcess(root, "app"); err != nil {
		t.Fatalf("SetLogDirForProcess: %v", err)
	}

	destPath := filepath.Join(t.TempDir(), "redacted.zip")
	opts := NewExportOptions()
	opts.Redact = true

	if _, err := ExportDiagnosticBundle(destPath, opts); err != nil {
		t.Fatalf("ExportDiagnosticBundle = %v", err)
	}

	reader, err := zip.OpenReader(destPath)
	if err != nil {
		t.Fatalf("zip.OpenReader: %v", err)
	}
	defer reader.Close()

	for _, f := range reader.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %q: %v", f.Name, err)
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %q: %v", f.Name, err)
		}
		if strings.Contains(string(content), "203.0.113.7") {
			t.Fatalf("entry %q in a redacted bundle still contains the raw address", f.Name)
		}
	}
}
