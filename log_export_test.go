package sdk

import (
	"os"
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
