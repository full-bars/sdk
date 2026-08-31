package sdk

import (
	"os"
	"path/filepath"
	"strings"
)

// logSeverities are the glog severity tags, in the order glog defines them.
// They appear in a log file name as the segment immediately after ".log."
// (glog/glog_file.go:124-140).
var logSeverities = []string{"INFO", "WARNING", "ERROR", "FATAL"}

// LogFileInfo describes one log file the bundle could include.
//
// gomobile does not support struct composition, so this is flat, and every
// field is a bindable scalar.
type LogFileInfo struct {
	// Name is the glog file name, unique within the export.
	Name string
	// Path is the absolute path on disk.
	Path string
	// Source is the writing process: the per-process subdirectory name,
	// e.g. "app" or "extension".
	Source string
	// Severity is INFO, WARNING, ERROR or FATAL.
	Severity  string
	ByteCount int64
	// ModifiedMillis is unix millis, 0 when unknown.
	ModifiedMillis int64
}

type LogFileInfoList struct {
	exportedList[*LogFileInfo]
}

func NewLogFileInfoList() *LogFileInfoList {
	return &LogFileInfoList{
		exportedList: *newExportedList[*LogFileInfo](),
	}
}

// logSeverityOf returns the severity named in a glog file name, or "" when the
// name is not a glog log file.
func logSeverityOf(name string) string {
	for _, severity := range logSeverities {
		if strings.Contains(name, ".log."+severity) {
			return severity
		}
	}
	return ""
}

// LogInventory enumerates every log file under the recorded log root, across
// every process that has written there.
//
// Symlinks are skipped: glog maintains a <program>.<SEVERITY> symlink beside
// each real file, and following it would list the same bytes twice.
func LogInventory() *LogFileInfoList {
	inventory := NewLogFileInfoList()

	root := GetLogRoot()
	if root == "" {
		// legacy single-directory configuration: report it as one source
		if dir := GetLogDir(); dir != "" {
			appendLogFilesIn(inventory, dir, "app")
		}
		return inventory
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return inventory
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		appendLogFilesIn(inventory, filepath.Join(root, entry.Name()), entry.Name())
	}
	return inventory
}

func appendLogFilesIn(inventory *LogFileInfoList, dir string, source string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		// Type()&ModeSymlink catches glog's severity symlinks without a stat
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		severity := logSeverityOf(entry.Name())
		if severity == "" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		inventory.Add(&LogFileInfo{
			Name:           entry.Name(),
			Path:           filepath.Join(dir, entry.Name()),
			Source:         source,
			Severity:       severity,
			ByteCount:      info.Size(),
			ModifiedMillis: info.ModTime().UnixMilli(),
		})
	}
}
