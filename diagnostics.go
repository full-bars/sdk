package sdk

import (
	"archive/zip"
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

// ExportOptions selects what an exported bundle contains.
type ExportOptions struct {
	// Redact maps ip addresses and uuid-shaped ids to per-export tokens.
	Redact bool
	// IncludeManifest writes manifest.json. The manifest body is supplied by
	// the platform via SetManifestJson, because on ios the device-side state
	// lives in the extension and arrives over the rpc.
	IncludeManifest bool
	// IncludePlatformLogs writes platform/*.txt from SetPlatformLog entries.
	IncludePlatformLogs bool
	// SelectedNames limits the export to these LogFileInfo.Name values. Empty
	// means every file.
	SelectedNames *StringList

	manifestJson  string
	platformLogs  *StringList
	platformNames *StringList
	missingNames  *StringList
	missingWhy    *StringList
}

func NewExportOptions() *ExportOptions {
	return &ExportOptions{
		SelectedNames: NewStringList(),
		platformLogs:  NewStringList(),
		platformNames: NewStringList(),
		missingNames:  NewStringList(),
		missingWhy:    NewStringList(),
	}
}

// SetManifestJson supplies the manifest body, normally
// Device.DiagnosticManifestJson().
func (self *ExportOptions) SetManifestJson(manifestJson string) {
	self.manifestJson = manifestJson
}

// AddPlatformLog adds one platform log entry, written to platform/<name>.
// Android passes its logcat dump here.
func (self *ExportOptions) AddPlatformLog(name string, content string) {
	self.platformNames.Add(name)
	self.platformLogs.Add(content)
}

// MissingSourceReason records a source that could not be read, so the bundle
// says so instead of silently omitting it.
func (self *ExportOptions) MissingSourceReason(source string, reason string) {
	self.missingNames.Add(source)
	self.missingWhy.Add(reason)
}

// ExportResult reports what was written.
type ExportResult struct {
	ByteCount int64
	FileCount int
	// MissingSources holds human-readable "<source>: <reason>" entries.
	MissingSources *StringList
}

// ExportDiagnosticBundle writes a zip of the selected logs to destPath.
//
// A source that cannot be read is reported in the result and in the bundle's
// README, never fatal: an ios build whose provisioning profile predates the
// app group must still export the logs it can reach. Only an unwritable
// destination is an error.
func ExportDiagnosticBundle(destPath string, opts *ExportOptions) (*ExportResult, error) {
	if opts == nil {
		opts = NewExportOptions()
	}

	FlushGlog()

	result := &ExportResult{MissingSources: NewStringList()}
	for i := 0; i < opts.missingNames.Len(); i += 1 {
		result.MissingSources.Add(opts.missingNames.Get(i) + ": " + opts.missingWhy.Get(i))
	}

	zipFile, err := os.Create(destPath)
	if err != nil {
		return nil, err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)

	var transform func(string) string
	if opts.Redact {
		redactor := newLogRedactor()
		transform = redactor.redactLine
	}

	inventory := LogInventory()
	for i := 0; i < inventory.Len(); i += 1 {
		info := inventory.Get(i)
		if 0 < opts.SelectedNames.Len() && !opts.SelectedNames.Contains(info.Name) {
			continue
		}
		f, err := os.Open(info.Path)
		if err != nil {
			result.MissingSources.Add(info.Name + ": " + err.Error())
			continue
		}
		err = zipWriteEntry(zipWriter, "logs/"+info.Source+"/"+info.Name, f, transform)
		f.Close()
		if err != nil {
			zipWriter.Close()
			return nil, err
		}
		result.FileCount += 1
	}

	if opts.IncludeManifest {
		manifestJson := opts.manifestJson
		if manifestJson == "" {
			manifestJson = "{\"available\":false}"
		}
		if err := zipWriteEntry(zipWriter, "manifest.json", strings.NewReader(manifestJson), transform); err != nil {
			zipWriter.Close()
			return nil, err
		}
	}

	if opts.IncludePlatformLogs {
		for i := 0; i < opts.platformNames.Len(); i += 1 {
			err := zipWriteEntry(
				zipWriter,
				"platform/"+opts.platformNames.Get(i),
				strings.NewReader(opts.platformLogs.Get(i)),
				transform,
			)
			if err != nil {
				zipWriter.Close()
				return nil, err
			}
		}
	}

	if err := zipWriteEntry(zipWriter, "README.txt", strings.NewReader(exportReadme(opts, result)), nil); err != nil {
		zipWriter.Close()
		return nil, err
	}

	if err := zipWriter.Close(); err != nil {
		return nil, err
	}
	if info, err := zipFile.Stat(); err == nil {
		result.ByteCount = info.Size()
	}
	return result, nil
}

func exportReadme(opts *ExportOptions, result *ExportResult) string {
	var b strings.Builder
	b.WriteString("URnetwork diagnostic bundle\n\n")
	if opts.Redact {
		b.WriteString("Mode: REDACTED. ip addresses and uuid-shaped ids are replaced by\n")
		b.WriteString("per-export tokens. The same value reads as the same token throughout\n")
		b.WriteString("this bundle, and differently in any other bundle. The mapping is not\n")
		b.WriteString("reversible and the salt is not included.\n\n")
	} else {
		b.WriteString("Mode: RAW. Nothing is masked. At raised log verbosity this can include\n")
		b.WriteString("the destination addresses and ports of your traffic, and your client id.\n\n")
	}
	b.WriteString("logs/<process>/  glog files, one directory per writing process\n")
	b.WriteString("manifest.json    device, build and connection state\n")
	b.WriteString("platform/        platform-side logs, where available\n\n")
	if 0 < result.MissingSources.Len() {
		b.WriteString("NOT INCLUDED:\n")
		for i := 0; i < result.MissingSources.Len(); i += 1 {
			b.WriteString("  - " + result.MissingSources.Get(i) + "\n")
		}
	}
	return b.String()
}
