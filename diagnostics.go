package sdk

import (
	"archive/zip"
	"encoding/json"
	"fmt"
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
	inventory, _ := logInventory()
	return inventory
}

// logRootSourceName labels a failure to read the log root itself, which is not
// attributable to any one process directory.
const logRootSourceName = "log root"

// logInventory is LogInventory plus the directories it could not read, as
// "<source>: <reason>" entries.
//
// The exported LogInventory drops them because its bound signature has nowhere
// to put them, but ExportDiagnosticBundle must not: an unreadable log root or
// per-process directory used to be omitted from the bundle with nothing
// recorded as missing, so a user whose Logs/extension directory had become
// unreadable got a zip with an empty NOT INCLUDED block and an ExportResult
// reporting zero missing sources, while a whole process's logs were absent.
// The spec's degradation promise is that a source that cannot be read is
// recorded as missing, never silently dropped.
func logInventory() (*LogFileInfoList, []string) {
	inventory := NewLogFileInfoList()
	unreadable := []string{}

	root := GetLogRoot()
	if root == "" {
		// legacy single-directory configuration: report it as one source
		if dir := GetLogDir(); dir != "" {
			if err := appendLogFilesIn(inventory, dir, "app"); err != nil {
				unreadable = append(unreadable, "app: "+err.Error())
			}
		}
		return inventory, unreadable
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return inventory, append(unreadable, logRootSourceName+": "+err.Error())
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if err := appendLogFilesIn(inventory, filepath.Join(root, entry.Name()), entry.Name()); err != nil {
			unreadable = append(unreadable, entry.Name()+": "+err.Error())
		}
	}
	return inventory, unreadable
}

func appendLogFilesIn(inventory *LogFileInfoList, dir string, source string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
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
	return nil
}

// ExportOptions selects what an exported bundle contains.
type ExportOptions struct {
	// Redact maps ip addresses and uuid-shaped ids to per-export tokens.
	Redact bool
	// IncludeManifest writes manifest.json. The manifest body is supplied by
	// the platform via SetManifestJson, because on ios the device-side state
	// lives in the extension and arrives over the rpc.
	IncludeManifest bool
	// IncludePlatformLogs writes platform log files (platform/NAME.txt) from
	// SetPlatformLog entries.
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
	options := &ExportOptions{}
	options.initLists()
	return options
}

// initLists fills in any list field left nil, and is called by every method
// that reads or writes one, plus by the exporter itself.
//
// ExportOptions reaches the exporter as a zero value on paths that never run
// NewExportOptions: the c abi json-unmarshals into a bare
// &sdk.ExportOptions{} (cgo/exports_gen.go, urnet_export_diagnostic_bundle)
// and leaves every unexported list nil, and a language binding that emits a
// zero-value constructor alongside the NewExportOptions one does the same.
// The lists are embedded-struct pointers, so reading Len() off a nil one is a
// nil dereference, not a zero result -- on the c abi that panic was recovered
// into a NULL return with no error set, and through a gomobile seq bridge it
// is an app crash. A zero-value ExportOptions must behave exactly like a
// fresh one.
func (self *ExportOptions) initLists() {
	if self.SelectedNames == nil {
		self.SelectedNames = NewStringList()
	}
	if self.platformLogs == nil {
		self.platformLogs = NewStringList()
	}
	if self.platformNames == nil {
		self.platformNames = NewStringList()
	}
	if self.missingNames == nil {
		self.missingNames = NewStringList()
	}
	if self.missingWhy == nil {
		self.missingWhy = NewStringList()
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
	self.initLists()
	self.platformNames.Add(name)
	self.platformLogs.Add(content)
}

// MissingSourceReason records a source that could not be read, so the bundle
// says so instead of silently omitting it.
func (self *ExportOptions) MissingSourceReason(source string, reason string) {
	self.initLists()
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
	opts.initLists()

	// A redacted bundle that cannot back its per-export salt with real
	// randomness must not be produced at all -- so this is checked, and can
	// fail, before anything is written to destPath. A RAW export never
	// reaches this branch and is unaffected.
	var transform func(string) string
	if opts.Redact {
		redactor, err := newLogRedactor()
		if err != nil {
			return nil, fmt.Errorf("redacted export not produced: a secure random salt was unavailable: %w", err)
		}
		transform = redactor.redactLine
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

	inventory, unreadable := logInventory()
	for _, entry := range unreadable {
		result.MissingSources.Add(entry)
	}
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
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			result.MissingSources.Add(info.Name + ": " + err.Error())
			continue
		}
		err = zipWriteEntry(zipWriter, "logs/"+info.Source+"/"+info.Name, f, fi, transform)
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
			// No platform ever called SetManifestJson -- e.g. Android exporting
			// while disconnected, where deviceManager.device is null. Build the
			// fallback through buildDiagnosticManifestJson rather than a
			// hand-written literal, so this path and the normal one share a
			// single source of truth for the manifest's shape and can't drift
			// apart on key names again.
			manifestJson = buildDiagnosticManifestJson(diagnosticManifestInput{
				SdkVersion:      Version,
				DeviceAvailable: false,
			})
		}
		if err := zipWriteEntry(zipWriter, "manifest.json", strings.NewReader(manifestJson), nil, transform); err != nil {
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
				nil,
				transform,
			)
			if err != nil {
				zipWriter.Close()
				return nil, err
			}
		}
	}

	// README.txt goes through transform like every other entry. Its NOT
	// INCLUDED block quotes os.Open/os.Stat error strings, which carry the
	// absolute path of the file that could not be read -- on ios that path
	// contains the app group container uuid, the very identifier manifest.json
	// masks two entries earlier. An unredacted README would have made a
	// redacted bundle both mask and leak the same value, under a README
	// asserting that uuid-shaped ids are replaced. Platform-supplied
	// MissingSourceReason text lands here too and is equally unfiltered at
	// source.
	if err := zipWriteEntry(zipWriter, "README.txt", strings.NewReader(exportReadme(opts, result)), nil, transform); err != nil {
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

// diagnosticManifestInput is the plain-Go input to the manifest. It is not
// exported to gomobile: the bound surface is DiagnosticManifestJson() string.
type diagnosticManifestInput struct {
	SdkVersion      string
	ClientId        string
	InstanceId      string
	NetworkSpace    string
	ConnectEnabled  bool
	ProvideEnabled  bool
	DeviceAvailable bool
}

func buildDiagnosticManifestJson(input diagnosticManifestInput) string {
	manifest := map[string]any{
		"sdk_version":   input.SdkVersion,
		"client_id":     input.ClientId,
		"instance_id":   input.InstanceId,
		"network_space": input.NetworkSpace,
		// device_available is false when the manifest was built without a live
		// device -- on ios that means the rpc into the extension was down, so
		// the fields below are absent rather than genuinely false.
		"device_available": input.DeviceAvailable,
		"connect_enabled":  input.ConnectEnabled,
		"provide_enabled":  input.ProvideEnabled,
		"log_root":         GetLogRoot(),
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "{\"device_available\":false}"
	}
	return string(encoded)
}
