package sdk

import (
	"encoding/json"
	"testing"
)

// The manifest must be valid json with the fields the bundle's reader relies
// on, and must never be empty -- an export with no manifest is an export that
// cannot be dated or attributed to a build.
func TestDiagnosticManifestJsonShape(t *testing.T) {
	manifestJson := buildDiagnosticManifestJson(diagnosticManifestInput{
		SdkVersion:      "0.0.0-test",
		ClientId:        "11111111-1111-1111-1111-111111111111",
		InstanceId:      "22222222-2222-2222-2222-222222222222",
		NetworkSpace:    "main",
		ConnectEnabled:  true,
		ProvideEnabled:  false,
		DeviceAvailable: true,
	})

	var decoded map[string]any
	if err := json.Unmarshal([]byte(manifestJson), &decoded); err != nil {
		t.Fatalf("manifest is not valid json: %v\n%s", err, manifestJson)
	}

	for _, key := range []string{"sdk_version", "client_id", "instance_id", "network_space", "connect_enabled", "device_available"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("manifest missing %q; has %v", key, decoded)
		}
	}
	if decoded["sdk_version"] != "0.0.0-test" {
		t.Errorf("sdk_version = %v, want 0.0.0-test", decoded["sdk_version"])
	}
}

// When the rpc is down the manifest must still be produced, marked so the
// reader knows the device-side fields are absent rather than false.
func TestDiagnosticManifestJsonWhenDeviceUnavailable(t *testing.T) {
	manifestJson := buildDiagnosticManifestJson(diagnosticManifestInput{
		SdkVersion:      "0.0.0-test",
		DeviceAvailable: false,
	})

	var decoded map[string]any
	if err := json.Unmarshal([]byte(manifestJson), &decoded); err != nil {
		t.Fatalf("manifest is not valid json: %v", err)
	}
	if decoded["device_available"] != false {
		t.Fatalf("device_available = %v, want false", decoded["device_available"])
	}
}
