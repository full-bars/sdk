package sdk

import (
	"sync"
	"testing"

	"github.com/urnetwork/connect"
)

// A store that holds nothing and records that the activation loop used it.
type testExtenderPacingStore struct {
	loaded chan struct{}
	saved  chan struct{}
	once   sync.Once
}

func newTestExtenderPacingStore() *testExtenderPacingStore {
	return &testExtenderPacingStore{
		loaded: make(chan struct{}),
		saved:  make(chan struct{}, 16),
	}
}

func (self *testExtenderPacingStore) LoadPacing() (*connect.ExtenderActivationPacingRecord, error) {
	self.once.Do(func() { close(self.loaded) })
	return nil, nil
}

func (self *testExtenderPacingStore) SavePacing(record *connect.ExtenderActivationPacingRecord) error {
	select {
	case self.saved <- struct{}{}:
	default:
	}
	return nil
}

// The store the embedder sets on the device is the store the activation loop
// loads from at start and saves to as it paces.
func TestDeviceLocalProviderExtenderActivatorUsesTheDevicePacingStore(t *testing.T) {
	store := newTestExtenderPacingStore()
	seen := make(chan connect.ExtenderActivationPacingStore, 1)
	fixture := newTestProvideExtenderFixtureWithDevice(t,
		func(settings *DeviceLocalSettings) {
			settings.ExtenderPacingStore = store
		},
		func(settings *deviceLocalExtenderSettings) {
			settings.ConfigureActivator = func(settings *connect.ExtenderActivatorSettings) {
				select {
				case seen <- settings.PacingStore:
				default:
				}
			}
		},
	)
	fixture.waitActivated()

	if got := <-seen; got != connect.ExtenderActivationPacingStore(store) {
		t.Fatalf("activator PacingStore = %v, expected the device's store", got)
	}
	<-store.loaded
	<-store.saved
}

// The zero value keeps no pacing state, which is how every device ran before.
func TestDeviceLocalProviderExtenderActivatorHasNoPacingStoreByDefault(t *testing.T) {
	seen := make(chan connect.ExtenderActivationPacingStore, 1)
	fixture := newTestProvideExtenderFixture(t, func(settings *deviceLocalExtenderSettings) {
		settings.ConfigureActivator = func(settings *connect.ExtenderActivatorSettings) {
			select {
			case seen <- settings.PacingStore:
			default:
			}
		}
	})
	fixture.waitActivated()

	if got := <-seen; got != nil {
		t.Fatalf("activator PacingStore = %v, expected nil", got)
	}
}
