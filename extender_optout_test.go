//go:build !js

package sdk

import (
	"context"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/gossip"
)

func TestExtenderNetworkOptedOut(t *testing.T) {
	if extenderNetworkOptedOut(nil) {
		t.Fatal("nil settings opted out")
	}
	settings := connect.DefaultClientStrategySettings()
	if extenderNetworkOptedOut(settings) {
		t.Fatal("default settings opted out")
	}
	settings.DisableExtenderNetwork = true
	if !extenderNetworkOptedOut(settings) {
		t.Fatal("DisableExtenderNetwork did not opt out")
	}
}

// A space on a real dns name would normally build both; the opt-out is the
// only thing that makes the client and the node come back nil here.
func TestExtenderOptOutBuildsNoClientNoNode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key := NewNetworkSpaceKey("space.example", "main")
	values := &NetworkSpaceValues{}
	if !extenderNetworkClientRuns(key, values) {
		t.Fatal("test space must be one that runs an extender network client")
	}

	settings := connect.DefaultClientStrategySettings()
	settings.DisableExtenderNetwork = true
	directory := newSpaceExtenderDirectory(ctx, key, values, nil, settings.Log)

	client := newSpaceExtenderNetworkClient(
		ctx,
		key,
		values,
		ExtenderRoleFeed,
		nil,
		settings,
		directory,
		"https://api.space.example",
		settings.Log,
	)
	if client != nil {
		t.Fatal("opted-out space built an extender network client")
	}

	node := newSpaceExtenderNodeWithRole(
		ctx,
		key,
		values,
		gossip.NodeRoleMember,
		nil,
		nil,
		directory,
		nil,
		nil,
		settings,
		settings.Log,
	)
	if node != nil {
		t.Fatal("opted-out space built a gossip node")
	}
}
