package snapshot

import (
	"context"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"

	"vpsmanager/services/connector/sshconnector"
	"vpsmanager/services/control-plane/internal/model"
)

// ExecuteCatalogCommand reuses the snapshot connector boundary for another
// opaque catalog command. Command scripts remain inaccessible to API callers.
func (c *Collector) ExecuteCatalogCommand(ctx context.Context, host model.Host, authMethod ssh.AuthMethod, command sshconnector.Command, timeout time.Duration, maxOutputBytes int64) (sshconnector.Result, error) {
	if host.HostKey == nil {
		return sshconnector.Result{}, errors.New("host key is not pinned")
	}
	pinned, err := sshconnector.ParsePinnedHostKey(host.HostKey.PublicKey)
	if err != nil {
		return sshconnector.Result{}, errors.New("stored host key is invalid")
	}
	if timeout <= 0 || timeout > 30*time.Second {
		return sshconnector.Result{}, errors.New("catalog command timeout is outside policy")
	}
	if maxOutputBytes <= 0 || maxOutputBytes > 256<<10 {
		return sshconnector.Result{}, errors.New("catalog command output limit is outside policy")
	}
	return c.runner.Run(ctx, sshconnector.Config{
		Address: host.Address, Port: host.Port, User: host.Username, Auth: authMethod,
		PinnedHostKey: pinned, ConnectTimeout: 10 * time.Second, CommandTimeout: timeout,
		MaxOutputBytes: maxOutputBytes, AllowPrivateTargets: c.allowPrivateTargets,
	}, command)
}
