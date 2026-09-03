package service

import (
	"context"
	"errors"
	"net"
	"time"
)

type connectionContextKey struct{}

// WithConnection is intended for http.Server.ConnContext. It lets the Web SSH
// route clear server-wide HTTP deadlines only after that connection has been
// successfully upgraded; ordinary HTTP requests retain all server deadlines.
func WithConnection(ctx context.Context, connection net.Conn) context.Context {
	return context.WithValue(ctx, connectionContextKey{}, connection)
}

func clearUpgradedConnectionDeadlines(ctx context.Context) error {
	connection, ok := ctx.Value(connectionContextKey{}).(net.Conn)
	if !ok || connection == nil {
		return errors.New("upgraded connection is unavailable")
	}
	return connection.SetDeadline(time.Time{})
}
