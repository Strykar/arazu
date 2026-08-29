// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"fmt"
	"net"
	"time"
)

// hostConnectProbe makes a real TCP connect on the host, to a listener this
// function creates. It proves host egress works without depending on the
// internet being reachable.
func hostConnectProbe() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if c, err := ln.Accept(); err == nil {
			c.Close()
		}
	}()

	c, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	if err != nil {
		return ln.Addr().String(), fmt.Errorf("dial: %w", err)
	}
	c.Close()
	<-done
	return ln.Addr().String(), nil
}
