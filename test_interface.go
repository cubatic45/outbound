package shadowsocks_2022

import (
    "github.com/daeuniverse/outbound/netproxy"
)

// Verify that FakeNetPacketConn implements netproxy.PacketConn
var _ netproxy.PacketConn = &FakeNetPacketConn{}
