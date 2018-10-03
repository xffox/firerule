Rule system for firewalls. High level rule language is translated to a low
level rule description (currently `iptables`). Translation includes
optimization step. Also includes D-Bus-based daemon to monitor network state
changes (uses `NetworkManager`) and apply rules according to those changes.
The rules for this network state reactions are described using the same high
level language as the one for firewalls.

Example firewall rules:

    input:
        drop,
        accept %
            layer.link.if src lo | (
                layer.net.ipv4 any & (
                    state.connection (related | established)
                )
            );
    output:
        drop,
        accept %
            layer.link.if dst lo | (
                layer.net.ipv4 any & (
                    layer.transport.udp.port dst (53 | 67 | 547 | 123) |
                    layer.transport.tcp.port dst (
                        22 | 443 | 465 | 587 | 993 | 5222 | 6697
                    ) |
                    layer.net.ipv4.icmp
                )
            );
    forward: drop;
