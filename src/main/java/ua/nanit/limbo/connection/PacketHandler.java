    public void handle(@NonNull ClientConnection conn, @NonNull PacketHandshake packet) {
        conn.updateVersion(packet.getVersion());

        switch (packet.getIntent()) {
            case STATUS -> {
                conn.updateState(State.STATUS);

                Log.debug("Pinged from %s [%s]", conn.getAddress(), conn.getClientVersion().toString());
            }
            case LOGIN, TRANSFER -> {
                conn.updateState(State.LOGIN);

                if (!conn.getClientVersion().isSupported()) {
                    conn.disconnect(Component.text("Unsupported client version", NamedTextColor.RED));
                    return;
                }

                if (this.server.getConfig().getInfoForwarding().isLegacy()) {
                    if (!ForwardingUtils.checkLegacyHandshake(conn, packet.getHost())) {
                        conn.disconnect(Component.text("You've enabled player info forwarding. You need to connect with proxy", NamedTextColor.RED));
                        return;
                    }
                } else if (this.server.getConfig().getInfoForwarding().isBungeeGuard()) {
                    if (!ForwardingUtils.checkBungeeGuardHandshake(conn, packet.getHost())) {
                        conn.disconnect(Component.text("Invalid BungeeGuard token or handshake format", NamedTextColor.RED));
                        return;
                    }
                }
            }
            default -> conn.disconnect(Component.text("Invalid handshake intent!", NamedTextColor.RED));
        }
    }
