package ua.nanit.limbo.connection;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Parses the null-separated "host" field of a forwarded handshake
 * (BungeeCord LEGACY / BungeeGuard format), tolerating the extra segment
 * that Geyser + Floodgate inject for Bedrock players.
 *
 * <p>Java player (4 segments):
 * <pre>host \0 ip \0 undashedUuid \0 propertiesJson</pre>
 *
 * <p>Bedrock player via Floodgate (5 segments):
 * <pre>host \0 ^Floodgate^&lt;blob&gt; \0 ip \0 undashedUuid \0 propertiesJson</pre>
 *
 * <p>Rather than trusting fixed indices, this anchors on the properties
 * array (the only segment that starts with '[') and walks backwards, so it
 * is immune to anything the proxy prepends. Any segment carrying the
 * Floodgate marker is stripped out and flagged.
 *
 * <p>This class is self-contained on purpose: it depends only on Gson,
 * which NanoLimbo already shades, so it drops into any fork without
 * touching GameProfile or the packet classes.
 */
public final class ForwardedHandshake {

    private static final String SEPARATOR = "\0";
    private static final String FLOODGATE_MARKER = "^Floodgate^";

    /** Property name used by lucko/BungeeGuard and, by default, BungeeGuardPlus. */
    public static final String DEFAULT_TOKEN_PROPERTY = "bungeeguard-token";

    private static final Gson GSON = new Gson();
    private static final Type PROPERTY_LIST = new TypeToken<List<Property>>() {
    }.getType();

    private final String virtualHost;
    private final String socketAddress;
    private final UUID uuid;
    private final String propertiesJson;
    private final boolean bedrock;

    private ForwardedHandshake(String virtualHost, String socketAddress, UUID uuid,
                               String propertiesJson, boolean bedrock) {
        this.virtualHost = virtualHost;
        this.socketAddress = socketAddress;
        this.uuid = uuid;
        this.propertiesJson = propertiesJson;
        this.bedrock = bedrock;
    }

    /**
     * @param host the raw host string from the handshake packet
     * @return parsed data, or {@code null} if the handshake was not forwarded
     * by a proxy (i.e. a direct connection attempt)
     */
    public static ForwardedHandshake parse(String host) {
        if (host == null || host.isEmpty()) {
            return null;
        }

        // Forge/FML clients append a marker after a null byte; drop it.
        int fml = host.indexOf("\0FML");
        if (fml >= 0) {
            host = host.substring(0, fml);
        }

        String[] raw = host.split(SEPARATOR, -1);

        List<String> parts = new ArrayList<>(raw.length);
        boolean bedrock = false;

        for (String part : raw) {
            if (part.isEmpty()) {
                continue;
            }
            if (part.contains(FLOODGATE_MARKER)) {
                // Floodgate's encrypted blob. NanoLimbo has no use for it and
                // does not run Floodgate, so it is simply discarded.
                bedrock = true;
                continue;
            }
            parts.add(part);
        }

        // Anchor on the properties array, counting backwards from it.
        int propertiesIndex = -1;
        for (int i = parts.size() - 1; i >= 1; i--) {
            if (parts.get(i).charAt(0) == '[') {
                propertiesIndex = i;
                break;
            }
        }

        String address;
        String rawUuid;
        String properties;

        if (propertiesIndex >= 3) {
            properties = parts.get(propertiesIndex);
            rawUuid = parts.get(propertiesIndex - 1);
            address = parts.get(propertiesIndex - 2);
        } else if (propertiesIndex < 0 && parts.size() >= 3) {
            // LEGACY forwarding without a properties array (offline-mode proxy).
            properties = null;
            rawUuid = parts.get(parts.size() - 1);
            address = parts.get(parts.size() - 2);
        } else {
            return null;
        }

        UUID uuid = parseUuid(rawUuid);
        if (uuid == null) {
            return null;
        }

        return new ForwardedHandshake(parts.get(0), address, uuid, properties, bedrock);
    }

    /**
     * Extracts the BungeeGuard token from the forwarded properties.
     *
     * @param propertyNames property names to accept, case-insensitively
     * @return the token, or {@code null} if no matching property was forwarded
     */
    public String findToken(Collection<String> propertyNames) {
        if (propertiesJson == null || propertyNames == null || propertyNames.isEmpty()) {
            return null;
        }

        List<Property> properties;
        try {
            properties = GSON.fromJson(propertiesJson, PROPERTY_LIST);
        } catch (JsonSyntaxException e) {
            return null;
        }

        if (properties == null) {
            return null;
        }

        for (Property property : properties) {
            if (property == null || property.name == null || property.value == null) {
                continue;
            }
            for (String name : propertyNames) {
                if (property.name.equalsIgnoreCase(name)) {
                    return property.value;
                }
            }
        }

        return null;
    }

    public String findToken() {
        return findToken(Arrays.asList(DEFAULT_TOKEN_PROPERTY));
    }

    /** Length-safe, constant-time token comparison. */
    public static boolean tokenMatches(String provided, String expected) {
        if (provided == null || expected == null) {
            return false;
        }
        return MessageDigest.isEqual(
                provided.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8));
    }

    public static boolean tokenAllowed(String provided, Collection<String> allowed) {
        if (provided == null || allowed == null) {
            return false;
        }
        boolean matched = false;
        for (String token : allowed) {
            // No short-circuit: keep the work constant regardless of position.
            matched |= tokenMatches(provided, token);
        }
        return matched;
    }

    private static UUID parseUuid(String value) {
        if (value == null) {
            return null;
        }
        try {
            if (value.length() == 32) {
                return new UUID(
                        Long.parseUnsignedLong(value.substring(0, 16), 16),
                        Long.parseUnsignedLong(value.substring(16), 16));
            }
            if (value.length() == 36) {
                return UUID.fromString(value);
            }
        } catch (NumberFormatException | IllegalArgumentException ignored) {
            // fall through
        }
        return null;
    }

    public String getVirtualHost() {
        return virtualHost;
    }

    public String getSocketAddress() {
        return socketAddress;
    }

    public UUID getUuid() {
        return uuid;
    }

    public String getPropertiesJson() {
        return propertiesJson;
    }

    /** True when the connection arrived through Geyser/Floodgate. */
    public boolean isBedrock() {
        return bedrock;
    }

    private static final class Property {
        private String name;
        private String value;
        private String signature;
    }
}
