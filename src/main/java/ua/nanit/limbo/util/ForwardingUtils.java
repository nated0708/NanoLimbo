/*
 * Copyright (C) 2020 Nan1t
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package ua.nanit.limbo.util;

import com.google.gson.*;
import lombok.NonNull;
import lombok.experimental.UtilityClass;
import ua.nanit.limbo.connection.ClientConnection;
import ua.nanit.limbo.protocol.ByteMessage;
import ua.nanit.limbo.server.Log;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@UtilityClass
public class ForwardingUtils {

    private static final String ALGORITHM = "HmacSHA256";

    /** Marker Floodgate injects into the handshake for Bedrock players. */
    private static final String FLOODGATE_MARKER = "^Floodgate^";

    public static final byte VELOCITY_MAX_SUPPORTED_FORWARDING_VERSION = 1;

    public static boolean checkVelocityKeyIntegrity(@NonNull ClientConnection conn,
                                                    @NonNull ByteMessage buf) {
        byte[] signature = new byte[32];
        buf.readBytes(signature);

        byte[] data = new byte[buf.readableBytes()];
        buf.getBytes(buf.readerIndex(), data);

        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(conn.getServer().getConfig().getInfoForwarding().getSecretKey(), ALGORITHM));
            byte[] mySignature = mac.doFinal(data);
            if (!MessageDigest.isEqual(signature, mySignature)) {
                return false;
            }
        } catch (InvalidKeyException | java.security.NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
        return true;
    }

    /**
     * Splits the handshake host field, discarding anything the proxy injected
     * that is not part of the standard BungeeCord forwarding format.
     *
     * <p>Java:    host \0 ip \0 uuid \0 properties
     * <p>Bedrock: host \0 ^Floodgate^&lt;blob&gt; \0 ip \0 uuid \0 properties
     *
     * <p>The Floodgate blob is dropped rather than decrypted — the limbo has
     * no Floodgate key and no use for the data.
     */
    private static String[] splitHandshake(@NonNull String handshake) {
        // Forge/FML clients append a marker after a null byte.
        int fml = handshake.indexOf("\u0000FML");
        if (fml >= 0) {
            handshake = handshake.substring(0, fml);
        }

        String[] raw = handshake.split("\u0000", -1);
        List<String> parts = new ArrayList<>(raw.length);

        for (String part : raw) {
            if (part.isEmpty() || part.contains(FLOODGATE_MARKER)) {
                continue;
            }
            parts.add(part);
        }

        return parts.toArray(new String[0]);
    }

    /**
     * Index of the forwarded properties array, or -1 if absent. Anchoring on
     * this instead of a fixed offset makes the parser immune to extra
     * segments prepended by Geyser, Floodgate, or anything else.
     */
    private static int propertiesIndex(@NonNull String[] parts) {
        for (int i = parts.length - 1; i >= 1; i--) {
            if (parts[i].charAt(0) == '[') {
                return i;
            }
        }
        return -1;
    }

    private static UUID parseUuid(@NonNull String raw) {
        try {
            return UUIDUtils.fromString(raw);
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Applies plain BungeeCord (LEGACY) info forwarding.
     *
     * @return false if the handshake was not forwarded by a proxy
     */
    public static boolean checkLegacyHandshake(@NonNull ClientConnection conn,
                                               @NonNull String handshake) {
        String[] parts = splitHandshake(handshake);
        int propsIdx = propertiesIndex(parts);

        int uuidIdx = propsIdx >= 3 ? propsIdx - 1 : parts.length - 1;
        int addressIdx = uuidIdx - 1;

        if (addressIdx < 1) {
            return false;
        }

        UUID uuid = parseUuid(parts[uuidIdx]);
        if (uuid == null) {
            return false;
        }

        conn.setAddress(parts[addressIdx]);
        conn.getGameProfile().setUuid(uuid);

        if (handshake.contains(FLOODGATE_MARKER)) {
            Log.debug("Accepted Floodgate handshake for %s", uuid);
        }

        return true;
    }

    public static boolean checkBungeeGuardHandshake(@NonNull ClientConnection conn,
                                                    @NonNull String handshake) {
        String[] parts = splitHandshake(handshake);
        int propsIdx = propertiesIndex(parts);

        if (propsIdx < 3) {
            return false;
        }

        String socketAddressHostname = parts[propsIdx - 2];
        UUID uuid = parseUuid(parts[propsIdx - 1]);

        if (uuid == null) {
            return false;
        }

        List<String> tokenProperties =
                conn.getServer().getConfig().getInfoForwarding().getTokenProperties();

        String token = null;

        try {
            JsonElement rootElement = JsonParser.parseString(parts[propsIdx]);
            if (!rootElement.isJsonArray()) {
                return false;
            }

            JsonArray jsonArray = rootElement.getAsJsonArray();

            outer:
            for (JsonElement jsonElement : jsonArray) {
                if (!jsonElement.isJsonObject()) {
                    continue;
                }

                JsonObject jsonObject = jsonElement.getAsJsonObject();

                JsonElement nameElement = jsonObject.get("name");
                if (nameElement == null || !nameElement.isJsonPrimitive()) {
                    continue;
                }

                String name = nameElement.getAsString();

                for (String candidate : tokenProperties) {
                    if (name.equalsIgnoreCase(candidate)) {
                        JsonElement valueElement = jsonObject.get("value");
                        if (valueElement != null && valueElement.isJsonPrimitive()) {
                            token = valueElement.getAsString();
                            break outer;
                        }
                    }
                }
            }
        } catch (JsonParseException e) {
            return false;
        }

        if (!conn.getServer().getConfig().getInfoForwarding().hasToken(token)) {
            return false;
        }

        conn.setAddress(socketAddressHostname);
        conn.getGameProfile().setUuid(uuid);

        if (handshake.contains(FLOODGATE_MARKER)) {
            Log.debug("Accepted Floodgate BungeeGuard handshake for %s", uuid);
        }

        return true;
    }

}
