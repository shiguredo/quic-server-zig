const std = @import("std");
const Allocator = std.mem.Allocator;
const cryptor = @import("./tls/cryptor.zig");

pub const Cryptor = cryptor.Cryptor;

/// This type provides the QUIC implementation with the interface to interact with the TLS stack.
///
/// https://www.rfc-editor.org/rfc/rfc9001#name-carrying-tls-messages
/// https://www.rfc-editor.org/rfc/rfc9001#name-interface-to-tls
pub const Tls = struct {
    /// https://www.rfc-editor.org/rfc/rfc9001#name-sending-and-receiving-hands
    ///
    /// > Before starting the handshake, QUIC provides TLS with the transport parameters
    /// > (see Section 8.2) that it wishes to carry.
    transport_params: TransportParameters,

    /// Encryption level used for receiving.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9001#name-sending-and-receiving-hands
    ///
    /// > At any time, the TLS stack at an endpoint will have a current sending encryption level
    /// > and a receiving encryption level.
    rx_encryption_level: EncryptionLevel,

    /// Encryption level used for sending.
    ///
    /// https://www.rfc-editor.org/rfc/rfc9001#name-sending-and-receiving-hands
    ///
    /// > At any time, the TLS stack at an endpoint will have a current sending encryption level
    /// > and a receiving encryption level.
    tx_encryption_level: EncryptionLevel,

    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, transport_params: TransportParameters) Self {
        return Self{
            .transport_params = transport_params,
            .allocator = allocator,
        };
    }

    /// Consume plain TLS handshake data sent from the peer.
    pub fn readHandshake(self: *Self, plaintext: []const u8) !void {
        // TODO(magurotuna)
        _ = self;
        _ = plaintext;
    }

    /// Emit plain TLS handshake data to the given `buf`.
    /// When new key materials have become ready, they are returned; otherwise `null` is returned.
    pub fn writeHandshake(self: *Self, buf: []u8) ?KeyChange {
        // TODO(magurotuna)
        _ = self;
        _ = buf;
        return null;
    }
};

/// Transport parameters
///
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameters
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-transport-parameter-encodin
/// https://www.rfc-editor.org/rfc/rfc9001.html#name-quic-transport-parameters-e
pub const TransportParameters = struct {
    // TODO
};

pub const KeyChange = union(enum) {
    handshake: struct {
        keys: Keys,
    },
    // TODO(magurotuna): uncomment this variant and implement it.
    // Reference: https://docs.rs/rustls/latest/rustls/quic/enum.KeyChange.html
    // one_rtt: struct {
    //     keys: Keys,
    //     next: Secrets,
    // },
};

pub const Keys = struct {
    /// Used to encrypt outgoing packets.
    local: Cryptor,
    /// Used to decrypt incoming packets.
    remote: Cryptor,

    const Self = @This();

    /// Construct keys used for Initial packets.
    pub fn initial(allocator: Allocator, client_dcid: []const u8, is_server: bool) !Self {
        var server_cryptor = try cryptor.TLS_AES_128_GCM_SHA256.initial(allocator, client_dcid, true);
        errdefer server_cryptor.deinit();
        var client_cryptor = try cryptor.TLS_AES_128_GCM_SHA256.initial(allocator, client_dcid, false);
        errdefer server_cryptor.deinit();

        return Self{
            .local = if (is_server) server_cryptor else client_cryptor,
            .remote = if (is_server) client_cryptor else server_cryptor,
        };
    }
};

/// https://www.rfc-editor.org/rfc/rfc9001#name-tls-overview
///
/// > Data is protected using a number of encryption levels:
/// >   - Initial keys
/// >   - Early data (0-RTT) keys
/// >   - Handshake keys
/// >   - Application data (1-RTT) keys
const EncryptionLevel = enum {
    initial,
    zero_rtt,
    handshake,
    application_data,
};

test {
    std.testing.refAllDecls(@This());
}
