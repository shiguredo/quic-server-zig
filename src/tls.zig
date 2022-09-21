const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;
const EnumArray = std.EnumArray;
const BoundedArray = std.BoundedArray;
const cryptor = @import("./tls/cryptor.zig");
const derive = @import("./tls/derive.zig");
const handshake = @import("./tls/handshake.zig");
const client_hello = @import("./tls/client_hello.zig");
const server_hello = @import("./tls/server_hello.zig");
const cipher_suite = @import("./tls/cipher_suite.zig");
const extension = @import("./tls/extension.zig");
const supported_groups = @import("./tls/extension/supported_groups.zig");
const supported_versions = @import("./tls/extension/supported_versions.zig");
const key_share = @import("./tls/extension/key_share.zig");
const Deque = @import("./deque.zig").Deque;
const Bytes = @import("./bytes.zig").Bytes;
const version = @import("./version.zig");
const assert = std.debug.assert;
const X25519 = std.crypto.dh.X25519;

pub const Cryptor = cryptor.Cryptor;

/// This type provides the QUIC implementation with the interface to interact with the TLS stack.
///
/// https://www.rfc-editor.org/rfc/rfc9001#name-carrying-tls-messages
/// https://www.rfc-editor.org/rfc/rfc9001#name-interface-to-tls
pub const Handshake = struct {
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

    /// The buffer to store the received handshake data sent from the peer per encryption level.
    recv_bufs: RecvBufs,

    /// The buffer to store the handshake data to be sent back to the peer per encryption level.
    send_bufs: SendBufs,

    /// The secret that is currently used to derive other secrets.
    /// This is set to `null` prior to calculating an early secret.
    ///
    /// We don't need to store the previous secrets as described in RFC 8446:
    /// https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1
    ///
    /// > Once all the values which are to be derived from a given secret have
    /// > been computed, that secret SHOULD be erased.
    current_secret: ?CurrentSecret = null,

    /// The concatenated handshake messages used to compute a transcript hash.
    ///
    /// https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.1
    ///
    /// > Many of the cryptographic computations in TLS make use of a
    /// > transcript hash.  This value is computed by hashing the concatenation
    /// > of each included handshake message, including the handshake message
    /// > header carrying the handshake message type and length fields, but not
    /// > including record layer headers.  I.e.,
    /// > Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
    concat_handshake_messages: ArrayList(u8),

    allocator: Allocator,

    const Self = @This();
    const RecvBufs = EnumArray(EncryptionLevel, ArrayList(u8));
    const SendBufs = EnumArray(EncryptionLevel, Deque(u8));
    const CurrentSecret = BoundedArray(u8, 64);

    pub fn init(allocator: Allocator, transport_params: TransportParameters) Allocator.Error!Self {
        var recv_bufs = recv: {
            var r = RecvBufs.initUndefined();
            inline for (std.meta.fields(EncryptionLevel)) |f| {
                const key = @field(EncryptionLevel, f.name);
                r.set(key, ArrayList(u8).init(allocator));
                errdefer r.get(key).deinit();
            }
            break :recv r;
        };
        var send_bufs = send: {
            var s = SendBufs.initUndefined();
            inline for (std.meta.fields(EncryptionLevel)) |f| {
                const key = @field(EncryptionLevel, f.name);
                s.set(key, try Deque(u8).init(allocator));
                errdefer s.get(key).deinit();
            }
            break :send s;
        };

        return Self{
            .transport_params = transport_params,
            .rx_encryption_level = .initial,
            .tx_encryption_level = .initial,
            .recv_bufs = recv_bufs,
            .send_bufs = send_bufs,
            .concat_handshake_messages = ArrayList(u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        self.recv_buf.deinit();
        self.send_buf.deinit();
        self.concat_handshake_messages.deinit();
    }

    /// Receive plain TLS handshake data sent from the peer.
    pub fn recv(self: *Self, enc_level: EncryptionLevel, plaintext: []const u8) Allocator.Error!void {
        try self.recv_bufs.getPtr(enc_level).appendSlice(plaintext);
    }

    /// Emit plain TLS handshake data to the given `buf`.
    pub fn emit(self: *Self, buf: []u8) usize {
        assert(buf.len > 0);

        var n_emit: usize = 0;

        while (self.send_buf.popFront()) |x| {
            buf[n_emit] = x;
            n_emit += 1;
            if (n_emit >= buf.len)
                break;
        }

        return n_emit;
    }

    /// Proceed with the handshake.
    /// When new key materials have become ready, they are returned; otherwise `null` is returned.
    pub fn proceed(self: *Self) !?KeyChange {
        // TODO(magurotuna): use appropriate encryption level to extract bufferred data
        var buf = Bytes{ .buf = self.recv_bufs.get(.initial).items };
        const hs = handshake.Handshake.decode(self.allocator, &buf) catch |e| switch (e) {
            // In case of `error.BufferTooShort` we need more data to successfully parse it a TLS handshake.
            error.BufferTooShort => return null,
            else => return e,
        };

        return try self.handleHandshakeMessage(hs);
    }

    fn handleHandshakeMessage(self: *Self, hs: handshake.Handshake) !?KeyChange {
        try self.appendHandshakeMessage(hs);
        return switch (hs) {
            .client_hello => |ch| try self.handleClientHello(ch),
            else => return error.Unimplemented,
        };
    }

    /// Generate ServerHello message based on information from ClientHello.
    fn handleClientHello(self: *Self, ch: client_hello.ClientHello) !?KeyChange {
        const suite = cipher_suite.pickCipherSuite(ch.cipher_suites.data.items) orelse
            return error.NoSupportedCipherSuite;

        var group_used: supported_groups.NamedGroup = undefined;
        var key_share_ent: key_share.KeyShareEntry = undefined;
        for (ch.extensions.data.items) |ext| {
            switch (ext) {
                .supported_groups => |groups| {
                    group_used = supported_groups.pickNamedGroup(groups.named_group_list.data.items) orelse
                        return error.NoSupportedNamedGroup;
                },
                .key_share => |shares| {
                    key_share_ent = key_share.pickKeyShareEntry(shares.client_shares.data.items) orelse
                        return error.NoSupportedNamedGroup;
                },
                else => {
                    // TODO(magurotuna)
                    return error.Unimplemented;
                },
            }
        }

        // TODO(magurotuna): For debugging purpose, we use fixed seed to create a key pair.
        // At some point we should change it to random values.
        const fixed_seed: [32]u8 = .{0x42} ** 32;
        const key_pair = try X25519.KeyPair.create(fixed_seed);

        // TODO(magurotuna): use random value
        const random: [32]u8 = .{0x42} ** 32;

        const sh_hs = handshake.Handshake{
            .server_hello = .{
                .random = random,
                .legacy_session_id_echo = ch.legacy_session_id,
                .cipher_suite = suite,

                // As RFC 8446 states, we send "supported_versions" and "key_share" extensions only in ServerHello.
                //
                // https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3
                //
                // > The ServerHello MUST only include
                // > extensions which are required to establish the cryptographic
                // > context and negotiate the protocol version.  All TLS 1.3
                // > ServerHello messages MUST contain the "supported_versions"
                // > extension.  Current ServerHello messages additionally contain
                // > either the "pre_shared_key" extension or the "key_share"
                // > extension, or both (when using a PSK with (EC)DHE key
                // > establishment).  Other extensions (see Section 4.2) are sent
                // > separately in the EncryptedExtensions message.
                .extensions = try server_hello.ServerHello.Extensions.fromSlice(self.allocator, &.{
                    .{
                        .supported_versions = .{
                            .selected_version = version.tls_v1_3,
                        },
                    },
                    .{
                        .key_share = .{
                            .server_share = .{
                                .group = .x25519,
                                .key_exchange = try key_share.KeyExchange.fromSlice(self.allocator, &key_pair.public_key),
                            },
                        },
                    },
                }),
            },
        };
        defer sh_hs.deinit();

        try self.writeToSendBuf(.initial, sh_hs);
        try self.appendHandshakeMessage(sh_hs);

        // Calculate shared secret with X25519.
        //
        // https://www.rfc-editor.org/rfc/rfc8446.html#section-7.4.2
        //
        // > The ECDH shared secret is the result of applying the ECDH scalar
        // > multiplication function to the secret key (into scalar input) and
        // > the peer's public key (into u-coordinate point input).  The output
        // > is used raw, with no processing.
        assert(key_share_ent.key_exchange.data.items.len == X25519.public_length);
        var client_public: [X25519.public_length]u8 = undefined;
        mem.copy(u8, &client_public, key_share_ent.key_exchange.data.items);
        const shared_secret = try X25519.scalarmult(key_pair.secret_key, client_public);

        // TODO(magurotuna): we support TLS_AES_128_GCM_SHA256 only for now.
        const TempSuite = cryptor.TLS_AES_128_GCM_SHA256;

        const early_secret = self.current_secret orelse early: {
            const e = derive.earlySecret(TempSuite, null);
            const s = try CurrentSecret.fromSlice(&e);
            self.current_secret = s;
            break :early s;
        };
        const handshake_secret = try derive.handshakeSecret(TempSuite, early_secret.constSlice(), &shared_secret);
        // Update the current secret with Handshake Secret.
        self.current_secret = try CurrentSecret.fromSlice(&handshake_secret);

        const client_handshake_traffic_secret = try derive.handshakeTrafficSecret(
            TempSuite,
            handshake_secret,
            self.concat_handshake_messages.items,
            false,
        );

        const server_handshake_traffic_secret = try derive.handshakeTrafficSecret(
            TempSuite,
            handshake_secret,
            self.concat_handshake_messages.items,
            true,
        );

        var encryptor = try TempSuite.fromSecret(self.allocator, server_handshake_traffic_secret);
        errdefer encryptor.deinit();
        var decryptor = try TempSuite.fromSecret(self.allocator, client_handshake_traffic_secret);
        errdefer decryptor.deinit();

        return .{
            .handshake = .{
                .keys = .{
                    .local = encryptor,
                    .remote = decryptor,
                },
            },
        };
    }

    /// Write the encoded handshake data into the send buffer with the specified encryption level.
    fn writeToSendBuf(self: *Self, enc_level: EncryptionLevel, hs: handshake.Handshake) !void {
        var hs_buf = try self.allocator.alloc(u8, hs.encodedLength());
        defer self.allocator.free(hs_buf);

        var hs_bytes = Bytes{ .buf = hs_buf };
        try hs.encode(&hs_bytes);
        try self.send_bufs.getPtr(enc_level).appendSlice(hs_bytes.split().former.buf);
    }

    /// Append the given handshake message to the end of `self.concat_handshake_messages`.
    fn appendHandshakeMessage(self: *Self, hs: handshake.Handshake) !void {
        var buf = try self.allocator.alloc(u8, hs.encodedLength());
        defer self.allocator.free(buf);
        var out = Bytes{ .buf = buf };
        try hs.encode(&out);
        try self.concat_handshake_messages.appendSlice(out.split().former.buf);
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
pub const EncryptionLevel = enum {
    initial,
    zero_rtt,
    handshake,
    application_data,
};

test {
    std.testing.refAllDecls(@This());
}
