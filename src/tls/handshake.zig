const std = @import("std");
const Bytes = @import("../bytes.zig").Bytes;
const utils = @import("../utils.zig");
const ClientHello = @import("./client_hello.zig").ClientHello;
const ServerHello = @import("./server_hello.zig").ServerHello;
const EncryptedExtensions = @import("./encrypted_extensions.zig").EncryptedExtensions;
const Certificate = @import("./certificate.zig").Certificate;
const CertificateVerify = @import("./certificate_verify.zig").CertificateVerify;
const Finished = @import("./finished.zig").Finished;

/// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.3
///
/// enum {
///     hello_request_RESERVED(0),
///     client_hello(1),
///     server_hello(2),
///     hello_verify_request_RESERVED(3),
///     new_session_ticket(4),
///     end_of_early_data(5),
///     hello_retry_request_RESERVED(6),
///     encrypted_extensions(8),
///     certificate(11),
///     server_key_exchange_RESERVED(12),
///     certificate_request(13),
///     server_hello_done_RESERVED(14),
///     certificate_verify(15),
///     client_key_exchange_RESERVED(16),
///     finished(20),
///     certificate_url_RESERVED(21),
///     certificate_status_RESERVED(22),
///     supplemental_data_RESERVED(23),
///     key_update(24),
///     message_hash(254),
///     (255)
/// } HandshakeType;
pub const HandshakeType = enum(u8) {
    hello_request_RESERVED = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request_RESERVED = 3,
    new_session_ticket = 4,
    end_of_early_data = 5,
    hello_retry_request_RESERVED = 6,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange_RESERVED = 12,
    certificate_request = 13,
    server_hello_done_RESERVED = 14,
    certificate_verify = 15,
    client_key_exchange_RESERVED = 16,
    finished = 20,
    certificate_url_RESERVED = 21,
    certificate_status_RESERVED = 22,
    supplemental_data_RESERVED = 23,
    key_update = 24,
    message_hash = 254,

    const Self = @This();
    const TagType = @typeInfo(Self).Enum.tag_type;
};

const Reserved = struct {};
const NoContent = struct {};

// TODO(magurotuna): implement these handshake message types
pub const EndOfEarlyData = struct {};
pub const KeyUpdate = struct {};

/// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.3
///
/// struct {
///     HandshakeType msg_type;    /* handshake type */
///     uint24 length;             /* bytes in message */
///     select (Handshake.msg_type) {
///         case client_hello:          ClientHello;
///         case server_hello:          ServerHello;
///         case end_of_early_data:     EndOfEarlyData;
///         case encrypted_extensions:  EncryptedExtensions;
///         case certificate_request:   CertificateRequest;
///         case certificate:           Certificate;
///         case certificate_verify:    CertificateVerify;
///         case finished:              Finished;
///         case new_session_ticket:    NewSessionTicket;
///         case key_update:            KeyUpdate;
///     };
/// } Handshake;
pub const Handshake = union(HandshakeType) {
    hello_request_RESERVED: Reserved,
    client_hello: ClientHello,
    server_hello: ServerHello,
    hello_verify_request_RESERVED: Reserved,
    new_session_ticket: NoContent,
    end_of_early_data: EndOfEarlyData,
    hello_retry_request_RESERVED: Reserved,
    encrypted_extensions: EncryptedExtensions,
    certificate: Certificate,
    server_key_exchange_RESERVED: Reserved,
    certificate_request: NoContent,
    server_hello_done_RESERVED: Reserved,
    certificate_verify: CertificateVerify,
    client_key_exchange_RESERVED: Reserved,
    finished: Finished,
    certificate_url_RESERVED: Reserved,
    certificate_status_RESERVED: Reserved,
    supplemental_data_RESERVED: Reserved,
    key_update: KeyUpdate,
    message_hash: NoContent,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        var len: usize = 0;
        len += utils.sizeOf(HandshakeType.TagType);
        len += utils.sizeOf(u24);
        len += switch (self) {
            .client_hello => |ch| ch.encodedLength(),
            .server_hello => |sh| sh.encodedLength(),
            .encrypted_extensions => |ee| ee.encodedLength(),
            .certificate => |cert| cert.encodedLength(),
            .certificate_verify => |cv| cv.encodedLength(),
            .finished => |fi| fi.encodedLength(),
            // TODO(magurotuna): implement
            else => unreachable,
        };
        return len;
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        try out.put(HandshakeType.TagType, @enumToInt(self));
        try out.put(u24, @intCast(u24, switch (self) {
            .client_hello => |ch| ch.encodedLength(),
            .server_hello => |sh| sh.encodedLength(),
            .encrypted_extensions => |ee| ee.encodedLength(),
            .certificate => |cert| cert.encodedLength(),
            .certificate_verify => |cv| cv.encodedLength(),
            .finished => |fi| fi.encodedLength(),
            // TODO(magurotuna): implement
            else => unreachable,
        }));

        switch (self) {
            .client_hello => |ch| try ch.encode(out),
            .server_hello => |sh| try sh.encode(out),
            .encrypted_extensions => |ee| try ee.encode(out),
            .certificate => |cert| try cert.encode(out),
            .certificate_verify => |cv| try cv.encode(out),
            .finished => |fi| try fi.encode(out),
            // TODO(magurotuna): implement
            else => unreachable,
        }
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        const ty = try in.consume(HandshakeType.TagType);
        const length = try in.consume(u24);
        var data_buf = Bytes{ .buf = try in.consumeBytes(@intCast(usize, length)) };

        return switch (@intToEnum(HandshakeType, ty)) {
            .client_hello => .{ .client_hello = try ClientHello.decode(allocator, &data_buf) },
            .server_hello => .{ .server_hello = try ServerHello.decode(allocator, &data_buf) },
            // TODO(magurotuna): implement
            else => unreachable,
        };
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            .client_hello => |ch| ch.deinit(),
            .server_hello => |sh| sh.deinit(),
            .encrypted_extensions => |ee| ee.deinit(),
            .certificate => |cert| cert.deinit(),
            .certificate_verify => |cv| cv.deinit(),
            .finished => |fi| fi.deinit(),
            // TODO(magurotuna): implement
            else => unreachable,
        }
    }
};

test "Handshake (ClientHello) encode" {
    const ch = Handshake{
        .client_hello = .{
            .random = .{0x42} ** 32,
            .legacy_session_id = try ClientHello.LegacySessionId.fromSlice(std.testing.allocator, &.{0x01}),
            .cipher_suites = try ClientHello.CipherSuites.fromSlice(std.testing.allocator, &.{ .TLS_AES_128_GCM_SHA256, .TLS_CHACHA20_POLY1305_SHA256 }),
            .legacy_compression_methods = try ClientHello.LegacyCompressionMethods.fromSlice(std.testing.allocator, &.{0x02}),
            .extensions = try ClientHello.Extensions.fromSlice(std.testing.allocator, &.{}),
        },
    };
    defer ch.deinit();

    var buf: [1024]u8 = undefined;
    var out = Bytes{ .buf = &buf };

    try ch.encode(&out);

    // zig fmt: off
    try std.testing.expectEqualSlices(u8, &.{
        // msg_type
        0x01,
        // length
        0x00, 0x00, 0x2e,

        // Client Hello
        0x03, 0x03,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x01, 0x01,
        0x00, 0x04, 0x13, 0x01, 0x13, 0x03,
        0x01, 0x02,
        0x00, 0x00,
    }, out.split().former.buf);
    // zig fmt: on
}

test "Handshake (ClientHello) decode" {
    // Brought from https://www.rfc-editor.org/rfc/rfc8448#section-3
    // but a little bit changed a part of TLS extensions so that it is suitable for QUIC
    // zig fmt: off
    var buf = [_]u8{
        0x01, // msg_type
        0x00, 0x00, 0xb8, // length

        // Client Hello

        // legacy_version
        0x03, 0x03,

        // random
        0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81, 0x63, 0xba,
        0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d,
        0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12, 0xec, 0x18,
        0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7,

        // legacy_session_id
        0x00,

        // cipher_suites
        0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02,

        // legacy_compression_methods
        0x01, 0x00,

        // extensions
        0x00, 0x89, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09,
        0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65,
        0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a,
        0x00, 0x14, 0x00, 0x12, 0x00, 0x1d, 0x00, 0x17,
        0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01,
        0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x23,
        0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
        0x00, 0x1d, 0x00, 0x20, 0x99, 0x38, 0x1d, 0xe5,
        0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43,
        0x5a, 0x7d, 0xba, 0xfe, 0xb3, 0xc0, 0x6e, 0x51,
        0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e,
        0x52, 0x9a, 0xaf, 0x2c, 0x00, 0x2b, 0x00, 0x03,
        0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x18, 0x00,
        0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02,
        0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04,
        0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x00,
        0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00,
        0x02, 0x40, 0x01,
    };
    // zig fmt: on

    var in = Bytes{ .buf = &buf };
    const got = try Handshake.decode(std.testing.allocator, &in);
    defer got.deinit();
    try std.testing.expect(got == .client_hello);
}
