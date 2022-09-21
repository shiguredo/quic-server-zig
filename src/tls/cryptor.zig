const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;
const Allocator = mem.Allocator;
const crypto = std.crypto;
const AuthenticationError = crypto.errors.AuthenticationError;
const Aes128 = crypto.core.aes.Aes128;
const Aes256 = crypto.core.aes.Aes256;
const ChaCha20IETF = crypto.stream.chacha.ChaCha20IETF;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha384 = crypto.hash.sha2.Sha384;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
const HmacSha384 = crypto.auth.hmac.sha2.HmacSha384;
const HkdfSha384 = crypto.kdf.hkdf.Hkdf(HmacSha384);
const derive = @import("./derive.zig");

/// `Cryptor` provides funtions to encrypt and decrypt QUIC packets.
pub const Cryptor = struct {
    impl: *anyopaque,
    vtable: *const VTable,

    const Self = @This();

    const VTable = struct {
        deinit: *const fn (suite: *anyopaque) void,
        protectHeader: *const fn (suite: *anyopaque, sample: [16]u8, first: *u8, packet_number: []u8) void,
        unprotectHeader: *const fn (suite: *anyopaque, sample: [16]u8, first: *u8, packet_number: []u8) void,
        encryptPayload: *const fn (suite: *anyopaque, packet_number: u64, header: []const u8, payload: []const u8, encrypted: []u8) [16]u8,
        decryptPayload: *const fn (suite: *anyopaque, packet_number: u64, header: []const u8, payload: []const u8, decrypted: []u8) AuthenticationError!void,
    };

    /// Create a new Cryptor instance.
    /// Make sure to call `deinit` method when the lifetime of `self` is about to finish.
    pub fn init(
        suite: anytype,
        comptime deinitFn: fn (suite: @TypeOf(suite)) void,
        comptime protectHeaderFn: fn (suite: @TypeOf(suite), sample: [16]u8, first: *u8, packet_number: []u8) void,
        comptime unprotectHeaderFn: fn (suite: @TypeOf(suite), sample: [16]u8, first: *u8, packet_number: []u8) void,
        comptime encryptPayloadFn: fn (suite: @TypeOf(suite), packet_number: u64, header: []const u8, payload: []const u8, encrypted: []u8) [16]u8,
        comptime decryptPayloadFn: fn (suite: @TypeOf(suite), packet_number: u64, header: []const u8, payload: []const u8, decrypted: []u8) AuthenticationError!void,
    ) Self {
        const Suite = @TypeOf(suite);
        const suite_info = @typeInfo(Suite);

        assert(suite_info == .Pointer); // Must be a pointer
        assert(suite_info.Pointer.size == .One); // Must be a single-item pointer

        const alignment = suite_info.Pointer.alignment;

        const gen = struct {
            fn deinitImpl(ptr: *anyopaque) void {
                const self = @ptrCast(Suite, @alignCast(alignment, ptr));
                deinitFn(self);
            }

            fn protectHeaderImpl(ptr: *anyopaque, sample: [16]u8, first: *u8, packet_number: []u8) void {
                const self = @ptrCast(Suite, @alignCast(alignment, ptr));
                protectHeaderFn(self, sample, first, packet_number);
            }

            fn unprotectHeaderImpl(ptr: *anyopaque, sample: [16]u8, first: *u8, packet_number: []u8) void {
                const self = @ptrCast(Suite, @alignCast(alignment, ptr));
                unprotectHeaderFn(self, sample, first, packet_number);
            }

            fn encryptPayloadImpl(ptr: *anyopaque, packet_number: u64, header: []const u8, payload: []const u8, encrypted: []u8) [16]u8 {
                const self = @ptrCast(Suite, @alignCast(alignment, ptr));
                return encryptPayloadFn(self, packet_number, header, payload, encrypted);
            }

            fn decryptPayloadImpl(ptr: *anyopaque, packet_number: u64, header: []const u8, payload: []const u8, decrypted: []u8) AuthenticationError!void {
                const self = @ptrCast(Suite, @alignCast(alignment, ptr));
                try decryptPayloadFn(self, packet_number, header, payload, decrypted);
            }

            const vtable = VTable{
                .deinit = deinitImpl,
                .protectHeader = protectHeaderImpl,
                .unprotectHeader = unprotectHeaderImpl,
                .encryptPayload = encryptPayloadImpl,
                .decryptPayload = decryptPayloadImpl,
            };
        };

        return .{
            .impl = suite,
            .vtable = &gen.vtable,
        };
    }

    /// Make sure to call `deinit` method when the lifetime of `self` is about to finish.
    pub fn deinit(self: *Self) void {
        self.vtable.deinit(self.impl);
    }

    pub fn protectHeader(self: Self, sample: [16]u8, first: *u8, packet_number: []u8) void {
        self.vtable.protectHeader(self.impl, sample, first, packet_number);
    }

    pub fn unprotectHeader(self: Self, sample: [16]u8, first: *u8, packet_number: []u8) void {
        self.vtable.unprotectHeader(self.impl, sample, first, packet_number);
    }

    pub fn encryptPayload(self: Self, packet_number: u64, header: []const u8, payload: []const u8, encrypted: []u8) [16]u8 {
        return self.vtable.encryptPayload(self.impl, packet_number, header, payload, encrypted);
    }

    pub fn decryptPayload(self: Self, packet_number: u64, header: []const u8, payload: []const u8, decrypted: []u8) AuthenticationError!void {
        try self.vtable.decryptPayload(self.impl, packet_number, header, payload, decrypted);
    }
};

pub const TLS_AES_128_GCM_SHA256 = struct {
    pub const Aead = Aes128Gcm;
    pub const Hmac = HmacSha256;
    pub const Hkdf = HkdfSha256;
    pub const Hash = Sha256;

    const Self = @This();

    secret: [Hmac.mac_length]u8,

    /// AEAD key
    aead_key: [Aead.key_length]u8,

    /// Initialization Vector
    iv: [Aead.nonce_length]u8,

    /// Header protection key
    hp: [Aead.key_length]u8,

    allocator: Allocator,

    pub fn fromSecret(allocator: Allocator, secret: [Hmac.mac_length]u8) !Cryptor {
        const aead_key = try derive.aeadKey(Self, secret);
        const iv = try derive.initializationVector(Self, secret);
        const hp = try derive.headerProtectionKey(Self, secret);
        var self = try allocator.create(Self);
        self.secret = secret;
        self.aead_key = aead_key;
        self.iv = iv;
        self.hp = hp;
        self.allocator = allocator;

        return Cryptor.init(self, deinit, protectHeader, unprotectHeader, encryptPayload, decryptPayload);
    }

    pub fn initial(allocator: Allocator, client_dcid: []const u8, is_server: bool) !Cryptor {
        const initial_secret = try derive.initialSecret(Self, client_dcid, is_server);
        return fromSecret(allocator, initial_secret);
    }

    fn deinit(self: *Self) void {
        self.allocator.destroy(self);
    }

    /// Apply the header protection to the first byte and packet number in the header.
    ///
    /// Algorithm in pseudo code:
    ///
    /// ```
    /// mask = header_protection(hp_key, sample)
    ///
    /// pn_length = (packet[0] & 0x03) + 1
    ///
    /// if (packet[0] & 0x80) == 0x80:
    ///    # Long header: 4 bits masked
    ///    packet[0] ^= mask[0] & 0x0f
    /// else:
    ///    # Short header: 5 bits masked
    ///    packet[0] ^= mask[0] & 0x1f
    ///
    /// # pn_offset is the start of the Packet Number field.
    /// packet[pn_offset:pn_offset+pn_length] ^= mask[1:1+pn_length]
    /// ```
    ///
    /// https://www.rfc-editor.org/rfc/rfc9001#name-header-protection-applicati
    /// https://www.rfc-editor.org/rfc/rfc9001#name-aes-based-header-protection
    fn protectHeader(self: *Self, sample: [16]u8, first: *u8, packet_number: []u8) void {
        const ctx = Aes128.initEnc(self.hp);
        var encrypted: [16]u8 = undefined;
        ctx.encrypt(&encrypted, &sample);
        const mask = encrypted[0..5];

        const pkt_len = (first.* & 0x03) + 1;

        if ((first.* & 0x80) == 0x80) {
            first.* ^= mask[0] & 0x0f;
        } else {
            first.* ^= mask[0] & 0x1f;
        }

        var i: usize = 0;
        while (i < pkt_len) : (i += 1) {
            packet_number[i] ^= mask[i + 1];
        }
    }

    /// Apply the header unprotection to the first byte and packet number in the header.
    ///
    /// Algorithm in pseudo code:
    ///
    /// ```
    /// mask = header_protection(hp_key, sample)
    ///
    /// if (packet[0] & 0x80) == 0x80:
    ///    # Long header: 4 bits masked
    ///    packet[0] ^= mask[0] & 0x0f
    /// else:
    ///    # Short header: 5 bits masked
    ///    packet[0] ^= mask[0] & 0x1f
    ///
    /// pn_length = (packet[0] & 0x03) + 1
    ///
    /// # pn_offset is the start of the Packet Number field.
    /// packet[pn_offset:pn_offset+pn_length] ^= mask[1:1+pn_length]
    /// ```
    ///
    /// https://www.rfc-editor.org/rfc/rfc9001#name-header-protection-applicati
    /// https://www.rfc-editor.org/rfc/rfc9001#name-aes-based-header-protection
    fn unprotectHeader(self: *Self, sample: [16]u8, first: *u8, packet_number: []u8) void {
        const ctx = Aes128.initEnc(self.hp);
        var encrypted: [16]u8 = undefined;
        ctx.encrypt(&encrypted, &sample);
        const mask = encrypted[0..5];

        if ((first.* & 0x80) == 0x80) {
            first.* ^= mask[0] & 0x0f;
        } else {
            first.* ^= mask[0] & 0x1f;
        }

        const pkt_len = (first.* & 0x03) + 1;

        var i: usize = 0;
        while (i < pkt_len) : (i += 1) {
            packet_number[i] ^= mask[i + 1];
        }
    }

    fn encryptPayload(
        self: *Self,
        packet_number: u64,
        header: []const u8,
        payload: []const u8,
        encrypted: []u8,
    ) [16]u8 {
        // https://www.rfc-editor.org/rfc/rfc9001#name-aead-usage
        //
        // The nonce, N, is formed by combining the packet protection IV with the packet number.
        // The 62 bits of the reconstructed QUIC packet number in network byte order are
        // left-padded with zeros to the size of the IV. The exclusive OR of the padded packet
        // number and the IV forms the AEAD nonce.
        const nonce = nonce: {
            var pn: [Aead.nonce_length]u8 = undefined;
            mem.writeIntSliceBig(u64, &pn, packet_number);
            var n: [Aead.nonce_length]u8 = undefined;
            for (n) |_, i| {
                n[i] = pn[i] ^ self.iv[i];
            }

            break :nonce n;
        };

        var tag: [16]u8 = undefined;
        Aead.encrypt(encrypted, &tag, payload, header, nonce, self.aead_key);
        return tag;
    }

    fn decryptPayload(
        self: *Self,
        packet_number: u64,
        header: []const u8,
        payload: []const u8,
        decrypted: []u8,
    ) AuthenticationError!void {
        const tag_len = Aead.tag_length;
        const payload_len = payload.len;

        assert(payload_len >= tag_len);

        const tag: [tag_len]u8 = tag: {
            var t: [tag_len]u8 = undefined;
            mem.copy(u8, &t, payload[(payload_len - tag_len)..payload_len]);
            break :tag t;
        };
        const ciphertext = payload[0..(payload_len - tag_len)];

        // https://www.rfc-editor.org/rfc/rfc9001#name-aead-usage
        //
        // The nonce, N, is formed by combining the packet protection IV with the packet number.
        // The 62 bits of the reconstructed QUIC packet number in network byte order are
        // left-padded with zeros to the size of the IV. The exclusive OR of the padded packet
        // number and the IV forms the AEAD nonce.
        const nonce = nonce: {
            var pn: [Aead.nonce_length]u8 = undefined;
            mem.writeIntSliceBig(u64, &pn, packet_number);
            var n: [Aead.nonce_length]u8 = undefined;
            for (n) |_, i| {
                n[i] = pn[i] ^ self.iv[i];
            }

            break :nonce n;
        };

        try Aead.decrypt(decrypted, ciphertext, tag, header, nonce, self.aead_key);
    }
};

test {
    _ = CryptorTest;
}

// Based on RFC 9001:
// https://www.rfc-editor.org/rfc/rfc9001#name-client-initial
const CryptorTest = struct {
    const allocator = std.testing.allocator;
    const client_initial_secret: [32]u8 = .{
        0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75,
        0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
        0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a,
        0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
    };
    const server_initial_secret: [32]u8 = .{
        0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd,
        0x21, 0x6c, 0x15, 0x5a, 0xd8, 0x44, 0xcc, 0x81,
        0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46, 0xfa, 0x7d,
        0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b,
    };

    test "protectHeader and unprotectHeader with client_initial_secret" {
        var cryptor = try TLS_AES_128_GCM_SHA256.fromSecret(allocator, client_initial_secret);
        defer cryptor.deinit();

        const sample: [16]u8 = .{
            0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
            0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b,
        };
        var first: u8 = 0xc3;
        var packet_number = [_]u8{ 0x00, 0x00, 0x00, 0x02 };

        cryptor.protectHeader(sample, &first, &packet_number);
        try std.testing.expectEqual(@as(u8, 0xc0), first);
        try std.testing.expectEqualSlices(u8, &.{ 0x7b, 0x9a, 0xec, 0x34 }, &packet_number);

        cryptor.unprotectHeader(sample, &first, &packet_number);
        try std.testing.expectEqual(@as(u8, 0xc3), first);
        try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00, 0x02 }, &packet_number);
    }

    test "protectHeader and unprotectHeader with server_initial_secret" {
        var cryptor = try TLS_AES_128_GCM_SHA256.fromSecret(allocator, server_initial_secret);
        defer cryptor.deinit();

        const sample: [16]u8 = .{
            0x2c, 0xd0, 0x99, 0x1c, 0xd2, 0x5b, 0x0a, 0xac,
            0x40, 0x6a, 0x58, 0x16, 0xb6, 0x39, 0x41, 0x00,
        };
        var first: u8 = 0xc1;
        var packet_number = [_]u8{ 0x00, 0x01 };

        cryptor.protectHeader(sample, &first, &packet_number);
        try std.testing.expectEqual(@as(u8, 0xcf), first);
        try std.testing.expectEqualSlices(u8, &.{ 0xc0, 0xd9 }, &packet_number);

        cryptor.unprotectHeader(sample, &first, &packet_number);
        try std.testing.expectEqual(@as(u8, 0xc1), first);
        try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01 }, &packet_number);
    }

    test "encryptPayload and decryptPayload with client_initial_secret" {
        var cryptor = try TLS_AES_128_GCM_SHA256.fromSecret(allocator, client_initial_secret);
        defer cryptor.deinit();

        const pkt_num = 2;
        const hdr = [_]u8{
            0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94,
            0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00,
            0x44, 0x9e, 0x00, 0x00, 0x00, 0x02,
        };
        var payload = payload: {
            const crypto_frame = [_]u8{
                0x06, 0x00, 0x40, 0xf1, 0x01, 0x00, 0x00, 0xed,
                0x03, 0x03, 0xeb, 0xf8, 0xfa, 0x56, 0xf1, 0x29,
                0x39, 0xb9, 0x58, 0x4a, 0x38, 0x96, 0x47, 0x2e,
                0xc4, 0x0b, 0xb8, 0x63, 0xcf, 0xd3, 0xe8, 0x68,
                0x04, 0xfe, 0x3a, 0x47, 0xf0, 0x6a, 0x2b, 0x69,
                0x48, 0x4c, 0x00, 0x00, 0x04, 0x13, 0x01, 0x13,
                0x02, 0x01, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
                0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b, 0x65, 0x78,
                0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
                0x6d, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a,
                0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17,
                0x00, 0x18, 0x00, 0x10, 0x00, 0x07, 0x00, 0x05,
                0x04, 0x61, 0x6c, 0x70, 0x6e, 0x00, 0x05, 0x00,
                0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33,
                0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
                0x93, 0x70, 0xb2, 0xc9, 0xca, 0xa4, 0x7f, 0xba,
                0xba, 0xf4, 0x55, 0x9f, 0xed, 0xba, 0x75, 0x3d,
                0xe1, 0x71, 0xfa, 0x71, 0xf5, 0x0f, 0x1c, 0xe1,
                0x5d, 0x43, 0xe9, 0x94, 0xec, 0x74, 0xd7, 0x48,
                0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00,
                0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x03, 0x05,
                0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08,
                0x05, 0x08, 0x06, 0x00, 0x2d, 0x00, 0x02, 0x01,
                0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00,
                0x39, 0x00, 0x32, 0x04, 0x08, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0x05, 0x04, 0x80,
                0x00, 0xff, 0xff, 0x07, 0x04, 0x80, 0x00, 0xff,
                0xff, 0x08, 0x01, 0x10, 0x01, 0x04, 0x80, 0x00,
                0x75, 0x30, 0x09, 0x01, 0x10, 0x0f, 0x08, 0x83,
                0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x06,
                0x04, 0x80, 0x00, 0xff, 0xff,
            };

            // PADDING frames are added to make the packet reach 1200 bytes, since clients MUST ensure that
            // UDP datagrams containing Initial packets have UDP payloads of at least 1200 bytes.
            // Note that `1162` is `1200 - header_size (22 bytes, in this case) - authentication_tag_size (16 bytes)`.
            //
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c
            // https://www.rfc-editor.org/rfc/rfc9001#name-client-initial
            const padding_frames = [_]u8{0x00} ** (1162 - crypto_frame.len);

            break :payload crypto_frame ++ padding_frames;
        };

        var encrypted: [payload.len]u8 = undefined;
        const tag = cryptor.encryptPayload(pkt_num, &hdr, &payload, &encrypted);
        try std.testing.expectEqualSlices(u8, &.{
            0xe2, 0x21, 0xaf, 0x44, 0x86, 0x00, 0x18, 0xab,
            0x08, 0x56, 0x97, 0x2e, 0x19, 0x4c, 0xd9, 0x34,
        }, &tag);

        var encrypted_with_tag: [payload.len + tag.len]u8 = undefined;
        mem.copy(u8, encrypted_with_tag[0..], &encrypted);
        mem.copy(u8, encrypted_with_tag[(encrypted_with_tag.len - tag.len)..], &tag);
        var decrypted: [payload.len]u8 = undefined;
        try cryptor.decryptPayload(pkt_num, &hdr, &encrypted_with_tag, &decrypted);

        // Ensure that encrypt and then decrypt gives us the original payload.
        try std.testing.expectEqualSlices(u8, &payload, &decrypted);
    }

    test "encryptPayload and decryptPayload with server_initial_secret" {
        var cryptor = try TLS_AES_128_GCM_SHA256.fromSecret(allocator, server_initial_secret);
        defer cryptor.deinit();

        const pkt_num = 1;
        const hdr = [_]u8{
            0xc1, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0,
            0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x00,
            0x40, 0x75, 0x00, 0x01,
        };
        const payload = [_]u8{
            0x02, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x40,
            0x5a, 0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0xee,
            0xfc, 0xe7, 0xf7, 0xb3, 0x7b, 0xa1, 0xd1, 0x63,
            0x2e, 0x96, 0x67, 0x78, 0x25, 0xdd, 0xf7, 0x39,
            0x88, 0xcf, 0xc7, 0x98, 0x25, 0xdf, 0x56, 0x6d,
            0xc5, 0x43, 0x0b, 0x9a, 0x04, 0x5a, 0x12, 0x00,
            0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00,
            0x24, 0x00, 0x1d, 0x00, 0x20, 0x9d, 0x3c, 0x94,
            0x0d, 0x89, 0x69, 0x0b, 0x84, 0xd0, 0x8a, 0x60,
            0x99, 0x3c, 0x14, 0x4e, 0xca, 0x68, 0x4d, 0x10,
            0x81, 0x28, 0x7c, 0x83, 0x4d, 0x53, 0x11, 0xbc,
            0xf3, 0x2b, 0xb9, 0xda, 0x1a, 0x00, 0x2b, 0x00,
            0x02, 0x03, 0x04,
        };

        var encrypted: [payload.len]u8 = undefined;
        const tag = cryptor.encryptPayload(pkt_num, &hdr, &payload, &encrypted);
        try std.testing.expectEqualSlices(u8, &.{
            0x3d, 0x20, 0x39, 0x8c, 0x27, 0x64, 0x56, 0xcb,
            0xc4, 0x21, 0x58, 0x40, 0x7d, 0xd0, 0x74, 0xee,
        }, &tag);

        var encrypted_with_tag: [payload.len + tag.len]u8 = undefined;
        mem.copy(u8, encrypted_with_tag[0..], &encrypted);
        mem.copy(u8, encrypted_with_tag[(encrypted_with_tag.len - tag.len)..], &tag);
        var decrypted: [payload.len]u8 = undefined;
        try cryptor.decryptPayload(pkt_num, &hdr, &encrypted_with_tag, &decrypted);

        // Ensure that encrypt and then decrypt gives us the original payload.
        try std.testing.expectEqualSlices(u8, &payload, &decrypted);
    }
};
