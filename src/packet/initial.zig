const std = @import("std");
const mem = std.mem;
const log = std.log;
const ArrayList = std.ArrayList;
const Bytes = @import("../bytes.zig").Bytes;
const isSupported = @import("../version.zig").isSupported;
const max_cid_len = @import("../packet.zig").max_cid_len;
const crypto = @import("../crypto.zig");
const Aes128 = std.crypto.core.aes.Aes128;

/// An Initial Packet
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-initial-packet
/// https://www.rfc-editor.org/rfc/rfc9001#name-header-protection-applicati
///
/// Initial Packet {
///     Header Form (1) = 1,
///     Fixed Bit (1) = 1,
///     Long Packet Type (2) = 0,
///     Reserved Bits (2),         # Protected
///     Packet Number Length (2),  # Protected
///     Version (32),
///     Destination Connection ID Length (8),
///     Destination Connection ID (0..160),
///     Source Connection ID Length (8),
///     Source Connection ID (0..160),
///     Token Length (i),
///     Token (..),
///     Length (i),
///     Packet Number (8..32),     # Protected
///     Packet Payload (8..),      # Encrypted
/// }
pub const Initial = struct {
    /// QUIC version identifier.
    version: u32,
    /// Destination connection ID of the packet.
    /// Although in QUIC v1 the maximum length is 20 bytes, the implementation should
    /// accept Connection ID with its length being over 20 bytes so it can handle QUIC
    /// packets of future versions, as explained here: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-3.12.1
    /// So we use `ArrayList(u8)` rather than `BoundedArray(u8, 20)`.
    destination_connection_id: ArrayList(u8),
    /// Source connection ID of the packet.
    /// Although in QUIC v1 the maximum length is 20 bytes, the implementation should
    /// accept Connection ID with its length being over 20 bytes so it can handle QUIC
    /// packets of future versions, as explained here: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-3.12.1
    /// So we use `ArrayList(u8)` rather than `BoundedArray(u8, 20)`.
    source_connection_id: ArrayList(u8),
    /// Address verification token.
    token: ArrayList(u8),
    /// Packet number.
    packet_number: u32,
    /// Payload of the packet.
    payload: ArrayList(u8),

    const Self = @This();

    /// Decodes the input bytes, assuming that the bytes are coming from a client, not from a server.
    pub fn fromBytes(allocator: std.mem.Allocator, bs: *Bytes, first_byte: u8, version: u32) !Self {
        // Ensure that `bs` has read the first byte (u8) and the version information (u32)
        std.debug.assert(bs.pos == @sizeOf(u8) + @sizeOf(u32));

        const dcid_len = try bs.consume(u8);
        log.debug("destination connection id length: {}\n", .{dcid_len});
        if (isSupported(version) and dcid_len > max_cid_len)
            return error.InvalidPacket;

        const dcid = try bs.consumeBytesOwned(allocator, dcid_len);
        log.debug("destination connection id: {}\n", .{std.fmt.fmtSliceHexLower(dcid.items)});
        errdefer dcid.deinit();

        const scid_len = try bs.consume(u8);
        log.debug("source connection id length: {}\n", .{scid_len});
        if (isSupported(version) and scid_len > max_cid_len)
            return error.InvalidPacket;

        const scid = try bs.consumeBytesOwned(allocator, scid_len);
        log.debug("source connection id: {}\n", .{std.fmt.fmtSliceHexLower(scid.items)});
        errdefer scid.deinit();

        const token = try bs.consumeBytesOwnedWithVarIntLength(allocator);
        errdefer token.deinit();

        const packet_number_and_payload = try bs.consumeBytesOwnedWithVarIntLength(allocator);
        defer packet_number_and_payload.deinit();

        // The original byte stream `bs` might contain multiple QUIC packets. We want to decode
        // one packet at the moment, so we create another `Bytes` that views only one packet we're focusing on.
        var packet_bytes = Bytes{ .buf = bs.buf[0..bs.pos] };
        log.debug("packet bytes: {}\n", .{std.fmt.fmtSliceHexLower(packet_bytes.buf)});

        // https://www.rfc-editor.org/rfc/rfc9001#name-header-protection-sample
        const sample_length = 16;
        const sample = packet_number_and_payload.items[4..(4 + sample_length)];

        const mask = try crypto.getClientHeaderProtectionMask(Aes128, dcid.items, sample);
        const unprotected_first = first_byte ^ (mask[0] & 0x1f);
        const packet_number_length = (unprotected_first & 0x03) + 1;
        log.debug("packet number length: {}\n", .{packet_number_length});

        const packet_number = blk: {
            const max_packet_number_length = 4;
            var pn = [_]u8{0x00} ** max_packet_number_length;
            var i: usize = 0;
            while (i < packet_number_length) : (i += 1) {
                pn[i] = packet_number_and_payload.items[i] ^ mask[1 + i];
            }
            log.debug("magurotuna pn: {}\n", .{std.fmt.fmtSliceHexLower(&pn)});
            break :blk mem.readVarInt(u32, pn[0..packet_number_length], .Big);
        };
        log.debug("packet number: {}\n", .{packet_number});

        const payload = blk: {
            const encrypted_payload = packet_number_and_payload.items[packet_number_length..];

            const unprotected_header = hdr: {
                // Set unprotected first byte
                const h = packet_bytes.buf[0..(packet_bytes.buf.len - encrypted_payload.len)];
                h[0] = unprotected_first;

                // Set unprotected Packet Number field.
                // First we encode the raw (unprotected) packet number as a big-endian u32 value,
                // then mutate the Packet Number space with the subarray of the encoded packet number,
                // whose length is equal to `packet_number_length`.
                var pn_big_endian: [4]u8 = undefined;
                mem.writeIntBig(u32, &pn_big_endian, packet_number);
                const sub = pn_big_endian[(pn_big_endian.len - packet_number_length)..];
                var packet_number_space = h[(h.len - packet_number_length)..];
                mem.copy(u8, packet_number_space, sub);

                break :hdr h;
            };

            break :blk try crypto.decryptPayload(allocator, encrypted_payload, unprotected_header, packet_number, dcid.items);
        };
        errdefer payload.deinit();

        return Self{
            .version = version,
            .destination_connection_id = dcid,
            .source_connection_id = scid,
            .token = token,
            .packet_number = packet_number,
            .payload = payload,
        };
    }

    pub fn deinit(self: Self) void {
        self.destination_connection_id.deinit();
        self.source_connection_id.deinit();
        self.token.deinit();
        self.payload.deinit();
    }
};

test "decode Client Initial" {
    // https://www.rfc-editor.org/rfc/rfc9001#name-client-initial
    // zig fmt: off
    var in = [_]u8{
        ///////////////////////////////////////////////
        // header
        ///////////////////////////////////////////////
        0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94,
        0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00,
        0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34,

        ///////////////////////////////////////////////
        // payload
        ///////////////////////////////////////////////
                                            0xd1, 0xb1,
        0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11,
        0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b, 0xd8, 0xba,
        0xb9, 0x36, 0xb4, 0x7d, 0x92, 0xec, 0x35, 0x6c,
        0x0b, 0xab, 0x7d, 0xf5, 0x97, 0x6d, 0x27, 0xcd,
        0x44, 0x9f, 0x63, 0x30, 0x00, 0x99, 0xf3, 0x99,
        0x1c, 0x26, 0x0e, 0xc4, 0xc6, 0x0d, 0x17, 0xb3,
        0x1f, 0x84, 0x29, 0x15, 0x7b, 0xb3, 0x5a, 0x12,
        0x82, 0xa6, 0x43, 0xa8, 0xd2, 0x26, 0x2c, 0xad,
        0x67, 0x50, 0x0c, 0xad, 0xb8, 0xe7, 0x37, 0x8c,
        0x8e, 0xb7, 0x53, 0x9e, 0xc4, 0xd4, 0x90, 0x5f,
        0xed, 0x1b, 0xee, 0x1f, 0xc8, 0xaa, 0xfb, 0xa1,
        0x7c, 0x75, 0x0e, 0x2c, 0x7a, 0xce, 0x01, 0xe6,
        0x00, 0x5f, 0x80, 0xfc, 0xb7, 0xdf, 0x62, 0x12,
        0x30, 0xc8, 0x37, 0x11, 0xb3, 0x93, 0x43, 0xfa,
        0x02, 0x8c, 0xea, 0x7f, 0x7f, 0xb5, 0xff, 0x89,
        0xea, 0xc2, 0x30, 0x82, 0x49, 0xa0, 0x22, 0x52,
        0x15, 0x5e, 0x23, 0x47, 0xb6, 0x3d, 0x58, 0xc5,
        0x45, 0x7a, 0xfd, 0x84, 0xd0, 0x5d, 0xff, 0xfd,
        0xb2, 0x03, 0x92, 0x84, 0x4a, 0xe8, 0x12, 0x15,
        0x46, 0x82, 0xe9, 0xcf, 0x01, 0x2f, 0x90, 0x21,
        0xa6, 0xf0, 0xbe, 0x17, 0xdd, 0xd0, 0xc2, 0x08,
        0x4d, 0xce, 0x25, 0xff, 0x9b, 0x06, 0xcd, 0xe5,
        0x35, 0xd0, 0xf9, 0x20, 0xa2, 0xdb, 0x1b, 0xf3,
        0x62, 0xc2, 0x3e, 0x59, 0x6d, 0x11, 0xa4, 0xf5,
        0xa6, 0xcf, 0x39, 0x48, 0x83, 0x8a, 0x3a, 0xec,
        0x4e, 0x15, 0xda, 0xf8, 0x50, 0x0a, 0x6e, 0xf6,
        0x9e, 0xc4, 0xe3, 0xfe, 0xb6, 0xb1, 0xd9, 0x8e,
        0x61, 0x0a, 0xc8, 0xb7, 0xec, 0x3f, 0xaf, 0x6a,
        0xd7, 0x60, 0xb7, 0xba, 0xd1, 0xdb, 0x4b, 0xa3,
        0x48, 0x5e, 0x8a, 0x94, 0xdc, 0x25, 0x0a, 0xe3,
        0xfd, 0xb4, 0x1e, 0xd1, 0x5f, 0xb6, 0xa8, 0xe5,
        0xeb, 0xa0, 0xfc, 0x3d, 0xd6, 0x0b, 0xc8, 0xe3,
        0x0c, 0x5c, 0x42, 0x87, 0xe5, 0x38, 0x05, 0xdb,
        0x05, 0x9a, 0xe0, 0x64, 0x8d, 0xb2, 0xf6, 0x42,
        0x64, 0xed, 0x5e, 0x39, 0xbe, 0x2e, 0x20, 0xd8,
        0x2d, 0xf5, 0x66, 0xda, 0x8d, 0xd5, 0x99, 0x8c,
        0xca, 0xbd, 0xae, 0x05, 0x30, 0x60, 0xae, 0x6c,
        0x7b, 0x43, 0x78, 0xe8, 0x46, 0xd2, 0x9f, 0x37,
        0xed, 0x7b, 0x4e, 0xa9, 0xec, 0x5d, 0x82, 0xe7,
        0x96, 0x1b, 0x7f, 0x25, 0xa9, 0x32, 0x38, 0x51,
        0xf6, 0x81, 0xd5, 0x82, 0x36, 0x3a, 0xa5, 0xf8,
        0x99, 0x37, 0xf5, 0xa6, 0x72, 0x58, 0xbf, 0x63,
        0xad, 0x6f, 0x1a, 0x0b, 0x1d, 0x96, 0xdb, 0xd4,
        0xfa, 0xdd, 0xfc, 0xef, 0xc5, 0x26, 0x6b, 0xa6,
        0x61, 0x17, 0x22, 0x39, 0x5c, 0x90, 0x65, 0x56,
        0xbe, 0x52, 0xaf, 0xe3, 0xf5, 0x65, 0x63, 0x6a,
        0xd1, 0xb1, 0x7d, 0x50, 0x8b, 0x73, 0xd8, 0x74,
        0x3e, 0xeb, 0x52, 0x4b, 0xe2, 0x2b, 0x3d, 0xcb,
        0xc2, 0xc7, 0x46, 0x8d, 0x54, 0x11, 0x9c, 0x74,
        0x68, 0x44, 0x9a, 0x13, 0xd8, 0xe3, 0xb9, 0x58,
        0x11, 0xa1, 0x98, 0xf3, 0x49, 0x1d, 0xe3, 0xe7,
        0xfe, 0x94, 0x2b, 0x33, 0x04, 0x07, 0xab, 0xf8,
        0x2a, 0x4e, 0xd7, 0xc1, 0xb3, 0x11, 0x66, 0x3a,
        0xc6, 0x98, 0x90, 0xf4, 0x15, 0x70, 0x15, 0x85,
        0x3d, 0x91, 0xe9, 0x23, 0x03, 0x7c, 0x22, 0x7a,
        0x33, 0xcd, 0xd5, 0xec, 0x28, 0x1c, 0xa3, 0xf7,
        0x9c, 0x44, 0x54, 0x6b, 0x9d, 0x90, 0xca, 0x00,
        0xf0, 0x64, 0xc9, 0x9e, 0x3d, 0xd9, 0x79, 0x11,
        0xd3, 0x9f, 0xe9, 0xc5, 0xd0, 0xb2, 0x3a, 0x22,
        0x9a, 0x23, 0x4c, 0xb3, 0x61, 0x86, 0xc4, 0x81,
        0x9e, 0x8b, 0x9c, 0x59, 0x27, 0x72, 0x66, 0x32,
        0x29, 0x1d, 0x6a, 0x41, 0x82, 0x11, 0xcc, 0x29,
        0x62, 0xe2, 0x0f, 0xe4, 0x7f, 0xeb, 0x3e, 0xdf,
        0x33, 0x0f, 0x2c, 0x60, 0x3a, 0x9d, 0x48, 0xc0,
        0xfc, 0xb5, 0x69, 0x9d, 0xbf, 0xe5, 0x89, 0x64,
        0x25, 0xc5, 0xba, 0xc4, 0xae, 0xe8, 0x2e, 0x57,
        0xa8, 0x5a, 0xaf, 0x4e, 0x25, 0x13, 0xe4, 0xf0,
        0x57, 0x96, 0xb0, 0x7b, 0xa2, 0xee, 0x47, 0xd8,
        0x05, 0x06, 0xf8, 0xd2, 0xc2, 0x5e, 0x50, 0xfd,
        0x14, 0xde, 0x71, 0xe6, 0xc4, 0x18, 0x55, 0x93,
        0x02, 0xf9, 0x39, 0xb0, 0xe1, 0xab, 0xd5, 0x76,
        0xf2, 0x79, 0xc4, 0xb2, 0xe0, 0xfe, 0xb8, 0x5c,
        0x1f, 0x28, 0xff, 0x18, 0xf5, 0x88, 0x91, 0xff,
        0xef, 0x13, 0x2e, 0xef, 0x2f, 0xa0, 0x93, 0x46,
        0xae, 0xe3, 0x3c, 0x28, 0xeb, 0x13, 0x0f, 0xf2,
        0x8f, 0x5b, 0x76, 0x69, 0x53, 0x33, 0x41, 0x13,
        0x21, 0x19, 0x96, 0xd2, 0x00, 0x11, 0xa1, 0x98,
        0xe3, 0xfc, 0x43, 0x3f, 0x9f, 0x25, 0x41, 0x01,
        0x0a, 0xe1, 0x7c, 0x1b, 0xf2, 0x02, 0x58, 0x0f,
        0x60, 0x47, 0x47, 0x2f, 0xb3, 0x68, 0x57, 0xfe,
        0x84, 0x3b, 0x19, 0xf5, 0x98, 0x40, 0x09, 0xdd,
        0xc3, 0x24, 0x04, 0x4e, 0x84, 0x7a, 0x4f, 0x4a,
        0x0a, 0xb3, 0x4f, 0x71, 0x95, 0x95, 0xde, 0x37,
        0x25, 0x2d, 0x62, 0x35, 0x36, 0x5e, 0x9b, 0x84,
        0x39, 0x2b, 0x06, 0x10, 0x85, 0x34, 0x9d, 0x73,
        0x20, 0x3a, 0x4a, 0x13, 0xe9, 0x6f, 0x54, 0x32,
        0xec, 0x0f, 0xd4, 0xa1, 0xee, 0x65, 0xac, 0xcd,
        0xd5, 0xe3, 0x90, 0x4d, 0xf5, 0x4c, 0x1d, 0xa5,
        0x10, 0xb0, 0xff, 0x20, 0xdc, 0xc0, 0xc7, 0x7f,
        0xcb, 0x2c, 0x0e, 0x0e, 0xb6, 0x05, 0xcb, 0x05,
        0x04, 0xdb, 0x87, 0x63, 0x2c, 0xf3, 0xd8, 0xb4,
        0xda, 0xe6, 0xe7, 0x05, 0x76, 0x9d, 0x1d, 0xe3,
        0x54, 0x27, 0x01, 0x23, 0xcb, 0x11, 0x45, 0x0e,
        0xfc, 0x60, 0xac, 0x47, 0x68, 0x3d, 0x7b, 0x8d,
        0x0f, 0x81, 0x13, 0x65, 0x56, 0x5f, 0xd9, 0x8c,
        0x4c, 0x8e, 0xb9, 0x36, 0xbc, 0xab, 0x8d, 0x06,
        0x9f, 0xc3, 0x3b, 0xd8, 0x01, 0xb0, 0x3a, 0xde,
        0xa2, 0xe1, 0xfb, 0xc5, 0xaa, 0x46, 0x3d, 0x08,
        0xca, 0x19, 0x89, 0x6d, 0x2b, 0xf5, 0x9a, 0x07,
        0x1b, 0x85, 0x1e, 0x6c, 0x23, 0x90, 0x52, 0x17,
        0x2f, 0x29, 0x6b, 0xfb, 0x5e, 0x72, 0x40, 0x47,
        0x90, 0xa2, 0x18, 0x10, 0x14, 0xf3, 0xb9, 0x4a,
        0x4e, 0x97, 0xd1, 0x17, 0xb4, 0x38, 0x13, 0x03,
        0x68, 0xcc, 0x39, 0xdb, 0xb2, 0xd1, 0x98, 0x06,
        0x5a, 0xe3, 0x98, 0x65, 0x47, 0x92, 0x6c, 0xd2,
        0x16, 0x2f, 0x40, 0xa2, 0x9f, 0x0c, 0x3c, 0x87,
        0x45, 0xc0, 0xf5, 0x0f, 0xba, 0x38, 0x52, 0xe5,
        0x66, 0xd4, 0x45, 0x75, 0xc2, 0x9d, 0x39, 0xa0,
        0x3f, 0x0c, 0xda, 0x72, 0x19, 0x84, 0xb6, 0xf4,
        0x40, 0x59, 0x1f, 0x35, 0x5e, 0x12, 0xd4, 0x39,
        0xff, 0x15, 0x0a, 0xab, 0x76, 0x13, 0x49, 0x9d,
        0xbd, 0x49, 0xad, 0xab, 0xc8, 0x67, 0x6e, 0xef,
        0x02, 0x3b, 0x15, 0xb6, 0x5b, 0xfc, 0x5c, 0xa0,
        0x69, 0x48, 0x10, 0x9f, 0x23, 0xf3, 0x50, 0xdb,
        0x82, 0x12, 0x35, 0x35, 0xeb, 0x8a, 0x74, 0x33,
        0xbd, 0xab, 0xcb, 0x90, 0x92, 0x71, 0xa6, 0xec,
        0xbc, 0xb5, 0x8b, 0x93, 0x6a, 0x88, 0xcd, 0x4e,
        0x8f, 0x2e, 0x6f, 0xf5, 0x80, 0x01, 0x75, 0xf1,
        0x13, 0x25, 0x3d, 0x8f, 0xa9, 0xca, 0x88, 0x85,
        0xc2, 0xf5, 0x52, 0xe6, 0x57, 0xdc, 0x60, 0x3f,
        0x25, 0x2e, 0x1a, 0x8e, 0x30, 0x8f, 0x76, 0xf0,
        0xbe, 0x79, 0xe2, 0xfb, 0x8f, 0x5d, 0x5f, 0xbb,
        0xe2, 0xe3, 0x0e, 0xca, 0xdd, 0x22, 0x07, 0x23,
        0xc8, 0xc0, 0xae, 0xa8, 0x07, 0x8c, 0xdf, 0xcb,
        0x38, 0x68, 0x26, 0x3f, 0xf8, 0xf0, 0x94, 0x00,
        0x54, 0xda, 0x48, 0x78, 0x18, 0x93, 0xa7, 0xe4,
        0x9a, 0xd5, 0xaf, 0xf4, 0xaf, 0x30, 0x0c, 0xd8,
        0x04, 0xa6, 0xb6, 0x27, 0x9a, 0xb3, 0xff, 0x3a,
        0xfb, 0x64, 0x49, 0x1c, 0x85, 0x19, 0x4a, 0xab,
        0x76, 0x0d, 0x58, 0xa6, 0x06, 0x65, 0x4f, 0x9f,
        0x44, 0x00, 0xe8, 0xb3, 0x85, 0x91, 0x35, 0x6f,
        0xbf, 0x64, 0x25, 0xac, 0xa2, 0x6d, 0xc8, 0x52,
        0x44, 0x25, 0x9f, 0xf2, 0xb1, 0x9c, 0x41, 0xb9,
        0xf9, 0x6f, 0x3c, 0xa9, 0xec, 0x1d, 0xde, 0x43,
        0x4d, 0xa7, 0xd2, 0xd3, 0x92, 0xb9, 0x05, 0xdd,
        0xf3, 0xd1, 0xf9, 0xaf, 0x93, 0xd1, 0xaf, 0x59,
        0x50, 0xbd, 0x49, 0x3f, 0x5a, 0xa7, 0x31, 0xb4,
        0x05, 0x6d, 0xf3, 0x1b, 0xd2, 0x67, 0xb6, 0xb9,
        0x0a, 0x07, 0x98, 0x31, 0xaa, 0xf5, 0x79, 0xbe,
        0x0a, 0x39, 0x01, 0x31, 0x37, 0xaa, 0xc6, 0xd4,
        0x04, 0xf5, 0x18, 0xcf, 0xd4, 0x68, 0x40, 0x64,
        0x7e, 0x78, 0xbf, 0xe7, 0x06, 0xca, 0x4c, 0xf5,
        0xe9, 0xc5, 0x45, 0x3e, 0x9f, 0x7c, 0xfd, 0x2b,
        0x8b, 0x4c, 0x8d, 0x16, 0x9a, 0x44, 0xe5, 0x5c,
        0x88, 0xd4, 0xa9, 0xa7, 0xf9, 0x47, 0x42, 0x41,
        0xe2, 0x21, 0xaf, 0x44, 0x86, 0x00, 0x18, 0xab,
        0x08, 0x56, 0x97, 0x2e, 0x19, 0x4c, 0xd9, 0x34,
    };
    // zig fmt: on

    var bs = Bytes{ .buf = &in };
    const first = try bs.consume(u8);
    const version = try bs.consume(u32);
    const got = try Initial.fromBytes(std.testing.allocator, &bs, first, version);
    defer got.deinit();

    // See if the header part is correctly decoded.
    const quic_v1 = @import("../version.zig").quic_v1;
    try std.testing.expectEqual(@as(u32, quic_v1), got.version);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 },
        got.destination_connection_id.items,
    );
    try std.testing.expectEqual(@as(usize, 0), got.source_connection_id.items.len);
    try std.testing.expectEqual(@as(usize, 0), got.token.items.len);
    try std.testing.expectEqual(@as(u32, 2), got.packet_number);
    try std.testing.expectEqual(@as(usize, 1162), got.payload.items.len);

    // See if the payload part is correctly decoded.
    const expected_payload = blk: {
        // Copied from https://www.rfc-editor.org/rfc/rfc9001#name-client-initial
        // zig fmt: off
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
        // zig fmt: on

        // PADDING frames are added to make the packet reach 1200 bytes, since clients MUST ensure that
        // UDP datagrams containing Initial packets have UDP payloads of at least 1200 bytes.
        // Note that `1162` is `1200 - header_size (22 bytes, in this case) - authentication_tag_size (16 bytes)`.
        //
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-address-validation-during-c
        // https://www.rfc-editor.org/rfc/rfc9001#name-client-initial
        const padding_frames = [_]u8{0x00} ** (1162 - crypto_frame.len);

        break :blk crypto_frame ++ padding_frames;
    };

    try std.testing.expectEqualSlices(u8, &expected_payload, got.payload.items);
}
