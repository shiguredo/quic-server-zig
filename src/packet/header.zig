//! QUIC's packets are classified into two: long header packets and short header packets.
//!
//! RFC 9000 specifies the shape of long header packets in:
//! https://www.rfc-editor.org/rfc/rfc9000.html#name-long-header-packet-format
//!
//! Long Header Packet {
//!   Header Form (1) = 1,
//!   Fixed Bit (1) = 1,
//!   Long Packet Type (2),
//!   Type-Specific Bits (4),
//!   Version (32),
//!   Destination Connection ID Length (8),
//!   Destination Connection ID (0..160),
//!   Source Connection ID Length (8),
//!   Source Connection ID (0..160),
//!   Type-Specific Payload (..),
//! }
//!
//!
//! Also short header packets are specified in:
//! https://www.rfc-editor.org/rfc/rfc9000.html#name-short-header-packets
//!
//! 1-RTT Packet {
//!   Header Form (1) = 0,
//!   Fixed Bit (1) = 1,
//!   Spin Bit (1),
//!   Reserved Bits (2),
//!   Key Phase (1),
//!   Packet Number Length (2),
//!   Destination Connection ID (0..160),
//!   Packet Number (8..32),
//!   Packet Payload (8..),
//! }

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;
const Bytes = @import("../bytes.zig").Bytes;
const version = @import("../version.zig");
const PacketType = @import("./packet_type.zig").PacketType;
const tls = @import("../tls.zig");

const Self = @This();

const form_bit: u8 = 0x80;
const fixed_bit: u8 = 0x40;
const packet_num_len_bit: u8 = 0x03;
const key_phase_bit: u8 = 0x04;
const packet_type_mask = 0x30;
/// In QUIC v1 The length of Connection IDs must be less than or equal to 20,
/// as specified in https://datatracker.ietf.org/doc/html/rfc9000#section-17.2
const max_cid_len = 20;

// For now we assume the length of Destination Connection ID is always 16-byte long.
const temporary_dcid_len = 16;

const DecodeError = error{
    InvalidPacket,
};

/// The packet type.
packet_type: PacketType,
/// The version of the packet.
/// Note that this field has a valid value only when it's a long header packet.
version: u32,
/// Destination connection ID of the packet.
/// Although in QUIC v1 the maximum length is 20 bytes, the implementation should
/// accept Connection ID with its length being over 20 bytes so it can handle QUIC
/// packets of future versions, as explained here: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-3.12.1
/// So we use `ArrayList(u8)` rather than `BoundedArray(u8, 20)`.
dcid: ArrayList(u8),
/// Source connection ID of the packet.
/// Although in QUIC v1 the maximum length is 20 bytes, the implementation should
/// accept Connection ID with its length being over 20 bytes so it can handle QUIC
/// packets of future versions, as explained here: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-3.12.1
/// So we use `ArrayList(u8)` rather than `BoundedArray(u8, 20)`.
/// Note that this field has a valid value only when it's a long header packet.
scid: ArrayList(u8),
/// Packet number, protected using header protection.
packet_num: u64,
/// The length of packet number, protected using header protection.
packet_num_len: usize,
/// Address verification token, only present in `Initial` and `Retry` packets.
token: ?ArrayList(u8),
/// The list of versions, only present in `VersionNegotiation` packets.
versions: ?ArrayList(u32),
/// Key phase bit, protected using header protection. Only present in `OneRTT` packets.
key_phase: bool,

pub fn new(
    allocator: Allocator,
    packet_type: PacketType,
    quic_version: u32,
    dcid: []const u8,
    scid: []const u8,
    packet_number: u64,
    packet_number_len: usize,
    token: ?[]const u8,
    versions: ?[]const u32,
    key_phase: bool,
) Allocator.Error!Self {
    var dcid_clone = try allocator.dupe(u8, dcid);
    errdefer allocator.free(dcid_clone);
    var scid_clone = try allocator.dupe(u8, scid);
    errdefer allocator.free(scid_clone);
    var token_clone = if (token) |t| try allocator.dupe(u8, t) else null;
    errdefer if (token_clone) |t| allocator.free(t);
    var versions_clone = if (versions) |v| try allocator.dupe(u32, v) else null;
    errdefer if (versions_clone) |v| allocator.free(v);

    return Self{
        .packet_type = packet_type,
        .version = quic_version,
        .dcid = ArrayList(u8).fromOwnedSlice(allocator, dcid_clone),
        .scid = ArrayList(u8).fromOwnedSlice(allocator, scid_clone),
        .packet_num = packet_number,
        .packet_num_len = packet_number_len,
        .token = if (token_clone) |t| ArrayList(u8).fromOwnedSlice(allocator, t) else null,
        .versions = if (versions_clone) |v| ArrayList(u32).fromOwnedSlice(allocator, v) else null,
        .key_phase = key_phase,
    };
}

/// Decodes header from the given buffer.
/// When the header is a short header, it assumes that the length of Destination Connection ID is 16 bytes.
pub fn decode(allocator: Allocator, buf: []u8) !Self {
    var bs = Bytes{ .buf = buf };
    return fromBytes(allocator, &bs, temporary_dcid_len);
}

/// Release all allocated memory.
pub fn deinit(self: Self) void {
    self.dcid.deinit();
    self.scid.deinit();
    if (self.token) |t| t.deinit();
    if (self.versions) |v| v.deinit();
}

/// Encodes the header into binary and writes it to `out`.
pub fn encode(self: Self, out: []u8) !void {
    var bs = Bytes{ .buf = out };
    try self.toBytes(&bs);
}

pub fn format(
    self: Self,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;

    try writer.print("packet_type = {}\n", .{self.packet_type});
    try writer.print("version = {}\n", .{self.version});
    try writer.print("destination_connection_id = {any}\n", .{self.dcid.items});
    try writer.print("source_connection_id = {any}\n", .{self.scid.items});
    try writer.print("packet_num_len = {}\n", .{self.packet_num_len});
    try writer.print("packet_num = {}\n", .{self.packet_num});
    if (self.token) |t| {
        try writer.print("token = {any}\n", .{t.items});
    } else {
        try writer.writeAll("token = null\n");
    }
    if (self.versions) |vs| {
        try writer.print("versions = {any}\n", .{vs.items});
    } else {
        try writer.writeAll("versions = null\n");
    }
    try writer.print("key_phase = {}\n", .{self.key_phase});
}

pub fn fromBytes(allocator: Allocator, bs: *Bytes, dcid_len: usize) !Self {
    const first = try bs.consume(u8);

    if (!isLongHeader(first)) {
        const dcid = try bs.consumeBytesOwned(allocator, dcid_len);

        return Self{
            .packet_type = .one_rtt,
            .version = 0,
            .dcid = dcid,
            .scid = ArrayList(u8).init(allocator),
            // packet_num and packet_num_len will have valid values after the header is unprotected.
            .packet_num = 0,
            .packet_num_len = 0,
            .token = null,
            .versions = null,
            // key_phase will have a valid value after the header is unprotected.
            .key_phase = false,
        };
    }

    const ver = try bs.consume(u32);
    const packet_type = if (ver == 0)
        PacketType.version_negotiation
    else switch ((first & packet_type_mask) >> 4) {
        0x00 => PacketType.initial,
        0x01 => PacketType.zero_rtt,
        0x02 => PacketType.handshake,
        0x03 => PacketType.retry,
        else => return DecodeError.InvalidPacket,
    };

    const decoded_dcid_len = try bs.consume(u8);
    if (version.isSupported(ver) and decoded_dcid_len > max_cid_len)
        return DecodeError.InvalidPacket;

    const dcid = try bs.consumeBytesOwned(allocator, decoded_dcid_len);
    errdefer dcid.deinit();

    const scid_len = try bs.consume(u8);
    if (version.isSupported(ver) and scid_len > max_cid_len)
        return DecodeError.InvalidPacket;

    const scid = try bs.consumeBytesOwned(allocator, scid_len);
    errdefer scid.deinit();

    var token: ?ArrayList(u8) = null;
    var versions: ?ArrayList(u32) = null;

    switch (packet_type) {
        // Initial packets have "Token Length" and "Token" fields.
        .initial => {
            token = try bs.consumeBytesOwnedWithVarIntLength(allocator);
        },
        .retry => {
            // https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.5
            const retry_integrity_tag_len = 16;
            if (bs.remainingCapacity() < retry_integrity_tag_len)
                return DecodeError.InvalidPacket;

            const token_len = bs.remainingCapacity() - retry_integrity_tag_len;
            token = try bs.consumeBytesOwned(allocator, token_len);
        },
        .version_negotiation => {
            var vs = ArrayList(u32).init(allocator);
            errdefer vs.deinit();

            while (bs.remainingCapacity() > 0) {
                const v = try bs.consume(u32);
                try vs.append(v);
            }

            versions = vs;
        },
        else => {},
    }

    return Self{
        .packet_type = packet_type,
        .version = ver,
        .dcid = dcid,
        .scid = scid,
        // packet_num and packet_num_len will have valid values after the header is unprotected.
        .packet_num = 0,
        .packet_num_len = 0,
        .token = token,
        .versions = versions,
        .key_phase = false,
    };
}

/// Unprotect the header and update the values stored in `self` appropriately.
/// Additionally, the given `in` will be advanced by the length of packet number.
/// Note that the passed `in` must have consumed the header part of the packet (i.e. up to the Length field).
pub fn unprotect(self: *Self, in: *Bytes, decryptor: tls.Cryptor) (DecodeError || Bytes.Error)!void {
    const max_packet_num_length = 4;
    const sample_length = 16;

    var remaining = in.split().latter.buf;

    if (remaining.len < max_packet_num_length + sample_length)
        return DecodeError.InvalidPacket;

    var packet_number_in_buf = remaining[0..max_packet_num_length];
    var sample: [sample_length]u8 = undefined;
    mem.copy(u8, &sample, remaining[max_packet_num_length..(max_packet_num_length + sample_length)]);
    decryptor.unprotectHeader(sample, &in.buf[0], packet_number_in_buf);

    // The last two bits of the unprotected first byte is packet number length minus 1.
    const pkt_num_len = @as(usize, @intCast(in.buf[0] & packet_num_len_bit)) + 1;
    self.packet_num_len = pkt_num_len;

    const pkt_num = switch (pkt_num_len) {
        1 => @as(u64, @intCast(try in.consume(u8))),
        2 => @as(u64, @intCast(try in.consume(u16))),
        3 => @as(u64, @intCast(try in.consume(u24))),
        4 => @as(u64, @intCast(try in.consume(u32))),
        else => return DecodeError.InvalidPacket,
    };
    self.packet_num = pkt_num;

    if (self.packet_type == .one_rtt)
        self.key_phase = (in.buf[0] & key_phase_bit) != 0;
}

pub fn toBytes(self: Self, bs: *Bytes) !void {
    var first: u8 = 0;
    first |= @as(u8, @intCast(self.packet_num_len -| 1));

    // Encode OneRTT (i.e. short) header.
    if (self.packet_type == .one_rtt) {
        first &= ~form_bit;
        first |= fixed_bit;
        if (self.key_phase) {
            first |= key_phase_bit;
        } else {
            first &= ~key_phase_bit;
        }

        try bs.put(u8, first);
        try bs.putBytes(self.dcid.items);

        return;
    }

    // Encode long header.
    const packet_type: u8 = switch (self.packet_type) {
        .initial => 0x00,
        .zero_rtt => 0x01,
        .handshake => 0x02,
        .retry => 0x03,
        else => return DecodeError.InvalidPacket,
    };

    first |= form_bit | fixed_bit | (packet_type << 4);
    try bs.put(u8, first);
    try bs.put(u32, self.version);
    try bs.put(u8, @as(u8, @intCast(self.dcid.items.len)));
    try bs.putBytes(self.dcid.items);
    try bs.put(u8, @as(u8, @intCast(self.scid.items.len)));
    try bs.putBytes(self.scid.items);

    switch (self.packet_type) {
        .initial => {
            if (self.token) |t| {
                try bs.putVarInt(@as(u64, @intCast(t.items.len)));
                try bs.putBytes(t.items);
            } else {
                try bs.putVarInt(0);
            }
        },
        .retry => {
            try bs.putBytes(self.token.?.items);
        },
        else => {},
    }
}

fn isLongHeader(b: u8) bool {
    return b & form_bit != 0;
}

fn assertHeaderEqual(expected: Self, actual: Self) !void {
    try std.testing.expectEqual(expected.packet_type, actual.packet_type);
    try std.testing.expectEqual(expected.version, actual.version);
    try std.testing.expectEqualSlices(u8, expected.dcid.items, actual.dcid.items);
    try std.testing.expectEqualSlices(u8, expected.scid.items, actual.scid.items);
    try std.testing.expectEqual(expected.packet_num, actual.packet_num);
    try std.testing.expectEqual(expected.packet_num_len, actual.packet_num_len);

    if (expected.token) |t| {
        try std.testing.expectEqualSlices(u8, t.items, actual.token.?.items);
    } else {
        try std.testing.expect(actual.token == null);
    }

    if (expected.versions) |vs| {
        try std.testing.expectEqualSlices(u32, vs.items, actual.versions.?.items);
    } else {
        try std.testing.expect(actual.versions == null);
    }

    try std.testing.expectEqual(expected.key_phase, actual.key_phase);
}

test "Initial" {
    const allocator = std.testing.allocator;

    var d: [50]u8 = undefined;

    const hdr = Self{
        .packet_type = .initial,
        .version = 0xafafafaf,
        .dcid = dcid: {
            var a = ArrayList(u8).init(allocator);
            errdefer a.deinit();
            try a.appendSlice(&[_]u8{ 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba });
            break :dcid a;
        },
        .scid = scid: {
            var a = ArrayList(u8).init(allocator);
            errdefer a.deinit();
            try a.appendSlice(&[_]u8{ 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb });
            break :scid a;
        },
        .packet_num = 0,
        .packet_num_len = 0,
        .token = token: {
            var a = ArrayList(u8).init(allocator);
            errdefer a.deinit();
            try a.appendSlice(&[_]u8{ 0x05, 0x06, 0x07, 0x08 });
            break :token a;
        },
        .versions = null,
        .key_phase = false,
    };
    defer hdr.deinit();

    try hdr.encode(&d);
    const got = try Self.decode(allocator, &d);
    defer got.deinit();

    try assertHeaderEqual(hdr, got);
}

test "retry" {
    const allocator = std.testing.allocator;

    var d: [63]u8 = undefined;

    const hdr = Self{
        .packet_type = .retry,
        .version = 0xafafafaf,
        .dcid = dcid: {
            var a = ArrayList(u8).init(allocator);
            errdefer a.deinit();
            try a.appendSlice(&[_]u8{ 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba, 0xba });
            break :dcid a;
        },
        .scid = scid: {
            var a = ArrayList(u8).init(allocator);
            errdefer a.deinit();
            try a.appendSlice(&[_]u8{ 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb });
            break :scid a;
        },
        .packet_num = 0,
        .packet_num_len = 0,
        .token = token: {
            var a = ArrayList(u8).init(allocator);
            errdefer a.deinit();
            try a.appendSlice(&[_]u8{0xba} ** 24);
            break :token a;
        },
        .versions = null,
        .key_phase = false,
    };
    defer hdr.deinit();

    var b = Bytes{ .buf = &d };
    try hdr.toBytes(&b);
    // Add fake retry integrity token.
    try b.putBytes(&[_]u8{0xba} ** 16);
    const got = try Self.decode(allocator, &d);
    defer got.deinit();

    try assertHeaderEqual(hdr, got);
}
