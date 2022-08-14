const std = @import("std");
const ArrayList = std.ArrayList;
const Bytes = @import("./bytes.zig").Bytes;
const version = @import("./version.zig");

const PacketType = enum {
    initial,
    retry,
    handshake,
    zero_rtt,
    version_negotiation,
    short,
};

const form_bit: u8 = 0x80;
const fixed_bit: u8 = 0x40;
const key_phase_bit: u8 = 0x04;

const Header = struct {
    packet_type: PacketType,
    version: u32,
    /// Destination connection ID of the packet.
    dcid: ArrayList(u8),
    /// Source connection ID of the packet.
    scid: ArrayList(u8),
    /// Packet number, protected using header protection.
    packet_num: u64,
    /// The length of packet number, protected using header protection.
    packet_num_len: usize,
    /// Address verification token, only present in `Initial` and `Retry` packets.
    token: ?ArrayList(u8),
    /// The list of versions, only present in `VersionNegotiation` packets.
    versions: ?ArrayList(u32),
    /// Key phase bit, protected using header protection.
    key_phase: bool,

    const Self = @This();
    const packet_type_mask = 0x30;
    const max_cid_len = 20;

    /// Decodes header from the given buffer.
    /// Deinitialize with `deinit`.
    pub fn decode(allocator: std.mem.Allocator, buf: []u8, dcid_len: usize) !Self {
        var bs = Bytes{ .buf = buf };
        return fromBytes(allocator, &bs, dcid_len);
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
        var bs = Bytes { .buf = out };

        var first: u8 = 0;
        first |= @intCast(u8, self.packet_num_len -| 1);

        // Encode short header.
        if (self.packet_type == .short) {
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
        const packet_type: u8  = switch (self.packet_type) {
            .initial => 0x00,
            .zero_rtt => 0x01,
            .handshake => 0x02,
            .retry => 0x03,
            else => return error.InvalidPacket,
        };

        first |= form_bit | fixed_bit | (packet_type << 4);
        try bs.put(u8, first);
        try bs.put(u32, self.version);
        try bs.put(u8, @intCast(u8, self.dcid.items.len));
        try bs.putBytes(self.dcid.items);
        try bs.put(u8, @intCast(u8, self.scid.items.len));
        try bs.putBytes(self.scid.items);

        switch (self.packet_type) {
            .initial => {
                if (self.token) |t| {
                    try bs.putVarInt(@intCast(u64, t.items.len));
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

    fn fromBytes(allocator: std.mem.Allocator, bs: *Bytes, dcid_len: usize) !Self {
        const first = try bs.get(u8);

        if (!isLongHeader(first)) {
            const dcid = try bs.getBytesOwned(allocator, dcid_len);

            return Self{
                .packet_type = .short,
                .version = 0,
                .dcid = dcid,
                .scid = ArrayList(u8).init(allocator),
                .packet_num = 0,
                .packet_num_len = 0,
                .token = null,
                .versions = null,
                .key_phase = false,
            };
        }

        const ver = try bs.get(u32);
        const packet_type = if (ver == 0)
            PacketType.version_negotiation
        else switch ((first & packet_type_mask) >> 4) {
            0x00 => PacketType.initial,
            0x01 => PacketType.zero_rtt,
            0x02 => PacketType.handshake,
            0x03 => PacketType.retry,
            else => return error.InvalidPacket,
        };

        const decoded_dcid_len = try bs.get(u8);
        if (version.isSupported(ver) and dcid_len > max_cid_len)
            return error.InvalidPacket;

        const dcid = try bs.getBytesOwned(allocator, decoded_dcid_len);
        errdefer dcid.deinit();

        const scid_len = try bs.get(u8);
        if (version.isSupported(ver) and scid_len > max_cid_len)
            return error.InvalidPacket;

        const scid = try bs.getBytesOwned(allocator, scid_len);
        errdefer scid.deinit();

        var token: ?ArrayList(u8) = null;
        var versions: ?ArrayList(u32) = null;

        switch (packet_type) {
            .initial => {
                token = try bs.getBytesOwnedWithVarIntLength(allocator);
            },
            .retry => {
                // https://datatracker.ietf.org/doc/html/rfc9000#section-17.2.5
                const retry_integrity_tag_len = 16;
                if (bs.remainingCapacity() < retry_integrity_tag_len)
                    return error.InvalidPacket;

                const token_len = bs.remainingCapacity() - retry_integrity_tag_len;
                token = try bs.getBytesOwned(allocator, token_len);
            },
            .version_negotiation => {
                var vs = ArrayList(u32).init(allocator);
                errdefer vs.deinit();

                while (bs.remainingCapacity() > 0) {
                    const v = try bs.get(u32);
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
            .packet_num = 0,
            .packet_num_len = 0,
            .token = token,
            .versions = versions,
            .key_phase = false,
        };
    }
};

fn isLongHeader(b: u8) bool {
    return b & form_bit != 0;
}

test "Initial" {
    const allocator = std.testing.allocator;

    var d = [_]u8{0} ** 50;

    const hdr = Header{
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
    const got = try Header.decode(allocator, &d, 9);
    defer got.deinit();

    try std.testing.expectEqual(hdr.packet_type, got.packet_type);
    try std.testing.expectEqual(hdr.version, got.version);
    try std.testing.expectEqualSlices(u8, hdr.dcid.items, got.dcid.items);
    try std.testing.expectEqualSlices(u8, hdr.scid.items, got.scid.items);
    try std.testing.expectEqual(hdr.packet_num, got.packet_num);
    try std.testing.expectEqual(hdr.packet_num_len, got.packet_num_len);
    try std.testing.expectEqualSlices(u8, hdr.token.?.items, got.token.?.items);
    try std.testing.expectEqual(hdr.versions, got.versions);
    try std.testing.expectEqual(hdr.key_phase, got.key_phase);
}
