const std = @import("std");
const ArrayList = std.ArrayList;
const bytes = @import("../bytes.zig");

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
///
/// ACK Frame {
///   Type (i) = 0x02..0x03,
///   Largest Acknowledged (i),
///   ACK Delay (i),
///   ACK Range Count (i),
///   First ACK Range (i),
///   ACK Range (..) ...,
///   [ECN Counts (..)],
/// }
pub const Ack = struct {
    largest_acknowledged: u64,
    ack_delay: u64,
    first_ack_range: u64,
    ack_range: AckRanges,
    ecn_counts: ?EcnCounts,

    const Self = @This();
    const AckRanges = ArrayList(AckRange);

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
    /// > Receivers send ACK frames (types 0x02 and 0x03) to inform senders of packets they have
    /// > received and processed.
    const frame_type_no_ecn = 0x02;
    const frame_type_with_ecn = 0x03;

    pub fn encodedLength(self: Self) usize {
        const type_len = bytes.varIntLength(self.get_frame_type());
        const largest_acknowledged_len = bytes.varIntLength(self.largest_acknowledged);
        const ack_delay_len = bytes.varIntLength(self.ack_delay);
        const ack_range_count_len = bytes.varIntLength(self.ack_range.items.len);
        const first_ack_range_len = bytes.varIntLength(self.first_ack_range);
        const ack_range_len = blk: {
            var len: usize = 0;
            for (self.ack_range.items) |a| {
                len += a.encodedLength();
            }
            break :blk len;
        };
        const ecn_counts_len = if (self.ecn_counts) |ecn| ecn.encodedLength() else 0;

        return type_len +
            largest_acknowledged_len +
            ack_delay_len +
            ack_range_count_len +
            first_ack_range_len +
            ack_range_len +
            ecn_counts_len;
    }

    pub fn encode(self: Self, out: *bytes.Bytes) !void {
        try out.putVarInt(self.get_frame_type());
        try out.putVarInt(self.largest_acknowledged);
        try out.putVarInt(self.ack_delay);
        try out.putVarInt(@intCast(u64, self.ack_range.items.len));
        try out.putVarInt(self.first_ack_range);
        for (self.ack_range.items) |a| {
            try a.encode(out);
        }
        if (self.ecn_counts) |ecn| {
            try ecn.encode(out);
        }
    }

    pub fn decode(allocator: std.mem.Allocator, in: *bytes.Bytes) !Self {
        const frame_type = try in.consumeVarInt();
        std.debug.assert(frame_type == frame_type_no_ecn or frame_type == frame_type_with_ecn);
        const largest_acknowledged = try in.consumeVarInt();
        const ack_delay = try in.consumeVarInt();
        const ack_range_count = try in.consumeVarInt();
        const first_ack_range = try in.consumeVarInt();

        const ack_range = blk: {
            var ranges = try AckRanges.initCapacity(allocator, @intCast(usize, ack_range_count));
            errdefer ranges.deinit();

            var i: usize = 0;
            while (i < ack_range_count) : (i += 1) {
                const r = try AckRange.decode(allocator, in);
                ranges.appendAssumeCapacity(r);
            }

            break :blk ranges;
        };
        errdefer ack_range.deinit();

        const ecn_counts = if (frame_type == frame_type_with_ecn)
            try EcnCounts.decode(allocator, in)
        else
            null;

        return Self{
            .largest_acknowledged = largest_acknowledged,
            .ack_delay = ack_delay,
            .first_ack_range = first_ack_range,
            .ack_range = ack_range,
            .ecn_counts = ecn_counts,
        };
    }

    pub fn deinit(self: Self) void {
        // Items in ack_range don't need to be deinitialized since `AckRange` type
        // consists of primitive values only
        self.ack_range.deinit();
    }

    fn get_frame_type(self: Self) u64 {
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
        // > Receivers send ACK frames (types 0x02 and 0x03) to inform senders of packets they have
        // > received and processed.
        //
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-ecn-counts
        // > The ACK frame uses the least significant bit of the type value (that is, type 0x03) to indicate ECN
        // > feedback and report receipt of QUIC packets with associated ECN codepoints of ECT(0), ECT(1), or ECN-CE
        // > in the packet's IP header. ECN counts are only present when the ACK frame type is 0x03.
        return if (self.ecn_counts == null)
            frame_type_no_ecn
        else
            frame_type_with_ecn;
    }
};

test "encode Ack (without ECN Counts)" {
    const ack = Ack{
        .largest_acknowledged = 1,
        .ack_delay = 2,
        .first_ack_range = 3,
        .ack_range = blk: {
            var xs = ArrayList(AckRange).init(std.testing.allocator);

            try xs.append(.{ .gap = 4, .ack_range_length = 5 });
            try xs.append(.{ .gap = 6, .ack_range_length = 7 });

            break :blk xs;
        },
        .ecn_counts = null,
    };
    defer ack.deinit();
    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try std.testing.expectEqual(@as(usize, 9), ack.encodedLength());

    try ack.encode(&out);
    // zig fmt: off
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x02, // frame_type
        0x01, // largest_acknowledged
        0x02, // ack_delay
        0x02, // ack_range_count
        0x03, // first_ack_range

        // ack_range (*2)
        0x04, 0x05,
        0x06, 0x07,
    }, out.split().former.buf);
    // zig fmt: on
}

test "encode Ack (with ECN Counts)" {
    const ack = Ack{
        .largest_acknowledged = 1,
        .ack_delay = 2,
        .first_ack_range = 3,
        .ack_range = blk: {
            var xs = ArrayList(AckRange).init(std.testing.allocator);

            try xs.append(.{ .gap = 4, .ack_range_length = 5 });
            try xs.append(.{ .gap = 6, .ack_range_length = 7 });

            break :blk xs;
        },
        .ecn_counts = EcnCounts{
            .ect0 = 8,
            .ect1 = 9,
            .ect_ce = 10,
        },
    };
    defer ack.deinit();
    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try std.testing.expectEqual(@as(usize, 12), ack.encodedLength());

    try ack.encode(&out);
    // zig fmt: off
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x03, // frame_type
        0x01, // largest_acknowledged
        0x02, // ack_delay
        0x02, // ack_range_count
        0x03, // first_ack_range

        // ack_range (*2)
        0x04, 0x05,
        0x06, 0x07,

        // ecn_counts
        0x08, 0x09, 0x0a,
    }, out.split().former.buf);
    // zig fmt: on
}

test "decode Ack (without ECN Counts)" {
    var buf = [_]u8{ 0x02, 0x01, 0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    var in = bytes.Bytes{ .buf = &buf };

    const got = try Ack.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(u64, 1), got.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 2), got.ack_delay);
    try std.testing.expectEqual(@as(u64, 3), got.first_ack_range);
    try std.testing.expectEqual(@as(usize, 2), got.ack_range.items.len);
    try std.testing.expectEqual(@as(u64, 4), got.ack_range.items[0].gap);
    try std.testing.expectEqual(@as(u64, 5), got.ack_range.items[0].ack_range_length);
    try std.testing.expectEqual(@as(u64, 6), got.ack_range.items[1].gap);
    try std.testing.expectEqual(@as(u64, 7), got.ack_range.items[1].ack_range_length);
    try std.testing.expect(got.ecn_counts == null);
}

test "decode Ack (with ECN Counts)" {
    var buf = [_]u8{ 0x03, 0x01, 0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a };
    var in = bytes.Bytes{ .buf = &buf };

    const got = try Ack.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(u64, 1), got.largest_acknowledged);
    try std.testing.expectEqual(@as(u64, 2), got.ack_delay);
    try std.testing.expectEqual(@as(u64, 3), got.first_ack_range);
    try std.testing.expectEqual(@as(usize, 2), got.ack_range.items.len);
    try std.testing.expect(got.ecn_counts != null);
    try std.testing.expectEqual(@as(u64, 8), got.ecn_counts.?.ect0);
    try std.testing.expectEqual(@as(u64, 9), got.ecn_counts.?.ect1);
    try std.testing.expectEqual(@as(u64, 10), got.ecn_counts.?.ect_ce);
}

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-ranges
///
/// ACK Range {
///   Gap (i),
///   ACK Range Length (i),
/// }
pub const AckRange = struct {
    gap: u64,
    ack_range_length: u64,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return bytes.varIntLength(self.gap) + bytes.varIntLength(self.ack_range_length);
    }

    pub fn encode(self: Self, out: *bytes.Bytes) !void {
        try out.putVarInt(self.gap);
        try out.putVarInt(self.ack_range_length);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *bytes.Bytes) !Self {
        _ = allocator;
        const gap = try in.consumeVarInt();
        const ack_range_length = try in.consumeVarInt();
        return Self{
            .gap = gap,
            .ack_range_length = ack_range_length,
        };
    }

    pub fn deinit(self: Self) void {
        // no-op
        _ = self;
    }
};

test "encode AckRange" {
    const ack_range = AckRange{
        .gap = 3,
        .ack_range_length = 4,
    };
    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try std.testing.expectEqual(@as(usize, 2), ack_range.encodedLength());

    try ack_range.encode(&out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x03, 0x04 }, out.split().former.buf);
}

test "decode AckRange" {
    var buf = [_]u8{ 0x03, 0x04 };
    var in = bytes.Bytes{ .buf = &buf };

    const got = try AckRange.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(u64, 3), got.gap);
    try std.testing.expectEqual(@as(u64, 4), got.ack_range_length);
}

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-ecn-counts
///
/// ECN Counts {
///   ECT0 Count (i),
///   ECT1 Count (i),
///   ECN-CE Count (i),
/// }
pub const EcnCounts = struct {
    ect0: u64,
    ect1: u64,
    ect_ce: u64,

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return bytes.varIntLength(self.ect0) + bytes.varIntLength(self.ect1) + bytes.varIntLength(self.ect_ce);
    }

    pub fn encode(self: Self, out: *bytes.Bytes) !void {
        try out.putVarInt(self.ect0);
        try out.putVarInt(self.ect1);
        try out.putVarInt(self.ect_ce);
    }

    pub fn decode(allocator: std.mem.Allocator, in: *bytes.Bytes) !Self {
        _ = allocator;
        const ect0 = try in.consumeVarInt();
        const ect1 = try in.consumeVarInt();
        const ect_ce = try in.consumeVarInt();
        return Self{
            .ect0 = ect0,
            .ect1 = ect1,
            .ect_ce = ect_ce,
        };
    }

    pub fn deinit(self: Self) void {
        // no-op
        _ = self;
    }
};

test "encode EcnCounts" {
    const ecn_counts = EcnCounts{
        .ect0 = 1,
        .ect1 = 2,
        .ect_ce = 3,
    };
    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try std.testing.expectEqual(@as(usize, 3), ecn_counts.encodedLength());

    try ecn_counts.encode(&out);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, out.split().former.buf);
}

test "decode EcnCounts" {
    var buf = [_]u8{ 0x01, 0x02, 0x03 };
    var in = bytes.Bytes{ .buf = &buf };

    const got = try EcnCounts.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(u64, 1), got.ect0);
    try std.testing.expectEqual(@as(u64, 2), got.ect1);
    try std.testing.expectEqual(@as(u64, 3), got.ect_ce);
}
