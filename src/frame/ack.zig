const std = @import("std");
const bytes = @import("../bytes.zig");
const range_set = @import("../range_set.zig");

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
///
/// ACK Range {
///   Gap (i),
///   ACK Range Length (i),
/// }
pub const Ack = struct {
    ack_delay: u64,
    ranges: range_set.RangeSet,
    ecn_counts: ?EcnCounts = null,

    const Self = @This();

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames
    /// > Receivers send ACK frames (types 0x02 and 0x03) to inform senders of packets they have
    /// > received and processed.
    const frame_type_no_ecn = 0x02;
    const frame_type_with_ecn = 0x03;

    pub fn encode(self: Self, out: *bytes.Bytes) !void {
        if (self.ranges.count() == 0)
            return error.NoPacketToAck;

        // Type
        try out.putVarInt(self.get_frame_type());

        var it = self.ranges.iteratorBack();
        const first_range = it.prev().?;

        // Largest Acknowledged
        try out.putVarInt(first_range.end);

        // ACK Delay
        try out.putVarInt(self.ack_delay);

        // ACK Range Count
        try out.putVarInt(self.ranges.count() - 1);

        // First ACK Range
        try out.putVarInt(first_range.end - first_range.start);

        // ACK Range
        var prev_smallest = first_range.start;
        while (it.prev()) |range| {
            const gap = prev_smallest - range.end - 2;
            const ack_range_length = range.end - range.start;
            try out.putVarInt(gap);
            try out.putVarInt(ack_range_length);
            prev_smallest = range.start;
        }

        // ECN Counts
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

        var ranges = range_set.RangeSet.init(allocator);
        errdefer ranges.deinit();

        // How to interpret an ACK frame is explained in the RFC:
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-ack-frames

        if (largest_acknowledged < first_ack_range)
            return error.InvalidFrame;

        var smallest = largest_acknowledged - first_ack_range;

        // Insert a range including the largest packet number.
        try ranges.insert(.{ .start = smallest, .end = largest_acknowledged });

        // Insert the remaining ranges, if any.
        var i: usize = 0;
        while (i < ack_range_count) : (i += 1) {
            const gap = try in.consumeVarInt();
            const ack_range_length = try in.consumeVarInt();

            if (smallest < gap + 2)
                return error.InvalidFrame;

            const largest = smallest - gap - 2;
            smallest = largest - ack_range_length;

            try ranges.insert(.{ .start = smallest, .end = largest });
        }

        const ecn_counts = if (frame_type == frame_type_with_ecn)
            try EcnCounts.decode(allocator, in)
        else
            null;

        return Self{
            .ack_delay = ack_delay,
            .ranges = ranges,
            .ecn_counts = ecn_counts,
        };
    }

    pub fn deinit(self: Self) void {
        self.ranges.deinit();
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
        .ack_delay = 2,
        .ranges = blk: {
            var ranges = range_set.RangeSet.init(std.testing.allocator);
            errdefer ranges.deinit();

            try ranges.insert(.{ .end = 15, .start = 12 });
            try ranges.insert(.{ .end = 10, .start = 8 });
            try ranges.insert(.{ .end = 5, .start = 2 });

            break :blk ranges;
        },
        .ecn_counts = null,
    };
    defer ack.deinit();
    var buf: [1024]u8 = undefined;
    var out = bytes.Bytes{ .buf = &buf };

    try ack.encode(&out);
    // zig fmt: off
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x02, // frame_type
        0x0f, // largest_acknowledged
        0x02, // ack_delay
        0x02, // ack_range_count
        0x03, // first_ack_range

        // ack_range (*2)
        0x00, 0x02,
        0x01, 0x03,
    }, out.split().former.buf);
    // zig fmt: on
}

test "encode Ack (with ECN Counts)" {
    const ack = Ack{
        .ack_delay = 2,
        .ranges = blk: {
            var ranges = range_set.RangeSet.init(std.testing.allocator);
            errdefer ranges.deinit();

            try ranges.insert(.{ .end = 15, .start = 12 });
            try ranges.insert(.{ .end = 10, .start = 8 });
            try ranges.insert(.{ .end = 5, .start = 2 });

            break :blk ranges;
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

    try ack.encode(&out);
    // zig fmt: off
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x03, // frame_type
        0x0f, // largest_acknowledged
        0x02, // ack_delay
        0x02, // ack_range_count
        0x03, // first_ack_range

        // ack_range (*2)
        0x00, 0x02,
        0x01, 0x03,

        // ecn_counts
        0x08, 0x09, 0x0a,
    }, out.split().former.buf);
    // zig fmt: on
}

test "decode Ack (without ECN Counts)" {
    var buf = [_]u8{ 0x02, 0x0f, 0x02, 0x02, 0x03, 0x00, 0x02, 0x01, 0x03 };
    var in = bytes.Bytes{ .buf = &buf };

    const got = try Ack.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(u64, 2), got.ack_delay);
    try std.testing.expectEqual(@as(usize, 3), got.ranges.count());

    var it = got.ranges.iteratorBack();

    try std.testing.expectEqual(it.prev().?.*, .{ .start = 12, .end = 15 });
    try std.testing.expectEqual(it.prev().?.*, .{ .start = 8, .end = 10 });
    try std.testing.expectEqual(it.prev().?.*, .{ .start = 2, .end = 5 });

    try std.testing.expect(got.ecn_counts == null);
}

test "decode Ack (with ECN Counts)" {
    var buf = [_]u8{ 0x03, 0x0f, 0x02, 0x02, 0x03, 0x00, 0x02, 0x01, 0x03, 0x08, 0x09, 0x0a };
    var in = bytes.Bytes{ .buf = &buf };

    const got = try Ack.decode(std.testing.allocator, &in);
    defer got.deinit();

    try std.testing.expectEqual(@as(u64, 2), got.ack_delay);
    try std.testing.expectEqual(@as(usize, 3), got.ranges.count());

    var it = got.ranges.iteratorBack();

    try std.testing.expectEqual(it.prev().?.*, .{ .start = 12, .end = 15 });
    try std.testing.expectEqual(it.prev().?.*, .{ .start = 8, .end = 10 });
    try std.testing.expectEqual(it.prev().?.*, .{ .start = 2, .end = 5 });

    try std.testing.expect(got.ecn_counts != null);
    try std.testing.expectEqual(@as(u64, 8), got.ecn_counts.?.ect0);
    try std.testing.expectEqual(@as(u64, 9), got.ecn_counts.?.ect1);
    try std.testing.expectEqual(@as(u64, 10), got.ecn_counts.?.ect_ce);
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
