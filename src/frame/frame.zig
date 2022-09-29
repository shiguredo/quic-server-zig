const std = @import("std");
const Bytes = @import("../bytes.zig").Bytes;
const Crypto = @import("./crypto.zig").Crypto;

pub const Padding = @import("./padding.zig").Padding;
pub const Ack = @import("./ack.zig").Ack;

pub const FrameType = enum {
    padding,
    ack,
    crypto,
    connection_close,
    // TODO(magurotuna) add other frame types

    const Self = @This();

    pub fn fromInt(type_id: u64) Self {
        return switch (type_id) {
            0x00 => .padding,
            0x02...0x03 => .ack,
            0x06 => .crypto,
            0x1c...0x1d => .connection_close,
            // TODO(magurotuna) add other frame types
            else => unreachable,
        };
    }
};

// TODO(magurotuna): implement
const ConnectionClose = struct {};

pub const Frame = union(FrameType) {
    padding: Padding,
    ack: Ack,
    crypto: Crypto,
    connection_close: ConnectionClose,
    // TODO(magurotuna) add other frame types

    const Self = @This();

    pub fn encodedLength(self: Self) usize {
        return switch (self) {
            .padding => |p| p.encodedLength(),
            .ack => |a| a.encodedLength(),
            .crypto => |c| c.encodedLength(),
            // TODO(magurotuna) implement
            .connection_close => unreachable,
            // TODO(magurotuna) add other frame types
        };
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        return switch (self) {
            .padding => |p| p.encode(out),
            .ack => |a| a.encode(out),
            .crypto => unreachable,
            // TODO(magurotuna) implement
            .connection_close => unreachable,
            // TODO(magurotuna) add other frame types
        };
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        const ty = try in.peekVarInt();
        return switch (FrameType.fromInt(ty)) {
            .padding => .{ .padding = try Padding.decode(allocator, in) },
            .ack => .{ .ack = try Ack.decode(allocator, in) },
            .crypto => .{ .crypto = try Crypto.decode(allocator, in) },
            // TODO(magurotuna) implement
            .connection_close => unreachable,
        };
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            .padding => |p| p.deinit(),
            .ack => |a| a.deinit(),
            .crypto => |c| c.deinit(),
            // TODO(magurotuna) implement
            .connection_close => unreachable,
        }
    }

    pub fn ackEliciting(self: Self) bool {
        const non_ack_eliciting =
            self == .ack or
            self == .padding or
            self == .connection_close;

        return !non_ack_eliciting;
    }
};
