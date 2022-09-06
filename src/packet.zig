const std = @import("std");
const Bytes = @import("./bytes.zig").Bytes;
const crypto = @import("./crypto.zig");
const Frame = @import("./frame/frame.zig").Frame;

pub const Initial = @import("./packet/initial.zig").Initial;
pub const ZeroRtt = @import("./packet/zero_rtt.zig").ZeroRtt;
pub const Handshake = @import("./packet/handshake.zig").Handshake;
pub const Retry = @import("./packet/retry.zig").Retry;
pub const VersionNegotiation = @import("./packet/version_negotiation.zig").VersionNegotiation;
pub const OneRtt = @import("./packet/one_rtt.zig").OneRtt;

/// An enum to distinguish packet number spaces.
/// https://datatracker.ietf.org/doc/html/rfc9000#section-12.3
pub const PacketNumberSpace = enum {
    initial,
    handshake,
    application_data,
};

pub const PacketType = enum {
    // Long Header Packets
    // https://www.rfc-editor.org/rfc/rfc9000.html#name-long-header-packets
    initial,
    zero_rtt,
    handshake,
    retry,
    // This packet type is not identified by the packet type field;
    // but by the fact that the version field is not present.
    version_negotiation,

    // Short Header Packets
    // https://www.rfc-editor.org/rfc/rfc9000.html#name-short-header-packets

    // This is the only packet type that uses a short header in QUIC v1, so we can identify it
    // by the fact that header form field is equal to 0 (meaning it's a short-header packet).
    one_rtt,
};

pub const Packet = union(PacketType) {
    initial: Initial,
    zero_rtt: ZeroRtt,
    handshake: Handshake,
    retry: Retry,
    version_negotiation: VersionNegotiation,
    one_rtt: OneRtt,

    const Self = @This();

    /// Encodes the packet data into `buf` and returns how many bytes have been written.
    pub fn toBytes(self: Self, buf: []u8) !usize {
        var out = Bytes{ .buf = buf };
        try self.encode(&out);
        return out.pos;
    }

    pub fn fromBytes(allocator: std.mem.Allocator, buf: []u8) !Self {
        var bs = Bytes{ .buf = buf };
        return decode(allocator, &bs);
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            .initial => |a| a.deinit(),
            // TODO(magurotuna)
            .zero_rtt => unreachable,
            // TODO(magurotuna)
            .handshake => unreachable,
            // TODO(magurotuna)
            .retry => unreachable,
            // TODO(magurotuna)
            .version_negotiation => unreachable,
            // TODO(magurotuna)
            .one_rtt => unreachable,
        }
    }

    pub fn encode(self: Self, out: *Bytes) !void {
        // Ensure that no data is written to `out` yet.
        std.debug.assert(out.pos == 0);

        switch (self) {
            .initial => |i| try i.encode(out),
            .zero_rtt => |z| try z.encode(out),
            .handshake => |h| try h.encode(out),
            .retry => |r| try r.encode(out),
            .version_negotiation => |v| try v.encode(out),
            .one_rtt => |o| try o.encode(out),
        }
    }

    pub fn decode(allocator: std.mem.Allocator, in: *Bytes) !Self {
        // Ensure that `in` has not been consumed yet.
        std.debug.assert(in.pos == 0);

        const first_byte = try in.peek(u8);
        if (isLongHeader(first_byte)) {
            return decodeAsLongHeaderPacket(allocator, in);
        } else {
            // For now, we use the max Conenction ID length as our local Connection ID length.
            return decodeAsShortHeaderPacket(allocator, in, max_cid_len);
        }
    }

    /// Gets the Destination Connection ID included in this packet. 
    pub fn destination_connection_id(self: Self) []const u8 {
        return switch (self) {
            .initial => |a| a.destination_connection_id.items,
            // TODO(magurotuna)
            .zero_rtt => unreachable,
            // TODO(magurotuna)
            .handshake => unreachable,
            // TODO(magurotuna)
            .retry => unreachable,
            // TODO(magurotuna)
            .version_negotiation => unreachable,
            // TODO(magurotuna)
            .one_rtt => unreachable,
        };
    }

    /// Gets the Source Connection ID included in this packet, if any.
    pub fn source_connection_id(self: Self) ?[]const u8 {
        return switch (self) {
            .initial => |a| a.source_connection_id.items,
            // TODO(magurotuna)
            .zero_rtt => unreachable,
            // TODO(magurotuna)
            .handshake => unreachable,
            // TODO(magurotuna)
            .retry => unreachable,
            // TODO(magurotuna)
            .version_negotiation => unreachable,
            // TODO(magurotuna)
            .one_rtt => unreachable,
        };
    }

    /// Gets the Packet Number included in this packet.
    pub fn packet_number(self: Self) u32 {
        return switch (self) {
            .initial => |a| a.packet_number,
            // TODO(magurotuna)
            .zero_rtt => unreachable,
            // TODO(magurotuna)
            .handshake => unreachable,
            // TODO(magurotuna)
            .retry => unreachable,
            // TODO(magurotuna)
            .version_negotiation => unreachable,
            // TODO(magurotuna)
            .one_rtt => unreachable,
        };
    }

    /// Gets the payload included in this packet.
    pub fn payload(self: Self) []const Frame {
        return switch (self) {
            .initial => |a| a.payload.items,
            // TODO(magurotuna)
            .zero_rtt => unreachable,
            // TODO(magurotuna)
            .handshake => unreachable,
            // TODO(magurotuna)
            .retry => unreachable,
            // TODO(magurotuna)
            .version_negotiation => unreachable,
            // TODO(magurotuna)
            .one_rtt => unreachable,
        };
    }

    fn decodeAsLongHeaderPacket(allocator: std.mem.Allocator, in: *Bytes) !Self {
        // Ensure that `in` has not been consumed yet.
        std.debug.assert(in.pos == 0);

        const first_and_version = try in.peek2(u8, u32);
        const first = first_and_version.first;
        const ver = first_and_version.second;

        const packet_type = if (ver == 0)
            PacketType.version_negotiation
        else switch ((first & packet_type_mask) >> 4) {
            0x00 => PacketType.initial,
            0x01 => PacketType.zero_rtt,
            0x02 => PacketType.handshake,
            0x03 => PacketType.retry,
            else => return error.InvalidPacket,
        };

        return switch (packet_type) {
            .initial => .{ .initial = try Initial.decode(allocator, in) },
            // TODO(magurotuna)
            .zero_rtt => error.Unimplemented,
            // TODO(magurotuna)
            .handshake => error.Unimplemented,
            // TODO(magurotuna)
            .retry => error.Unimplemented,
            // TODO(magurotuna)
            .version_negotiation => error.Unimplemented,
            .one_rtt => unreachable,
        };
    }

    fn decodeAsShortHeaderPacket(allocator: std.mem.Allocator, in: *Bytes, destination_connection_id_length: usize) !Self {
        // Ensure that `in` has not been consumed yet.
        std.debug.assert(in.pos == 0);

        _ = allocator;
        _ = destination_connection_id_length;

        // TODO(magurotuna): implement decoding as OneRTT packet
        return error.Unimplemented;
    }
};

const form_bit: u8 = 0x80;
const fixed_bit: u8 = 0x40;
const key_phase_bit: u8 = 0x04;
const packet_type_mask = 0x30;
/// In QUIC v1 The length of Connection IDs must be less than or equal to 20,
/// as specified in https://datatracker.ietf.org/doc/html/rfc9000#section-17.2
pub const max_cid_len = 20;

fn isLongHeader(b: u8) bool {
    return b & form_bit != 0;
}
