const std = @import("std");
const Bytes = @import("./bytes.zig").Bytes;
const crypto = @import("./crypto.zig");
const Initial = @import("./packet/initial.zig").Initial;
const ZeroRtt = @import("./packet/zero_rtt.zig").ZeroRtt;
const Handshake = @import("./packet/handshake.zig").Handshake;
const Retry = @import("./packet/retry.zig").Retry;
const VersionNegotiation = @import("./packet/version_negotiation.zig").VersionNegotiation;
const OneRtt = @import("./packet/one_rtt.zig").OneRtt;

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

    pub fn decode(allocator: std.mem.Allocator, buf: []u8, destination_connection_id_length: usize) !Self {
        var bs = Bytes{ .buf = buf };
        return fromBytes(allocator, &bs, destination_connection_id_length);
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

    fn fromBytes(allocator: std.mem.Allocator, bs: *Bytes, destination_connection_id_length: usize) !Self {
        const first = try bs.consume(u8);

        if (!isLongHeader(first)) {
            _ = destination_connection_id_length;
            // TODO(magurotuna): decode as OneRTT packet
            return error.Unimplemented;
        }

        const ver = try bs.consume(u32);
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
            .initial => .{ .initial = try Initial.fromBytes(allocator, bs, first, ver) },
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
