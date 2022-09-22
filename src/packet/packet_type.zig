const PacketNumberSpace = @import("../packet_number_space.zig").PacketNumberSpace;

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

    const Self = @This();

    pub fn fromPacketNumberSpace(space_type: PacketNumberSpace.SpaceType) Self {
        return switch (space_type) {
            .initial => .initial,
            .handshake => .handshake,
            .application_data => .one_rtt,
        };
    }
};
