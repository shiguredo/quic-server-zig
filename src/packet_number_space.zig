const std = @import("std");
const EnumArray = std.EnumArray;
const crypto = @import("./crypto.zig");
const tls = @import("./tls.zig");

pub const PacketNumberSpaces = EnumArray(PacketNumberSpaceKind, PacketNumberSpace);

fn HashSet(comptime K: type) type {
    return std.AutoHashMap(K, void);
}

pub const RangeSet = struct {
    // TODO(magurotuna)
};

pub const Stream = struct {
    // TODO(magurotuna)
};

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-numbers
///
/// > Packet numbers are divided into three spaces in QUIC:
/// > Initial space:          All Initial packets (Section 17.2.2) are in this space.
/// > Handshake space:        All Handshake packets (Section 17.2.4) are in this space.
/// > Application data space: All 0-RTT (Section 17.2.3) and 1-RTT (Section 17.3.1) packets are in this space.
pub const PacketNumberSpaceKind = enum {
    initial,
    handshake,
    application_data,
};

/// https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-numbers
///
/// > Packet numbers are divided into three spaces in QUIC:
/// > Initial space:          All Initial packets (Section 17.2.2) are in this space.
/// > Handshake space:        All Handshake packets (Section 17.2.4) are in this space.
/// > Application data space: All 0-RTT (Section 17.2.3) and 1-RTT (Section 17.3.1) packets are in this space.
///
/// > As described in [QUIC-TLS], each packet type uses different protection keys.
///
/// > Conceptually, a packet number space is the context in which a packet can be processed and acknowledged.
/// > Initial packets can only be sent with Initial packet protection keys and acknowledged in packets that
/// > are also Initial packets. Similarly, Handshake packets are sent at the Handshake encryption level and
/// > can only be acknowledged in Handshake packets.
pub const PacketNumberSpace = struct {
    largest_recv_packet_number: u64 = 0,
    largest_recv_packet_time: u64 = 0,
    largest_recv_non_probing_packet_number: u64 = 0,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-numbers
    ///
    /// > Packet numbers in each space start at packet number 0. Subsequent packets sent in
    /// > the same packet number space MUST increase the packet number by at least one.
    next_packet_number: u64 = 0,

    recv_packet_need_ack: RangeSet = .{},

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-numbers
    ///
    /// > Endpoints that track all individual packets for the purposes of detecting duplicates are
    /// > at risk of accumulating excessive state. The data required for detecting duplicates can be
    /// > limited by maintaining a minimum packet number below which all packets are immediately dropped.
    ///
    /// This field is used to detect duplicate packets. We use HashSet to store the already-received
    /// packet numbers, but it can use too much memory. We should reduce the memory usage by adopting
    /// the technique introduced in the RFC.
    // recv_packet_number: HashSet(u64),

    ack_elicited: bool = false,

    encryptor: ?tls.Cryptor = null,
    decryptor: ?tls.Cryptor = null,

    zero_rtt_encryptor: ?tls.Cryptor = null,
    zero_rtt_decryptor: ?tls.Cryptor = null,

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-crypto-frames
    ///
    /// > CRYPTO frames are functionally identical to STREAM frames, except that they do not
    /// > bear a stream identifier; they are not flow controlled; and they do not carry markers
    /// > for optional offset, optional length, and the end of the stream.
    ///
    /// > Unlike STREAM frames, which include a stream ID indicating to which stream the data
    /// > belongs, the CRYPTO frame carries data for a single stream **per encryption level**.
    /// > The stream does not have an explicit end, so CRYPTO frames do not have a FIN bit.
    crypto_stream: Stream = .{},
};
