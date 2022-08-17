const std = @import("std");
const ArrayList = std.ArrayList;

/// An enum to distinguish packet number spaces.
/// https://datatracker.ietf.org/doc/html/rfc9000#section-12.3
pub const PacketNumberSpace = enum {
    initial,
    handshake,
    application_data,
};

pub fn Initial(comptime PacketNumber: type, comptime Payload: type) type {
    return struct {
        version: u32,
        destination_connection_id: ArrayList(u8),
        source_connection_id: ArrayList(u8),
        token: ArrayList(u8),
        packet_number: PacketNumber,
        payload: Payload,
    };
}

const ProtectedPacketNumber = struct {};
const ProtectedPaylaod = struct {
    payload: ArrayList(u8),
};

const PacketNumber = u64;
const EnctyptedPayload = struct {
    payload: ArrayList(u8),
};

const PlainPayload = struct {
    payload: ArrayList(u8),
};

pub const ProtectedInitial = Initial(ProtectedPacketNumber, ProtectedPayload);
pub const EncryptedInitial = Initial(PacketNumber, EnctyptedPayload);
pub const PlainInitial = Initial(PacketNumber, PlainPayload);
