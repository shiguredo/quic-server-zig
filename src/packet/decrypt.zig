const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const math = std.math;
const Bytes = @import("../bytes.zig").Bytes;
const tls = @import("../tls.zig");

pub const Error = error{
    InvalidPacket,
} || mem.Allocator.Error || crypto.errors.AuthenticationError || Bytes.Error;

/// Decrypt the payload and return the Bytes that points to the decrypted payload data.
/// Additionally, the given `in` will be advanced by the length of payload (including AEAD tag).
/// Note that the passed `in` must have consumed the header part of the packet plus the packet number part.
pub fn decrypt(
    in: *Bytes,
    packet_num: u64,
    packet_num_len: usize,
    pkt_num_and_payload_len: usize,
    aead_tag_length: usize,
    decryptor: tls.Cryptor,
) Error!Bytes {
    const header = in.split().former.buf;
    const payload_len = math.sub(usize, pkt_num_and_payload_len, packet_num_len) catch
        return error.InvalidPacket;

    if (payload_len < aead_tag_length)
        return error.InvalidPacket;

    const payload = try in.peekBytes(payload_len);

    const allocator = std.heap.page_allocator;
    var decrypted = try allocator.alloc(u8, payload_len - aead_tag_length);
    defer allocator.free(decrypted);

    try decryptor.decryptPayload(packet_num, header, payload, decrypted);

    // Create another view to the range of decrypted payload.
    var payload_bytes = Bytes{ .buf = try in.consumeBytes(payload_len - aead_tag_length) };
    mem.copy(u8, payload_bytes.buf, decrypted);

    // Skip the AEAD tag part since it's already processed.
    try in.skip(aead_tag_length);

    return payload_bytes;
}
