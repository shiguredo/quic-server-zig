const std = @import("std");
const net = std.net;
const mem = std.mem;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;
const packet_number_space = @import("./packet_number_space.zig");
const Bytes = @import("./bytes.zig").Bytes;
const packet = @import("./packet.zig");
const version = @import("./version.zig");
const Frame = @import("./frame/frame.zig").Frame;

pub const Conn = struct {
    scid: ArrayList(u8),
    dcid: ArrayList(u8),
    pkt_num_spaces: packet_number_space.PacketNumberSpaces,

    /// The QUIC version used in the connection.
    version: u32 = version.quic_v1,
    /// Whether a version negotiation has already been done.
    did_version_negotiation: bool = false,
    /// Total number of received packets throughout this connection.
    recv_count: usize = 0,
    /// Total number of bytes received over the connection.
    recv_bytes: usize = 0,

    allocator: Allocator,

    const Self = @This();
    pub const Error = error{
        /// All of the received datagram has been processed.
        DoneReceive,
        /// Unable to process the givenn packet because of the unknown QUIC version.
        UnknownQUICVersion,
        /// Unable to process the given packet because it's in invalid form.
        InvalidPacket,
        /// Failure on a cryptographic operation.
        CryptoFail,
    };

    pub fn accept(
        allocator: Allocator,
        scid: []const u8,
        dcid: []const u8,
        local: net.Address,
        peer: net.Address,
    ) !Self {
        // TODO(magurotuna): use these values probably for path verification
        _ = local;
        _ = peer;

        var scid_owned = try ArrayList(u8).initCapacity(allocator, scid.len);
        errdefer scid_owned.deinit();
        scid_owned.appendSliceAssumeCapacity(scid);

        var dcid_owned = try ArrayList(u8).initCapacity(allocator, dcid.len);
        errdefer dcid_owned.deinit();
        dcid_owned.appendSliceAssumeCapacity(dcid);

        // Initialize three packet number spaces.
        var pkt_num_spaces = try packet_number_space.PacketNumberSpaces.init(allocator);
        errdefer pkt_num_spaces.deinit();
        // For the Initial space, we can derive data needed to encrypt/decrypt right away.
        try pkt_num_spaces.setInitialCryptor(allocator, dcid, true);

        return Self{
            .scid = scid_owned,
            .dcid = dcid_owned,
            .pkt_num_spaces = pkt_num_spaces,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: Self) void {
        self.source_connection_id.deinit();
        self.destination_connection_id.deinit();
    }

    pub fn recv(self: *Self, buf: []u8, local: net.Address, peer: net.Address) !usize {
        _ = local;
        _ = peer;

        var done: usize = 0;
        var left: usize = buf.len;

        // One UDP datagram may contain multiple QUIC packets. We handle each packet one by one.
        while (left > 0) {
            const read = try self.recvSingle(buf);
            left -= read;
            done += read;
        }

        return done;
    }

    /// Process just one QUIC packet from the buffer and returns the number of bytes processed.
    fn recvSingle(self: *Self, buf: []u8) !usize {
        var input = Bytes{ .buf = buf };

        var hdr = try packet.Header.fromBytes(self.allocator, &input, self.dcid.items.len);
        defer hdr.deinit();

        if (hdr.packet_type == .version_negotiation) {
            self.handleVersionNegotiationPacket();

            // RFC 9000 states:
            // > a Version Negotiation packet consumes an entire UDP datagram.
            // Thus we can think of it as the final packet in the buffer.
            return Error.DoneReceive;
        }

        if (hdr.packet_type == .retry) {
            self.handleRetryPacket();

            // RFC 9000 states:
            // > A server MUST NOT send more than one Retry packet in response to a single UDP datagram.
            // Thus we can think of it as the final packet in the buffer.
            return Error.DoneReceive;
        }

        if (!self.did_version_negotiation) {
            if (!version.isSupported(hdr.version))
                return Error.UnknownQUICVersion;

            self.did_version_negotiation = true;
            self.version = hdr.version;
        }

        const pkt_num_and_payload_len = if (hdr.packet_type == .one_rtt)
            // 1-RTT packets (i.e. long header packets) don't have the Length field, so the length of
            // the payload is implicit. We use the the number of unprocessed bytes as the packet number
            // plus payload length.
            input.remainingCapacity()
        else blk: {
            // Packet types we need to consider here are:
            // - Initial
            // - Handshake
            // - 0-RTT
            // and all of these have the Length field at the next position of the buffer.
            const len = try input.consumeVarInt();
            break :blk @intCast(usize, len);
        };

        if (pkt_num_and_payload_len > input.remainingCapacity())
            return Error.InvalidPacket;

        // Packets with the type of Retry or Version Negotiation are already handled and returned,
        // so we can definitely find the packet number space that corresponds to the given packet type.
        var pkt_num_space = self.pkt_num_spaces.getByPacketType(hdr.packet_type) catch unreachable;
        const decryptor = if (pkt_num_space.decryptor) |d| d else {
            // TODO(magurotuna): in case of 0-RTT packets, we need to buffer the received data
            // until the decryptor is ready so that we can decrypt them later.
            // But we skip implementing it for now.

            return Error.CryptoFail;
        };

        try hdr.unprotect(&input, decryptor);

        // TODO(magurotuna): The packet number we got by unprotecting the header is truncated;
        // although packet numbers can be ranged from 0 to 2^62 - 1, it's encoded in 4 bytes at the longest.
        // We need to recover to get the true packet number by applying the algorithm shown in RFC:
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-packet-number-encoding-and-
        // But we skip this for now.
        const pkt_num = hdr.packet_num;

        // Ignore a packet that the connection has already seen.
        if (pkt_num_space.recv_packet_number.contains(pkt_num))
            return Error.DoneReceive;

        // TODO(magurotuna): don't use the hardcoded value. Maybe Cryptor should have a method to return AEAD tag length?
        const aead_tag_len = 16;
        var payload = try packet.decryptPayload(
            &input,
            pkt_num,
            hdr.packet_num_len,
            pkt_num_and_payload_len,
            aead_tag_len,
            decryptor,
        );

        // Packets with no frames are invalid.
        if (payload.buf.len == 0)
            return Error.InvalidPacket;

        // Process all frames in the payload.
        while (payload.remainingCapacity() > 0) {
            // TODO(magurotuna): do the following
            // 1. Parse one frame
            // 2. Process the parsed frame depending on the frame type
            const frame = try Frame.decode(self.allocator, &payload);
            try self.handleFrame(frame, pkt_num_space);
        }

        // Update the state of the packet number space with the current packet number.
        try pkt_num_space.updatePacketNumber(pkt_num);

        self.recv_count += 1;
        // At this point, `input` should point to the very end of the packet, meaning that
        // `input.pos` is the number of bytes we have just consumed in this method.
        const read = input.pos;
        self.recv_bytes += read;

        return read;
    }

    /// https://www.rfc-editor.org/rfc/rfc9000.html#name-version-negotiation-packet
    ///
    /// > The Version Negotiation packet does not include the Packet Number and Length fields
    /// > present in other packets that use the long header form. Consequently, **a Version
    /// > Negotiation packet consumes an entire UDP datagram**.
    ///
    /// Version Negotiation Packet {
    ///   Header Form (1) = 1,
    ///   Unused (7),
    ///   Version (32) = 0,
    ///   Destination Connection ID Length (8),
    ///   Destination Connection ID (0..2040),
    ///   Source Connection ID Length (8),
    ///   Source Connection ID (0..2040),
    ///   Supported Version (32) ...,
    /// }
    fn handleVersionNegotiationPacket(self: *Self) void {
        if (self.did_version_negotiation)
            return;

        if (self.recv_count > 0)
            return;

        // A Version Negotiation packet is sent from a server only; the client never sends.
        // Since we are implementing QUIC server, we just ignore Version Negotiation in received packets for now.
        // See also: https://www.rfc-editor.org/rfc/rfc9000.html#name-version-negotiation
        return;

        // TODO(magurotuna): Implement the logics necessary to handle the version negotiation
        // packet sent from the server.
    }

    fn handleRetryPacket(self: *Self) void {
        _ = self;
        // A Retry packet is sent from a server only; the client never sends.
        // Since we are implementing QUIC server, we just ignore Version Negotiation in received packets for now.
        // See also: https://www.rfc-editor.org/rfc/rfc9000.html#name-retry-packet
        return;
    }

    fn handleFrame(
        self: *Self,
        frame: Frame,
        pkt_num_space: *packet_number_space.PacketNumberSpace,
    ) !void {
        _ = self;
        _ = pkt_num_space;
        switch (frame) {
            .padding => {},
            .ack => |ack| {
                // TODO
                _ = ack;
            },
            .crypto => |crypto| {
                // TODO
                _ = crypto;
            },
            .connection_close => |cc| {
                // TODO
                _ = cc;
            },
        }
    }
};
