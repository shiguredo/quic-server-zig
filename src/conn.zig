const std = @import("std");
const net = std.net;
const mem = std.mem;
const math = std.math;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;
const packet_number_space = @import("./packet_number_space.zig");
const bytes = @import("./bytes.zig");
const packet = @import("./packet.zig");
const version = @import("./version.zig");
const Frame = @import("./frame/frame.zig").Frame;
const tls = @import("./tls.zig");
const encode_crypto_header = @import("./frame/crypto.zig").encode_crypto_header;

pub const Conn = struct {
    scid: ArrayList(u8),
    dcid: ArrayList(u8),
    pkt_num_spaces: packet_number_space.PacketNumberSpaces,
    handshake: tls.Handshake,

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
        /// All of the QUIC packets to be sent has been processed.
        DoneSend,
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

        var handshake = try tls.Handshake.init(allocator, .{});
        errdefer handshake.deinit();

        return Self{
            .scid = scid_owned,
            .dcid = dcid_owned,
            .pkt_num_spaces = pkt_num_spaces,
            .handshake = handshake,
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
            const read = self.recvSingle(buf[done..]) catch |e| switch (e) {
                error.DoneReceive => break,
                else => return e,
            };
            left -= read;
            done += read;
        }

        return done;
    }

    /// Process just one QUIC packet from the buffer and returns the number of bytes processed.
    fn recvSingle(self: *Self, buf: []u8) !usize {
        var input = bytes.Bytes{ .buf = buf };

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

        // At this point version negotiation was already performed, so
        // ignore packets that don't match the connection's version.
        if (hdr.packet_type != .one_rtt and hdr.version != self.version)
            return Error.DoneReceive;

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

            // We just discard the packet if the encryption setup is not yet ready.
            //
            // https://www.rfc-editor.org/rfc/rfc9000.html#name-coalescing-packets
            //
            // > For example, if decryption fails (because the keys are not available or for any other reason),
            // > the receiver MAY either discard or buffer the packet for later processing and MUST attempt to
            // > process the remaining packets.
            return Error.DoneReceive;
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

        // In order to prevent ACK frames from being sent back and forth infinitely, we only send ACK frames in response to ack-eliciting packets.
        // This flag maintains whether the received packet is ack-eliciting or not.
        //
        // https://www.rfc-editor.org/rfc/rfc9000.html#name-generating-acknowledgments
        var ack_elicited = false;

        // Process all frames in the payload.
        while (payload.remainingCapacity() > 0) {
            const frame = try Frame.decode(self.allocator, &payload);
            try self.handleFrame(frame, pkt_num_space);

            ack_elicited = ack_elicited or frame.ackEliciting();
        }

        // Update the state of the packet number space with the current packet number.
        try pkt_num_space.updatePacketNumber(pkt_num);
        // Update the state regarding whether we need to ACK for this packet number space.
        pkt_num_space.ack_elicited = pkt_num_space.ack_elicited or ack_elicited;

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
        switch (frame) {
            .padding => {},
            .ack => |ack| {
                // TODO
                _ = ack;
            },
            .crypto => |crypto| {
                try pkt_num_space.crypto_stream.recv.write(crypto.crypto_data);
                const enc_level = pkt_num_space.toEncryptionLevel();
                var crypto_buf: [1024]u8 = undefined;

                while (true) {
                    const n_emit = pkt_num_space.crypto_stream.recv.emit(&crypto_buf) catch break;
                    try self.handshake.recv(
                        enc_level,
                        crypto_buf[0..n_emit],
                    );
                }

                try self.doHandshake();
            },
            .connection_close => |cc| {
                // TODO
                _ = cc;
            },
        }
    }

    fn doHandshake(self: *Self) !void {
        const res = try self.handshake.proceed();
        if (res) |key_change| switch (key_change) {
            .handshake => |hs| {
                self.pkt_num_spaces.handshake.encryptor = hs.keys.local;
                self.pkt_num_spaces.handshake.decryptor = hs.keys.remote;
            },
        };

        // Move TLS Handshake messages to the send buffer dedicated to CRYPTO frames.
        try self.pkt_num_spaces.fetchTlsMessages(&self.handshake);
    }

    pub fn send(self: *Self, buf: []u8) !usize {
        if (buf.len == 0)
            return error.BufferTooShort;

        var done: usize = 0;
        var left: usize = buf.len;

        // Write one or more QUIC packets into the buffer as long as there's space.
        // TODO(magurotuna): probably we should respect the maximum UDP payload size limit.
        while (left > 0) {
            const res = self.sendSingle(buf[done..]) catch |e| switch (e) {
                error.DoneSend => break,
                else => return e,
            };
            done += res.n_written;
            left -= res.n_written;

            // No other packets must not be put after a OneRTT (short header) packet.
            //
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-12.2
            //
            // > A packet with a short header does not include a length, so it can only
            // > be the last packet included in a UDP datagram.
            if (res.packet_type == .one_rtt)
                break;
        }

        return done;
    }

    const SendSignleResult = struct {
        n_written: usize,
        packet_type: packet.PacketType,
    };

    pub fn sendSingle(self: *Self, buf: []u8) !SendSignleResult {
        if (buf.len == 0)
            return error.BufferTooShort;

        var out = bytes.Bytes{ .buf = buf };
        var left = out.remainingCapacity();

        const pkt_type = self.pkt_num_spaces.writePacketType() orelse
            return error.DoneSend;

        const pkt_num_space = self.pkt_num_spaces.getByPacketType(pkt_type) catch unreachable;

        const pkt_num = pkt_num_space.next_packet_number;
        // TODO(magurotuna): use shorter length if pkt_num is a small number
        const pkt_num_len = 4;

        const hdr = try packet.Header.new(
            self.allocator,
            pkt_type,
            self.version,
            self.dcid.items,
            self.scid.items,
            pkt_num,
            pkt_num_len,
            null,
            null,
            false,
        );

        try hdr.toBytes(&out);

        const aead_len = 16;
        // We make an assumption that the `Length` field, which is only present in long
        // header packets, can be encoded with a 2-byte variable-length integer.
        const payload_length_len: usize = if (pkt_type == .one_rtt) 0 else 2;
        // Minimum length of bytes required to write the packet.
        const overhead = out.pos + pkt_num_len + aead_len + payload_length_len;

        left -= math.sub(usize, left, overhead) catch return error.DoneSend;

        const length_field_offset = out.pos;
        // The total length of payload is unknown at this point. We reserve certain bytes
        // so we can populate it later.
        try out.skip(payload_length_len);

        // TODO(magurotuna): use the packet number encoding algorithm
        try out.put(u32, @intCast(u32, pkt_num));

        const payload_offset = out.pos;

        // ACK frame
        if (pkt_num_space.recv_packet_need_ack.count() > 0 and pkt_num_space.ack_elicited) {
            const ack_delay_micro = pkt_num_space.largest_recv_packet_ack_timer.read() / 1000;

            // TODO(magurotuna): This value should be configured via transport parameters.
            // For the moment, we use the default value as defined in the RFC.
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.26.1
            const ack_delay_exponent = 3;

            const ack_delay = ack_delay_micro / math.pow(u64, 2, ack_delay_exponent);

            const frame = Frame{
                .ack = .{
                    .ack_delay = ack_delay,
                    .ranges = try pkt_num_space.recv_packet_need_ack.clone(),
                },
            };
            defer frame.deinit();

            try frame.encode(&out);

            // Now that we have sent an ACK frame, we reset the ack_elicited field.
            pkt_num_space.ack_elicited = false;
        }

        // CRYPTO frame
        if (pkt_num_space.crypto_stream.isFlushable()) {
            const crypto_offset = pkt_num_space.crypto_stream.send.offset;
            const hdr_len = 1 + // frame type
                bytes.varIntLength(@intCast(u64, crypto_offset)) + // offset
                2; // length, always encode as 2-byte varint

            if (math.sub(usize, left, hdr_len)) |max_len| {
                var crypto_hdr = bytes.Bytes{ .buf = try out.consumeBytes(hdr_len) };

                // Write crypto data before the header to figure out the data length.
                const crypto_data_len = pkt_num_space.crypto_stream.send.emit(try out.peekBytes(max_len));
                try out.skip(crypto_data_len);

                // Write the frame header.
                try encode_crypto_header(crypto_offset, crypto_data_len, &crypto_hdr);
            } else |_| {
                // There's no room enough for the CRYPTO frame. Just skip this encoding.
            }
        }

        // Update the payload length with the actual value.
        const payload_end_offset = out.pos;
        var length_field_buf = (try out.splitAt(length_field_offset)).latter;
        try length_field_buf.putVarInt(@intCast(u64, payload_end_offset - payload_offset));

        pkt_num_space.next_packet_number += 1;

        return SendSignleResult{
            .n_written = 0,
            .packet_type = pkt_type,
        };
    }
};
