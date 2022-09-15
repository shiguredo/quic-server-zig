const std = @import("std");
const log = std.log;
const net = std.net;
const UdpSocket = @import("./udp.zig").UdpSocket;
const packet = @import("./packet.zig");
const Conn = @import("./conn.zig").Conn;
const Frame = @import("./frame/frame.zig").Frame;
const Ack = @import("./frame/frame.zig").Ack;

// key = ConnectionID
const ClientMap = std.StringHashMap(Conn);

pub fn main() !void {
    const addr = try net.Address.parseIp4("127.0.0.1", 5555);
    const sock = try UdpSocket.bind(addr);
    defer sock.deinit();
    var buf: [65536]u8 = undefined;

    // TODO(magurotuna): it may be better to use the c_allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var clients = ClientMap.init(allocator);
    defer clients.deinit();

    read_loop: while (true) {
        const recv = try sock.recvFrom(&buf);
        log.info("read {} bytes from {}. received data:\n{}\n", .{
            recv.num_bytes,
            recv.src,
            std.fmt.fmtSliceHexLower(buf[0..recv.num_bytes]),
        });

        const hdr = try packet.Header.decode(allocator, buf[0..recv.num_bytes]);
        defer hdr.deinit();

        if (clients.getEntry(hdr.dcid.items)) |client| {
            // The associated client is found, meaning that it's the existing connection.
            // TODO(magurotuna) implement
            _ = client;
            std.debug.print("UNIMPLEMENTED: the associated client is found.", .{});
        } else {
            // When there's no clients registered in the client map, it means this client is new.
            if (hdr.packet_type != .initial) {
                log.err("Initial packet is expected, but received `{s}`\n", .{@tagName(hdr.packet_type)});
                continue :read_loop;
            }

            // Create a new Conn
            //var conn = try Conn.new(allocator, hdr.scid.items, hdr.dcid.items);

            //// Do handshake
            //const client_initial_pkt =

            //// Initial packet has come from a client.
            //// We need to respond with Server Initial and then Handshake.
            //const server_initial = try generateServerInitial(
            //    allocator,
            //    decoded_packet.destination_connection_id(),
            //    decoded_packet.source_connection_id().?,
            //    decoded_packet.packet_number(),
            //    decoded_packet.payload(),
            //);

            //var send_buf: [65536]u8 = undefined;
            //const packet_to_send = packet.Packet{ .initial = server_initial };
            //defer packet_to_send.deinit();
            //const n_written = try packet_to_send.toBytes(&send_buf);
            //const n_sent = try sock.sendTo(send_buf[0..n_written], recv.src);
            //log.info("{} bytes have been sent to the client.\n", .{n_sent});
        }
    }
}

fn generateServerInitial(
    allocator: std.mem.Allocator,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    received_packet_number: u32,
    frames: []const Frame,
) !packet.Initial {
    var dcid = try std.ArrayList(u8).initCapacity(allocator, peer_connection_id.len);
    errdefer dcid.deinit();
    dcid.appendSliceAssumeCapacity(peer_connection_id);

    var scid = try std.ArrayList(u8).initCapacity(allocator, local_connection_id.len);
    errdefer scid.deinit();
    scid.appendSliceAssumeCapacity(local_connection_id);

    var token = try std.ArrayList(u8).initCapacity(allocator, 0);
    errdefer token.deinit();

    var payload = std.ArrayList(Frame).init(allocator);
    errdefer payload.deinit();

    try payload.append(.{
        .ack = .{
            .largest_acknowledged = @intCast(u64, received_packet_number),
            .ack_delay = 0, // TODO(magurotuna): calculate the right number
            .first_ack_range = 0, // TODO(magurotuna): calculate the right number
            .ack_range = Ack.AckRanges.init(allocator),
        },
    });

    for (frames) |frame| {
        switch (frame) {
            .crypto => |crypto_frame| {
                const data = crypto_frame.crypto_data;
                std.debug.assert(data == .client_hello);

                const cipher_suite = blk: {
                    for (data.client_hello.cipher_suites.data.items) |suite| {
                        if (suite == .TLS_AES_128_GCM_SHA256)
                            break :blk suite;
                    }
                    // TODO(magurotuna): we support TLS_AES_128_GCM_SHA256 only for now.
                    return error.NoSupportedCipherSuiteProvidedByClient;
                };

                const extensions = data.client_hello.extensions;

                const NamedGroup = @import("./tls/extension/supported_groups.zig").NamedGroup;
                const KeyExchange = @import("./tls/extension/key_share.zig").KeyExchange;
                var group_used: NamedGroup = undefined;
                var client_public_key: KeyExchange = undefined;
                extension_loop: for (extensions.data.items) |ext| {
                    switch (ext) {
                        .supported_groups => |sg| {
                            for (sg.named_group_list.data.items) |supported_group| {
                                if (supported_group == .x25519) {
                                    group_used = .x25519;
                                    continue :extension_loop;
                                }
                            }
                            // TODO(magurotuna): we support x25519 only for now.
                            return error.NoSupportedGroupProvidedByClient;
                        },
                        .key_share => |ks| {
                            for (ks.client_shares.data.items) |key| {
                                if (key.group == .x25519) {
                                    client_public_key = key.key_exchange;
                                    continue :extension_loop;
                                }
                            }
                            // TODO(magurotuna): we support x25519 only for now.
                            return error.NoSupportedGroupProvidedByClient;
                        },
                        else => {
                            // TODO(magurotuna)
                        },
                    }
                }

                const ServerHello = @import("./tls/server_hello.zig").ServerHello;
                const X25519 = std.crypto.dh.X25519;

                // TODO(magurotuna): For debugging purpose, we use fixed seed to create a key pair.
                // At some point we should change it to random values.
                const fixed_seed: [32]u8 = .{0x42} ** 32;
                const key_pair = try X25519.KeyPair.create(fixed_seed);

                try payload.append(.{
                    .crypto = .{
                        .offset = 0,
                        .crypto_data = .{
                            .server_hello = .{
                                .random = .{0x42} ** 32,
                                .legacy_session_id_echo = data.client_hello.legacy_session_id,
                                .cipher_suite = cipher_suite,
                                .extensions = try ServerHello.Extensions.fromSlice(allocator, &.{
                                    .{
                                        .supported_versions = .{
                                            // TODO(magurotuna): make this version number defined constantly
                                            .selected_version = 0x03_04,
                                        },
                                    },
                                    .{
                                        .key_share = .{
                                            .server_share = .{
                                                .group = .x25519,
                                                .key_exchange = try KeyExchange.fromSlice(allocator, &key_pair.public_key),
                                            },
                                        },
                                    },
                                }),
                            },
                        },
                    },
                });
            },
            else => {
                // TODO(magurotuna): handle other frame types
            },
        }
    }

    return packet.Initial{
        .destination_connection_id = dcid,
        .source_connection_id = scid,
        .token = token,
        .packet_number = 0,
        .payload = payload,
    };
}

test {
    std.testing.refAllDecls(@This());
}
