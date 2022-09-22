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

        var client = try clients.getOrPut(hdr.dcid.items);
        if (client.found_existing) {
            // The associated client is found, meaning that it's the existing connection.
            // TODO(magurotuna) implement
            std.debug.print("UNIMPLEMENTED: the associated client is found.", .{});
        } else {
            // When there's no clients registered in the client map, it means this client is new.
            if (hdr.packet_type != .initial) {
                log.err("Initial packet is expected, but received `{s}`\n", .{@tagName(hdr.packet_type)});
                continue :read_loop;
            }

            // Create a new Conn
            var conn = try Conn.accept(allocator, hdr.scid.items, hdr.dcid.items, addr, recv.src);

            const n_processed = try conn.recv(buf[0..recv.num_bytes], addr, recv.src);
            _ = n_processed;

            client.value_ptr.* = conn;

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

test {
    std.testing.refAllDecls(@This());
}
