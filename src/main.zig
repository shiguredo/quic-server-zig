const std = @import("std");
const log = std.log;
const net = std.net;
const UdpSocket = @import("./udp.zig").UdpSocket;
const packet = @import("./packet.zig");
const Conn = @import("./conn.zig").Conn;
const Frame = @import("./frame/frame.zig").Frame;
const Ack = @import("./frame/frame.zig").Ack;

const udp_recv_buf_size = 65535;
const udp_send_buf_size = 1350;

// key = ConnectionID
const ClientMap = std.StringHashMap(Conn);

pub fn main() !void {
    const addr = try net.Address.parseIp4("127.0.0.1", 5555);
    const sock = try UdpSocket.bind(addr);
    defer sock.deinit();

    var recv_buf: [udp_recv_buf_size]u8 = undefined;
    var send_buf: [udp_send_buf_size]u8 = undefined;

    // TODO(magurotuna): it may be better to use the c_allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var clients = ClientMap.init(allocator);
    defer clients.deinit();

    loop: while (true) {
        // Receive data from a client.
        const recv = try sock.recvFrom(&recv_buf);
        log.info("read {} bytes from {}. received data:\n{}\n", .{
            recv.num_bytes,
            recv.src,
            std.fmt.fmtSliceHexLower(recv_buf[0..recv.num_bytes]),
        });

        // Parse the received data so that we can determine if it's a new client or not.
        const hdr = try packet.Header.decode(allocator, recv_buf[0..recv.num_bytes]);
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
                continue :loop;
            }

            // Create a new Conn
            var conn = try Conn.accept(allocator, hdr.scid.items, hdr.dcid.items, addr, recv.src);

            const n_processed = try conn.recv(recv_buf[0..recv.num_bytes], addr, recv.src);
            _ = n_processed;

            client.value_ptr.* = conn;
        }

        // Send response back to the client.
        const n_written = try client.value_ptr.send(&send_buf);
        _ = try sock.sendTo(send_buf[0..n_written], recv.src);
    }
}

test {
    std.testing.refAllDecls(@This());
}
