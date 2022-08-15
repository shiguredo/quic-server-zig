const std = @import("std");
const net = std.net;
const UdpSocket = @import("./udp.zig").UdpSocket;

pub fn main() !void {
    const addr = try net.Address.parseIp4("127.0.0.1", 5555);
    const sock = try UdpSocket.bind(addr);
    defer sock.deinit();
    var buf: [65536]u8 = undefined;

    while (true) {
        const recv = try sock.recvFrom(&buf);
        std.log.info("read {} bytes from {}. received data: {s}\n", .{
            recv.num_bytes,
            recv.src,
            buf[0..recv.num_bytes],
        });
    }
}
