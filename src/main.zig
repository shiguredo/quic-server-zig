const std = @import("std");
const net = std.net;
const UdpSocket = @import("./udp.zig").UdpSocket;
const Header = @import("./header.zig").Header;

pub fn main() !void {
    const addr = try net.Address.parseIp4("127.0.0.1", 5555);
    const sock = try UdpSocket.bind(addr);
    defer sock.deinit();
    var buf: [65536]u8 = undefined;

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    while (true) {
        const recv = try sock.recvFrom(&buf);
        std.log.info("read {} bytes from {}. received data: {}\n", .{
            recv.num_bytes,
            recv.src,
            std.fmt.fmtSliceHexLower(buf[0..recv.num_bytes]),
        });

        const decoded = try Header.decode(allocator, &buf, 9);
        defer decoded.deinit();

        std.log.info("received header:\n{}\n", .{decoded});
    }
}

test {
    std.testing.refAllDecls(@This());
}
