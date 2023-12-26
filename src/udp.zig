// The implementation in this file is mostly brought from [MasterQ32/zig-network](https://github.com/MasterQ32/zig-network).
// MIT License
// Copyright (c) 2020 Felix Queißner

const std = @import("std");
const net = std.net;
const os = std.os;
const mem = std.mem;
const log = std.log;
const builtin = @import("builtin");

pub const UdpSocket = struct {
    const Self = @This();

    sockfd: os.socket_t,

    pub fn bind(addr: net.Address) !Self {
        const sockfd = try os.socket(addr.any.family, os.SOCK.DGRAM, 0);
        errdefer os.close(sockfd);
        try os.setsockopt(sockfd, os.SOL.SOCKET, os.SO.REUSEPORT, &mem.toBytes(@as(c_int, 1)));
        try os.setsockopt(sockfd, os.SOL.SOCKET, os.SO.REUSEADDR, &mem.toBytes(@as(c_int, 1)));
        try os.bind(sockfd, &addr.any, addr.getOsSockLen());
        return Self{ .sockfd = sockfd };
    }

    pub fn deinit(self: Self) void {
        os.close(self.sockfd);
    }

    const ReceiveFrom = struct {
        num_bytes: usize,
        src: net.Address,
    };

    pub fn recvFrom(self: Self, buf: []u8) !ReceiveFrom {
        const flags = comptime if (builtin.os.tag == .linux) os.linux.MSG.NOSIGNAL else 0;

        // Use the ipv6 sockaddr to guarantee any data will fit.
        var addr: os.sockaddr.in6 align(4) = undefined;
        var size: os.socklen_t = @sizeOf(os.sockaddr.in6);

        var addr_ptr = @as(*os.sockaddr, @ptrCast(&addr));
        const len = try os.recvfrom(self.sockfd, buf, flags | 4, addr_ptr, &size);

        return ReceiveFrom{
            .num_bytes = len,
            .src = try parseAddr(addr_ptr, size),
        };
    }

    pub fn sendTo(self: Self, buf: []const u8, to: net.Address) !usize {
        return os.sendto(self.sockfd, buf, 0, &to.any, to.getOsSockLen());
    }
};

fn parseAddr(raw_addr: *const os.sockaddr, size: usize) !net.Address {
    switch (raw_addr.family) {
        os.AF.INET => {
            if (size < @sizeOf(os.sockaddr.in))
                return error.InsufficientBytes;

            const value = @as(*const os.sockaddr.in, @ptrCast(@alignCast(raw_addr)));
            return net.Address{
                .in = net.Ip4Address.init(@as([4]u8, @bitCast(value.addr)), mem.bigToNative(u16, value.port)),
            };
        },
        os.AF.INET6 => {
            if (size < @sizeOf(os.sockaddr.in6))
                return error.InsufficientBytes;

            const value = @as(*const os.sockaddr.in6, @ptrCast(@alignCast(raw_addr)));
            return net.Address{
                .in6 = net.Ip6Address.init(value.addr, mem.bigToNative(u16, value.port), 0, value.scope_id),
            };
        },
        else => {
            log.warn("got invalid socket address: {}\n", .{raw_addr});
            return error.UnsupportedAddressFamily;
        },
    }
}
