const std = @import("std");
const fs = std.fs;
const math = std.math;
const Allocator = std.mem.Allocator;
const TransportParams = @import("./transport_parameters.zig");

const Self = @This();

local_transport_params: TransportParams,
// TODO(magurotuna) Support certificate chain
der_certificate: []const u8,
private_key: []const u8,

/// Allocator that is used to allocate `der_certificate` and `private_key`.
allocator: Allocator,

pub const Builder = struct {
    local_transport_params: TransportParams = TransportParams.default(),
    // TODO(magurotuna) Support certificate chain
    der_certificate: ?[]u8 = null,
    private_key: ?[]u8 = null,

    allocator: Allocator,

    pub fn init(allocator: Allocator) Builder {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: Builder) void {
        self.local_transport_params.deinit();
        if (self.der_certificate) |cert| self.allocator.free(cert);
        if (self.private_key) |key| self.allocator.free(key);
    }

    /// Set the given transport_params to the builder.
    /// Note that the ownership of the given one is moved.
    pub fn setTransportParams(self: *Builder, transport_params: TransportParams) void {
        self.local_transport_params = transport_params;
    }

    pub fn loadCertificateFromDer(self: *Builder, path: []const u8) !void {
        const cert = try fs.cwd().readFileAlloc(self.allocator, path, math.maxInt(usize));
        self.der_certificate = cert;
    }

    pub fn loadPrivateKey(self: *Builder, path: []const u8) !void {
        const key = try fs.cwd().readFileAlloc(self.allocator, path, math.maxInt(usize));
        self.private_key = key;
    }

    pub fn build(self: Builder) error{FieldMissing}!Self {
        const cert = self.der_certificate orelse return error.FieldMissing;
        const key = self.private_key orelse return error.FieldMissing;

        return Self{
            .local_transport_params = self.local_transport_params,
            .der_certificate = cert,
            .private_key = key,
            .allocator = self.allocator,
        };
    }
};

pub fn deinit(self: Self) void {
    self.local_transport_params.deinit();
    self.allocator.free(self.der_certificate);
    self.allocator.free(self.private_key);
}
