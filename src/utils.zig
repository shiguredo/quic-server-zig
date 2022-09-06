const std = @import("std");
const mem = std.mem;
const meta = std.meta;
const builtin = std.builtin;

/// Calculates how many bytes a value of type `T` takes in the memory.
/// This is not always identical to the builtin `@sizeOf` because the builtin
/// one takes padding into account, while this function does not.
/// J
/// For instance, `@sizeOf(u24)` returns `4` on 64 bit machines, while this returns `3`.
pub fn sizeOf(comptime T: type) comptime_int {
    return switch (@typeInfo(T)) {
        .Int => |i| @divExact(i.bits, 8),
        .Array => |a| a.len * sizeOf(a.child),
        else => @compileError("`sizeOf` only supports `Int` or `Array`"),
    };
}

test "sizeOf" {
    try std.testing.expectEqual(1, sizeOf(u8));
    try std.testing.expectEqual(2, sizeOf(u16));
    try std.testing.expectEqual(3, sizeOf(u24));
    try std.testing.expectEqual(4, sizeOf(u32));
    try std.testing.expectEqual(8, sizeOf(u64));

    try std.testing.expectEqual(3, sizeOf([3]u8));
    try std.testing.expectEqual(4, sizeOf([2]u16));
    try std.testing.expectEqual(6, sizeOf([2]u24));
}

/// Returns declarations that belong to the given type.
/// Unlike `std.meta.declarations`, this returns `null` if `T` never has declaratons.
pub fn declarations(comptime T: type) ?[]const builtin.Type.Declaration {
    return switch (@typeInfo(T)) {
        .Struct => |info| info.decls,
        .Enum => |info| info.decls,
        .Union => |info| info.decls,
        .Opaque => |info| info.decls,
        else => null,
    };
}

test "declarations" {
    {
        const Enum = enum {
            A,

            fn a() void {}
        };

        const decls = declarations(Enum);
        try std.testing.expect(decls != null);
        try std.testing.expectEqual(@as(usize, 1), decls.?.len);
        try std.testing.expect(mem.eql(u8, decls.?[0].name, "a"));
    }

    {
        const Struct = struct {
            fn a() void {}
        };

        const decls = declarations(Struct);
        try std.testing.expect(decls != null);
        try std.testing.expectEqual(@as(usize, 1), decls.?.len);
        try std.testing.expect(mem.eql(u8, decls.?[0].name, "a"));
    }

    {
        const Union = union {
            a: u8,

            fn a() void {}
        };

        const decls = declarations(Union);
        try std.testing.expect(decls != null);
        try std.testing.expectEqual(@as(usize, 1), decls.?.len);
        try std.testing.expect(mem.eql(u8, decls.?[0].name, "a"));
    }

    {
        const Opaque = opaque {
            fn a() void {}
        };

        const decls = declarations(Opaque);
        try std.testing.expect(decls != null);
        try std.testing.expectEqual(@as(usize, 1), decls.?.len);
        try std.testing.expect(mem.eql(u8, decls.?[0].name, "a"));
    }

    {
        const Int = u32;

        const decls = declarations(Int);
        try std.testing.expect(decls == null);
    }

    {
        const Array = [4]u8;

        const decls = declarations(Array);
        try std.testing.expect(decls == null);
    }
}

/// Returns true if the given type `T` has a public `deinit` method.
pub fn hasDeinit(comptime T: type) bool {
    return meta.trait.hasFn("deinit")(T);
}

test "hasDeinit" {
    try std.testing.expect(!hasDeinit(u8));
    try std.testing.expect(!hasDeinit([4]u8));
    try std.testing.expect(!hasDeinit(bool));
    try std.testing.expect(!hasDeinit([]u8));
    try std.testing.expect(!hasDeinit(struct {}));
    try std.testing.expect(!hasDeinit(enum {}));
    try std.testing.expect(!hasDeinit(union {}));
    try std.testing.expect(!hasDeinit(struct {
        // private `deinit` is ignored
        fn deinit() void {}
    }));
    try std.testing.expect(!hasDeinit(enum {
        // private `deinit` is ignored
        fn deinit() void {}
    }));
    try std.testing.expect(!hasDeinit(union {
        // private `deinit` is ignored
        fn deinit() void {}
    }));

    try std.testing.expect(hasDeinit(struct {
        pub fn deinit() void {}
    }));
    try std.testing.expect(hasDeinit(enum {
        pub fn deinit() void {}
    }));
    try std.testing.expect(hasDeinit(union {
        pub fn deinit() void {}
    }));
    try std.testing.expect(hasDeinit(std.ArrayList(u8)));
}
