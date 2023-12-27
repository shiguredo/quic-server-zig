const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const optimize = b.standardOptimizeOption(.{});

    const variable_length_vector = b.addModule("variable_length_vector", .{
        .source_file = pkgPath("src/variable_length_vector.zig"),
    });

    const bytes = b.addModule("bytes", .{
        .source_file = pkgPath("src/bytes.zig"),
    });

    const utils = b.addModule("utils", .{
        .source_file = pkgPath("src/utils.zig"),
    });

    const exe = b.addExecutable(.{
        .name = "quic-server-zig",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.addModule("variable_length_vector", variable_length_vector);
    exe.addModule("bytes", bytes);
    exe.addModule("utils", utils);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe_tests.addModule("variable_length_vector", variable_length_vector);
    exe_tests.addModule("bytes", bytes);
    exe_tests.addModule("utils", utils);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);
}

fn pkgPath(comptime pathRelativeToProjectRoot: []const u8) std.build.FileSource {
    const root = comptime std.fs.path.dirname(@src().file).?;
    return .{
        .path = root ++ std.fs.path.sep_str ++ pathRelativeToProjectRoot,
    };
}
