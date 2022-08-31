const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("quic-server-zig", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    addInternalPackages(exe);
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest("src/main.zig");
    exe_tests.setTarget(target);
    exe_tests.setBuildMode(mode);
    addInternalPackages(exe_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);
}

fn pkgPath(comptime pathRelativeToProjectRoot: []const u8) std.build.FileSource {
    const root = comptime std.fs.path.dirname(@src().file).?;
    return .{
        .path = root ++ std.fs.path.sep_str ++ pathRelativeToProjectRoot,
    };
}

fn addInternalPackages(step: *std.build.LibExeObjStep) void {
    step.addPackage(.{
        .name = "variable_length_vector",
        .source = pkgPath("src/variable_length_vector.zig"),
    });

    step.addPackage(.{
        .name = "bytes",
        .source = pkgPath("src/bytes.zig"),
    });

    step.addPackage(.{
        .name = "utils",
        .source = pkgPath("src/utils.zig"),
    });
}
