// MIT License
// Copyright (c) 2022 Yusuke Tanaka
// https://github.com/magurotuna/zig-deque/blob/1b042d06e55cc6ee0b9d71984ed6c15e9d378d89/LICENSE

const std = @import("std");
const mem = std.mem;
const math = std.math;
const Allocator = mem.Allocator;
const assert = std.debug.assert;

/// Double-ended queue ported from Rust's standard library, which is provided under MIT License.
/// It can be found at https://github.com/rust-lang/rust/blob/master/LICENSE-MIT
pub fn Deque(comptime T: type) type {
    return struct {
        /// tail and head are pointers into the buffer. Tail always points
        /// to the first element that could be read, Head always points
        /// to where data should be written.
        /// If tail == head the buffer is empty. The length of the ringbuffer
        /// is defined as the distance between the two.
        tail: usize,
        head: usize,
        /// Users should **NOT** use this field directly.
        /// In order to access an item with an index, use `get` method.
        /// If you want to iterate over the items, call `iterator` method to get an iterator.
        buf: []T,
        allocator: Allocator,

        const Self = @This();
        const INITIAL_CAPACITY = 7; // 2^3 - 1
        const MINIMUM_CAPACITY = 1; // 2 - 1

        pub const Error = error{
            Overflow,
        } || Allocator.Error;

        /// Creates an empty deque.
        /// Deinitialize with `deinit`.
        pub fn init(allocator: Allocator) Error!Self {
            return initCapacity(allocator, INITIAL_CAPACITY);
        }

        /// Creates an empty deque with space for at least `capacity` elements.
        /// Deinitialize with `deinit`.
        pub fn initCapacity(allocator: Allocator, capacity: usize) Error!Self {
            const effective_cap = try math.ceilPowerOfTwo(usize, math.max(capacity + 1, MINIMUM_CAPACITY + 1));
            const buf = try allocator.alloc(T, effective_cap);
            return Self{
                .tail = 0,
                .head = 0,
                .buf = buf,
                .allocator = allocator,
            };
        }

        /// Release all allocated memory.
        pub fn deinit(self: Self) void {
            self.allocator.free(self.buf);
        }

        /// Returns the length of the already-allocated buffer.
        pub fn cap(self: Self) usize {
            return self.buf.len;
        }

        /// Returns the number of elements in the deque.
        pub fn len(self: Self) usize {
            return count(self.tail, self.head, self.cap());
        }

        /// Gets the pointer to the element with the given index, if any.
        /// Otherwise it returns `null`.
        pub fn get(self: Self, index: usize) ?*T {
            if (index >= self.len()) return null;

            const idx = self.wrapAdd(self.tail, index);
            return &self.buf[idx];
        }

        /// Adds the given element to the back of the deque.
        pub fn pushBack(self: *Self, item: T) Allocator.Error!void {
            if (self.isFull()) {
                try self.grow();
            }

            const head = self.head;
            self.head = self.wrapAdd(self.head, 1);
            self.buf[head] = item;
        }

        /// Adds the given element to the front of the deque.
        pub fn pushFront(self: *Self, item: T) Allocator.Error!void {
            if (self.isFull()) {
                try self.grow();
            }

            self.tail = self.wrapSub(self.tail, 1);
            const tail = self.tail;
            self.buf[tail] = item;
        }

        /// Pops and returns the last element of the deque.
        pub fn popBack(self: *Self) ?T {
            if (self.len() == 0) return null;

            self.head = self.wrapSub(self.head, 1);
            const head = self.head;
            const item = self.buf[head];
            self.buf[head] = undefined;
            return item;
        }

        /// Pops and returns the first element of the deque.
        pub fn popFront(self: *Self) ?T {
            if (self.len() == 0) return null;

            const tail = self.tail;
            self.tail = self.wrapAdd(self.tail, 1);
            const item = self.buf[tail];
            self.buf[tail] = undefined;
            return item;
        }

        /// Adds all the elements in the given slice to the back of the deque.
        pub fn appendSlice(self: *Self, items: []const T) Allocator.Error!void {
            for (items) |item| {
                try self.pushBack(item);
            }
        }

        /// Adds all the elements in the given slice to the front of the deque.
        pub fn prependSlice(self: *Self, items: []const T) Allocator.Error!void {
            if (items.len == 0) return;

            var i: usize = items.len - 1;

            while (true) : (i -= 1) {
                const item = items[i];
                try self.pushFront(item);
                if (i == 0) break;
            }
        }

        /// Returns an iterator over the deque.
        /// Modifying the deque may invalidate this iterator.
        pub fn iterator(self: Self) Iterator {
            return .{
                .head = self.head,
                .tail = self.tail,
                .ring = self.buf,
            };
        }

        pub const Iterator = struct {
            head: usize,
            tail: usize,
            ring: []T,

            pub fn next(it: *Iterator) ?*T {
                if (it.head == it.tail) return null;

                const tail = it.tail;
                it.tail = wrapIndex(it.tail +% 1, it.ring.len);
                return &it.ring[tail];
            }

            pub fn nextBack(it: *Iterator) ?*T {
                if (it.head == it.tail) return null;

                it.head = wrapIndex(it.head -% 1, it.ring.len);
                return &it.ring[it.head];
            }
        };

        /// Returns `true` if the buffer is at full capacity.
        fn isFull(self: Self) bool {
            return self.cap() - self.len() == 1;
        }

        fn grow(self: *Self) Allocator.Error!void {
            assert(self.isFull());
            const old_cap = self.cap();

            // Reserve additional space to accomodate more items
            self.buf = try self.allocator.realloc(self.buf, old_cap * 2);

            // Update `tail` and `head` pointers accordingly
            self.handleCapacityIncrease(old_cap);

            assert(self.cap() >= old_cap * 2);
            assert(!self.isFull());
        }

        /// Updates `tail` and `head` values to handle the fact that we just reallocated the internal buffer.
        fn handleCapacityIncrease(self: *Self, old_capacity: usize) void {
            const new_capacity = self.cap();

            // Move the shortest contiguous section of the ring buffer.
            // There are three cases to consider:
            //
            // (A) No need to update
            //          T             H
            // before: [o o o o o o o . ]
            //
            // after : [o o o o o o o . . . . . . . . . ]
            //          T             H
            //
            //
            // (B) [..H] needs to be moved
            //              H T
            // before: [o o . o o o o o ]
            //          ---
            //           |_______________.
            //                           |
            //                           v
            //                          ---
            // after : [. . . o o o o o o o . . . . . . ]
            //                T             H
            //
            //
            // (C) [T..old_capacity] needs to be moved
            //                    H T
            // before: [o o o o o . o o ]
            //                      ---
            //                       |_______________.
            //                                       |
            //                                       v
            //                                      ---
            // after : [o o o o o . . . . . . . . . o o ]
            //                    H                 T

            if (self.tail <= self.head) {
                // (A), Nop
            } else if (self.head < old_capacity - self.tail) {
                // (B)
                self.copyNonOverlapping(old_capacity, 0, self.head);
                self.head += old_capacity;
                assert(self.head > self.tail);
            } else {
                // (C)
                const new_tail = new_capacity - (old_capacity - self.tail);
                self.copyNonOverlapping(new_tail, self.tail, old_capacity - self.tail);
                self.tail = new_tail;
                assert(self.head < self.tail);
            }
            assert(self.head < self.cap());
            assert(self.tail < self.cap());
        }

        fn copyNonOverlapping(self: *Self, dest: usize, src: usize, length: usize) void {
            assert(dest + length <= self.cap());
            assert(src + length <= self.cap());
            mem.copy(T, self.buf[dest .. dest + length], self.buf[src .. src + length]);
        }

        fn wrapAdd(self: Self, idx: usize, addend: usize) usize {
            return wrapIndex(idx +% addend, self.cap());
        }

        fn wrapSub(self: Self, idx: usize, subtrahend: usize) usize {
            return wrapIndex(idx -% subtrahend, self.cap());
        }
    };
}

fn count(tail: usize, head: usize, size: usize) usize {
    assert(math.isPowerOfTwo(size));
    return (head -% tail) & (size - 1);
}

fn wrapIndex(index: usize, size: usize) usize {
    assert(math.isPowerOfTwo(size));
    return index & (size - 1);
}

test "Deque works" {
    const testing = std.testing;

    var deque = try Deque(usize).init(testing.allocator);
    defer deque.deinit();

    // empty deque
    try testing.expectEqual(@as(usize, 0), deque.len());
    try testing.expect(deque.get(0) == null);
    try testing.expect(deque.popBack() == null);
    try testing.expect(deque.popFront() == null);

    // pushBack
    try deque.pushBack(101);
    try testing.expectEqual(@as(usize, 1), deque.len());
    try testing.expectEqual(@as(usize, 101), deque.get(0).?.*);

    // pushFront
    try deque.pushFront(100);
    try testing.expectEqual(@as(usize, 2), deque.len());
    try testing.expectEqual(@as(usize, 100), deque.get(0).?.*);
    try testing.expectEqual(@as(usize, 101), deque.get(1).?.*);

    // more items
    {
        var i: usize = 99;
        while (true) : (i -= 1) {
            try deque.pushFront(i);
            if (i == 0) break;
        }
    }
    {
        var i: usize = 102;
        while (i < 200) : (i += 1) {
            try deque.pushBack(i);
        }
    }

    try testing.expectEqual(@as(usize, 200), deque.len());
    {
        var i: usize = 0;
        while (i < deque.len()) : (i += 1) {
            try testing.expectEqual(i, deque.get(i).?.*);
        }
    }
    {
        var i: usize = 0;
        var it = deque.iterator();
        while (it.next()) |val| : (i += 1) {
            try testing.expectEqual(i, val.*);
        }
        try testing.expectEqual(@as(usize, 200), i);
    }
}

test "appendSlice and prependSlice" {
    const testing = std.testing;

    var deque = try Deque(usize).init(testing.allocator);
    defer deque.deinit();

    try deque.prependSlice(&[_]usize{ 1, 2, 3, 4, 5, 6 });
    try deque.appendSlice(&[_]usize{ 7, 8, 9 });
    try deque.prependSlice(&[_]usize{0});
    try deque.appendSlice(&[_]usize{ 10, 11, 12, 13, 14 });

    {
        var i: usize = 0;
        while (i <= 14) : (i += 1) {
            try testing.expectEqual(i, deque.get(i).?.*);
        }
    }
}

test "nextBack" {
    const testing = std.testing;

    var deque = try Deque(usize).init(testing.allocator);
    defer deque.deinit();

    try deque.appendSlice(&[_]usize{ 5, 4, 3, 2, 1, 0 });

    {
        var i: usize = 0;
        var it = deque.iterator();
        while (it.nextBack()) |val| : (i += 1) {
            try testing.expectEqual(i, val.*);
        }
    }
}

test "code sample in README" {
    var deque = try Deque(usize).init(std.testing.allocator);
    defer deque.deinit();

    try deque.pushBack(1);
    try deque.pushBack(2);
    try deque.pushFront(0);

    std.debug.assert(deque.get(0).?.* == @as(usize, 0));
    std.debug.assert(deque.get(1).?.* == @as(usize, 1));
    std.debug.assert(deque.get(2).?.* == @as(usize, 2));
    std.debug.assert(deque.get(3) == null);

    var it = deque.iterator();
    var sum: usize = 0;
    while (it.next()) |val| {
        sum += val.*;
    }
    std.debug.assert(sum == 3);

    std.debug.assert(deque.popFront().? == @as(usize, 0));
    std.debug.assert(deque.popBack().? == @as(usize, 2));
}
