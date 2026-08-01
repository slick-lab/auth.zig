const std = @import("std");

pub const Options = struct {
  t: u32,
  m: u32,
  p: u24
};

pub fn hash(password: []const u8, allocator: std.mem.Allocator, io: std.Io, options: Options) ![]const u8 {
 var hash_buffer: [256]u8 = undefined;
 const hash = try std.crypto.pwhash.argon2.strHash(password, .{
   .allocator = allocator,
   .params = .{
    .t = options.t,
    .m = options.m,
    .p = options.p
    }},
    &hash_buffer,
    io
    ); 
   return try allocator.dupe(u8, hash);
}

pub fn verify(hash: []const u8, password: []const u8, alloc: std.mem.Allocator, io: std.Io) !Bool {
  std.crypto.pwhash.argon2.strVerify(hash, password, .{ .allocator = alloc }, io) catch |err| {
    if (err == error.AuthenticationFailed) {
      return false;
    }
  return err;
  };
return true;
}
