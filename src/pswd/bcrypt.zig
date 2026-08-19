const std = @import("std");

pub fn hash(password: []const u8, alloc: std.mem.Allocator, io: std.Io, rounds: u6) ![]const u8 {
  var buffer: [256]u8 = undefined;
  const hash = std.crypto.pwhash.bcrypt.strHash(password, .{
    .allocator = alloc,
    .params = .{
      .rounds_log = rounds,
      .silently_truncate_password = false,
    },
    .encoding = crypt,
    },
   &buffer,
   io
 );
 return try alloc.dupe(u8, hash);
}

pub fn verify(password: []const u8, hash: []const u8, alloc: std.mem.Allocator) !bool {
  std.crypto.pwhash.bcrypt.strVerify(hash, password, .{ .allocator = alloc, .silently_truncate_password = false }) catch |err| {
   if (err == error.AuthenticationFailed) {
     return false;
   }
  return err;
};
return true;
}
