const argon2_impl = @import("argon2.zig");
const bcrypt_impl = @import("bcrypt.zig");

pub const argon2 = argon2_impl;
pub const bcrypt = argon2_impl;
