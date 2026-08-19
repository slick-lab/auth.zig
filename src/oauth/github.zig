const std = @import("std");

pub const GitHubOAuth = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    client_id: []const u8,
    client_secret: []const u8,
    redirect_uri: []const u8,

    pub const User = struct {
        id: u64,
        login: []const u8,
        name: ?[]const u8,
        email: ?[]const u8,
        avatar_url: ?[]const u8,
    };

    pub const TokenResponse = struct {
        access_token: []const u8,
        token_type: []const u8,
        scope: []const u8,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        client_id: []const u8,
        client_secret: []const u8,
        redirect_uri: []const u8,
    ) GitHubOAuth {
        return GitHubOAuth{
            .allocator = allocator,
            .io = io,
            .client_id = client_id,
            .client_secret = client_secret,
            .redirect_uri = redirect_uri,
        };
    }

    pub fn deinit(self: *GitHubOAuth) void {
        _ = self;
        // User manages their own strings
    }

    pub fn authorizationUrl(self: *GitHubOAuth, state: []const u8) ![]const u8 {
        return try std.fmt.allocPrint(self.allocator,
            "https://github.com/login/oauth/authorize?client_id={s}&redirect_uri={s}&state={s}",
            .{ self.client_id, self.redirect_uri, state }
        );
    }

    pub fn exchangeCode(self: *GitHubOAuth, code: []const u8) !TokenResponse {
        var client = std.http.Client{
            .allocator = self.allocator,
            .io = self.io,
        };
        defer client.deinit();

        var response_body = std.ArrayList(u8).empty;
        defer response_body.deinit(self.allocator);

        const body = try std.fmt.allocPrint(self.allocator,
            "client_id={s}&client_secret={s}&code={s}",
            .{ self.client_id, self.client_secret, code }
        );
        defer self.allocator.free(body);

        const result = try client.fetch(.{
            .location = .{ .url = "https://github.com/login/oauth/access_token" },
            .method = .POST,
            .headers = .{
                .extra_headers = &.{
                    .{ .name = "Accept", .value = "application/json" },
                    .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
                },
            },
            .payload = body,
            .response_writer = &response_body.writer(),
        });

        if (result.status.class() != .success) {
            return error.GitHubOAuthFailed;
        }

        const parsed = try std.json.parseFromSlice(TokenResponse, self.allocator, response_body.items, .{});
        defer parsed.deinit();

        return TokenResponse{
            .access_token = try self.allocator.dupe(u8, parsed.value.access_token),
            .token_type = try self.allocator.dupe(u8, parsed.value.token_type),
            .scope = try self.allocator.dupe(u8, parsed.value.scope),
        };
    }

    pub fn freeTokenResponse(self: *GitHubOAuth, token: *TokenResponse) void {
        self.allocator.free(@constCast(token.access_token));
        self.allocator.free(@constCast(token.token_type));
        self.allocator.free(@constCast(token.scope));
    }

    pub fn fetchUser(self: *GitHubOAuth, access_token: []const u8) !User {
        var client = std.http.Client{
            .allocator = self.allocator,
            .io = self.io,
        };
        defer client.deinit();

        var response_body = std.ArrayList(u8).empty;
        defer response_body.deinit(self.allocator);

        const auth_header = try std.fmt.allocPrint(self.allocator, "Bearer {s}", .{access_token});
        defer self.allocator.free(auth_header);

        const result = try client.fetch(.{
            .location = .{ .url = "https://api.github.com/user" },
            .method = .GET,
            .headers = .{
                .extra_headers = &.{
                    .{ .name = "Authorization", .value = auth_header },
                    .{ .name = "Accept", .value = "application/json" },
                },
            },
            .response_writer = &response_body.writer(),
        });

        if (result.status.class() != .success) {
            return error.GitHubUserFetchFailed;
        }

        const parsed = try std.json.parseFromSlice(User, self.allocator, response_body.items, .{});
        defer parsed.deinit();

        return User{
            .id = parsed.value.id,
            .login = try self.allocator.dupe(u8, parsed.value.login),
            .name = if (parsed.value.name) |n| try self.allocator.dupe(u8, n) else null,
            .email = if (parsed.value.email) |e| try self.allocator.dupe(u8, e) else null,
            .avatar_url = if (parsed.value.avatar_url) |a| try self.allocator.dupe(u8, a) else null,
        };
    }

    pub fn freeUser(self: *GitHubOAuth, user: *User) void {
        self.allocator.free(@constCast(user.login));
        if (user.name) |n| self.allocator.free(@constCast(n));
        if (user.email) |e| self.allocator.free(@constCast(e));
        if (user.avatar_url) |a| self.allocator.free(@constCast(a));
    }
};
