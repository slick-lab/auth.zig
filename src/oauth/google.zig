const std = @import("std");

pub const GoogleOAuth = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    client_id: []const u8,
    client_secret: []const u8,
    redirect_uri: []const u8,

    pub const User = struct {
        id: []const u8,
        email: []const u8,
        name: []const u8,
        given_name: []const u8,
        family_name: []const u8,
        picture: ?[]const u8,
    };

    pub const TokenResponse = struct {
        access_token: []const u8,
        refresh_token: ?[]const u8,
        expires_in: u64,
        token_type: []const u8,
        scope: []const u8,
        id_token: ?[]const u8,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        client_id: []const u8,
        client_secret: []const u8,
        redirect_uri: []const u8,
    ) GoogleOAuth {
        return .{
            .allocator = allocator,
            .io = io,
            .client_id = client_id,
            .client_secret = client_secret,
            .redirect_uri = redirect_uri,
        };
    }

    pub fn deinit(self: *GoogleOAuth) void {
        _ = self;
    }

    /// Generates the authorization URL with PKCE.
    /// Returns the URL, code_verifier, and code_challenge.
    pub fn authorizationUrl(self: *GoogleOAuth, state: []const u8) !struct { url: []u8, code_verifier: []u8, code_challenge: []u8 } {
        // 1. Generate a random code verifier.
        const verifier = try generateCodeVerifier(self.allocator);
        errdefer self.allocator.free(verifier);

        // 2. Calculate the code challenge (SHA256 hash of the verifier).
        const challenge = try generateCodeChallenge(self.allocator, verifier);
        errdefer self.allocator.free(challenge);

        // 3. Build the URL.
        const url = try std.fmt.allocPrint(self.allocator,
            "https://accounts.google.com/o/oauth2/v2/auth?" ++
            "client_id={s}&" ++
            "redirect_uri={s}&" ++
            "response_type=code&" ++
            "scope=openid%20profile%20email&" ++
            "state={s}&" ++
            "code_challenge={s}&" ++
            "code_challenge_method=S256",
            .{ self.client_id, self.redirect_uri, state, challenge }
        );

        return .{
            .url = url,
            .code_verifier = verifier,
            .code_challenge = challenge,
        };
    }

    /// Exchanges the authorization code for an access token.
    pub fn exchangeCode(self: *GoogleOAuth, code: []const u8, code_verifier: []const u8) !TokenResponse {
        var client = std.http.Client{
            .allocator = self.allocator,
            .io = self.io,
        };
        defer client.deinit();

        var response_body = std.ArrayList(u8).empty;
        defer response_body.deinit(self.allocator);

        const body = try std.fmt.allocPrint(self.allocator,
            "client_id={s}&" ++
            "client_secret={s}&" ++
            "code={s}&" ++
            "redirect_uri={s}&" ++
            "grant_type=authorization_code&" ++
            "code_verifier={s}",
            .{ self.client_id, self.client_secret, code, self.redirect_uri, code_verifier }
        );
        defer self.allocator.free(body);

        const result = try client.fetch(.{
            .location = .{ .url = "https://oauth2.googleapis.com/token" },
            .method = .POST,
            .headers = .{
                .extra_headers = &.{
                    .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
                },
            },
            .payload = body,
            .response_writer = &response_body.writer(),
        });

        if (result.status.class() != .success) {
            return error.GoogleOAuthFailed;
        }

        // Parse the JSON response.
        const parsed = try std.json.parseFromSlice(TokenResponse, self.allocator, response_body.items, .{});
        defer parsed.deinit();

        return TokenResponse{
            .access_token = try self.allocator.dupe(u8, parsed.value.access_token),
            .refresh_token = if (parsed.value.refresh_token) |rt| try self.allocator.dupe(u8, rt) else null,
            .expires_in = parsed.value.expires_in,
            .token_type = try self.allocator.dupe(u8, parsed.value.token_type),
            .scope = try self.allocator.dupe(u8, parsed.value.scope),
            .id_token = if (parsed.value.id_token) |id| try self.allocator.dupe(u8, id) else null,
        };
    }

    pub fn freeTokenResponse(self: *GoogleOAuth, token: *TokenResponse) void {
        self.allocator.free(@constCast(token.access_token));
        if (token.refresh_token) |rt| self.allocator.free(@constCast(rt));
        self.allocator.free(@constCast(token.token_type));
        self.allocator.free(@constCast(token.scope));
        if (token.id_token) |id| self.allocator.free(@constCast(id));
    }

    /// Fetches the authenticated user's info from Google.
    pub fn fetchUser(self: *GoogleOAuth, access_token: []const u8) !User {
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
            .location = .{ .url = "https://www.googleapis.com/oauth2/v3/userinfo" },
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
            return error.GoogleUserFetchFailed;
        }

        const parsed = try std.json.parseFromSlice(User, self.allocator, response_body.items, .{});
        defer parsed.deinit();

        return User{
            .id = try self.allocator.dupe(u8, parsed.value.id),
            .email = try self.allocator.dupe(u8, parsed.value.email),
            .name = try self.allocator.dupe(u8, parsed.value.name),
            .given_name = try self.allocator.dupe(u8, parsed.value.given_name),
            .family_name = try self.allocator.dupe(u8, parsed.value.family_name),
            .picture = if (parsed.value.picture) |p| try self.allocator.dupe(u8, p) else null,
        };
    }

    pub fn freeUser(self: *GoogleOAuth, user: *User) void {
        self.allocator.free(@constCast(user.id));
        self.allocator.free(@constCast(user.email));
        self.allocator.free(@constCast(user.name));
        self.allocator.free(@constCast(user.given_name));
        self.allocator.free(@constCast(user.family_name));
        if (user.picture) |p| self.allocator.free(@constCast(p));
    }
};

// Helper functions for PKCE.
fn generateCodeVerifier(allocator: std.mem.Allocator) ![]u8 {
    const verifier_len = 64;
    var verifier = try allocator.alloc(u8, verifier_len);
    // Fill with random bytes (we need a cryptographically secure RNG).
    std.crypto.random.bytes(verifier);
    // Ensure it's URL-safe.
    for (verifier) |*c| {
        if (*c == '+' or *c == '/') *c = '-';
    }
    return verifier;
}

fn generateCodeChallenge(allocator: std.mem.Allocator, verifier: []const u8) ![]u8 {
    // SHA256 hash the verifier.
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &hash, .{});

    // Encode the hash as URL-safe base64.
    const Encoder = std.base64.url_safe_no_pad.Base64Encoder;
    var encoder = Encoder.init();
    const len = encoder.calcSize(hash.len);
    const challenge = try allocator.alloc(u8, len);
    _ = encoder.encode(challenge, &hash);
    return challenge;
}
