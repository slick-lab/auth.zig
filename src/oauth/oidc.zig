const std = @import("std");

pub const OIDCProvider = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    client_id: []const u8,
    client_secret: []const u8,
    redirect_uri: []const u8,
    issuer: []const u8,

    // Discovery document (fetched from .well-known/openid-configuration)
    discovery: ?DiscoveryDocument = null,

    pub const DiscoveryDocument = struct {
        issuer: []const u8,
        authorization_endpoint: []const u8,
        token_endpoint: []const u8,
        userinfo_endpoint: []const u8,
        jwks_uri: []const u8,
    };

    pub const User = struct {
        sub: []const u8,
        email: ?[]const u8,
        email_verified: bool = false,
        name: ?[]const u8,
        given_name: ?[]const u8,
        family_name: ?[]const u8,
        picture: ?[]const u8,
        locale: ?[]const u8,
    };

    pub const TokenResponse = struct {
        access_token: []const u8,
        refresh_token: ?[]const u8,
        expires_in: u64,
        token_type: []const u8,
        scope: ?[]const u8,
        id_token: ?[]const u8,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        client_id: []const u8,
        client_secret: []const u8,
        redirect_uri: []const u8,
        issuer: []const u8,
    ) OIDCProvider {
        return OIDCProvider{
            .allocator = allocator,
            .io = io,
            .client_id = client_id,
            .client_secret = client_secret,
            .redirect_uri = redirect_uri,
            .issuer = issuer,
            .discovery = null,
        };
    }

    pub fn deinit(self: *OIDCProvider) void {
        if (self.discovery) |*d| {
            self.allocator.free(@constCast(d.issuer));
            self.allocator.free(@constCast(d.authorization_endpoint));
            self.allocator.free(@constCast(d.token_endpoint));
            self.allocator.free(@constCast(d.userinfo_endpoint));
            self.allocator.free(@constCast(d.jwks_uri));
        }
        _ = self;
        // The user manages their own strings
    }

    /// Fetches the OpenID Connect discovery document from the issuer.
    pub fn discover(self: *OIDCProvider) !void {
        const well_known_url = try std.fmt.allocPrint(self.allocator,
            "{s}/.well-known/openid-configuration",
            .{self.issuer}
        );
        defer self.allocator.free(well_known_url);

        var client = std.http.Client{
            .allocator = self.allocator,
            .io = self.io,
        };
        defer client.deinit();

        var response_body = std.ArrayList(u8).empty;
        defer response_body.deinit(self.allocator);

        const result = try client.fetch(.{
            .location = .{ .url = well_known_url },
            .method = .GET,
            .headers = .{
                .extra_headers = &.{
                    .{ .name = "Accept", .value = "application/json" },
                },
            },
            .response_writer = &response_body.writer(),
        });

        if (result.status.class() != .success) {
            return error.OIDCDiscoveryFailed;
        }

        // Parse the discovery document
        const parsed = try std.json.parseFromSlice(DiscoveryDocument, self.allocator, response_body.items, .{});
        defer parsed.deinit();

        self.discovery = DiscoveryDocument{
            .issuer = try self.allocator.dupe(u8, parsed.value.issuer),
            .authorization_endpoint = try self.allocator.dupe(u8, parsed.value.authorization_endpoint),
            .token_endpoint = try self.allocator.dupe(u8, parsed.value.token_endpoint),
            .userinfo_endpoint = try self.allocator.dupe(u8, parsed.value.userinfo_endpoint),
            .jwks_uri = try self.allocator.dupe(u8, parsed.value.jwks_uri),
        };
    }

    /// Builds the authorization URL using the discovered endpoint.
    pub fn authorizationUrl(self: *OIDCProvider, state: []const u8, scopes: []const u8) ![]const u8 {
        if (self.discovery) |d| {
            return try std.fmt.allocPrint(self.allocator,
                "{s}?client_id={s}&redirect_uri={s}&response_type=code&scope={s}&state={s}",
                .{ d.authorization_endpoint, self.client_id, self.redirect_uri, scopes, state }
            );
        } else {
            return error.OIDCNotDiscovered;
        }
    }

    /// Exchanges the authorization code for an access token.
    pub fn exchangeCode(self: *OIDCProvider, code: []const u8) !TokenResponse {
        if (self.discovery) |d| {
            var client = std.http.Client{
                .allocator = self.allocator,
                .io = self.io,
            };
            defer client.deinit();

            var response_body = std.ArrayList(u8).empty;
            defer response_body.deinit(self.allocator);

            const body = try std.fmt.allocPrint(self.allocator,
                "client_id={s}&client_secret={s}&code={s}&redirect_uri={s}&grant_type=authorization_code",
                .{ self.client_id, self.client_secret, code, self.redirect_uri }
            );
            defer self.allocator.free(body);

            const result = try client.fetch(.{
                .location = .{ .url = d.token_endpoint },
                .method = .POST,
                .headers = .{
                    .extra_headers = &.{
                        .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
                        .{ .name = "Accept", .value = "application/json" },
                    },
                },
                .payload = body,
                .response_writer = &response_body.writer(),
            });

            if (result.status.class() != .success) {
                return error.OIDCTokenExchangeFailed;
            }

            // Parse the token response
            const parsed = try std.json.parseFromSlice(TokenResponse, self.allocator, response_body.items, .{});
            defer parsed.deinit();

            return TokenResponse{
                .access_token = try self.allocator.dupe(u8, parsed.value.access_token),
                .refresh_token = if (parsed.value.refresh_token) |rt| try self.allocator.dupe(u8, rt) else null,
                .expires_in = parsed.value.expires_in,
                .token_type = try self.allocator.dupe(u8, parsed.value.token_type),
                .scope = if (parsed.value.scope) |s| try self.allocator.dupe(u8, s) else null,
                .id_token = if (parsed.value.id_token) |id| try self.allocator.dupe(u8, id) else null,
            };
        } else {
            return error.OIDCNotDiscovered;
        }
    }

    pub fn freeTokenResponse(self: *OIDCProvider, token: *TokenResponse) void {
        self.allocator.free(@constCast(token.access_token));
        if (token.refresh_token) |rt| self.allocator.free(@constCast(rt));
        self.allocator.free(@constCast(token.token_type));
        if (token.scope) |s| self.allocator.free(@constCast(s));
        if (token.id_token) |id| self.allocator.free(@constCast(id));
    }

    /// Fetches the authenticated user's info using the discovered endpoint.
    pub fn fetchUser(self: *OIDCProvider, access_token: []const u8) !User {
        if (self.discovery) |d| {
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
                .location = .{ .url = d.userinfo_endpoint },
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
                return error.OIDCUserFetchFailed;
            }

            const parsed = try std.json.parseFromSlice(User, self.allocator, response_body.items, .{});
            defer parsed.deinit();

            return User{
                .sub = try self.allocator.dupe(u8, parsed.value.sub),
                .email = if (parsed.value.email) |e| try self.allocator.dupe(u8, e) else null,
                .email_verified = parsed.value.email_verified,
                .name = if (parsed.value.name) |n| try self.allocator.dupe(u8, n) else null,
                .given_name = if (parsed.value.given_name) |g| try self.allocator.dupe(u8, g) else null,
                .family_name = if (parsed.value.family_name) |f| try self.allocator.dupe(u8, f) else null,
                .picture = if (parsed.value.picture) |p| try self.allocator.dupe(u8, p) else null,
                .locale = if (parsed.value.locale) |l| try self.allocator.dupe(u8, l) else null,
            };
        } else {
            return error.OIDCNotDiscovered;
        }
    }

    pub fn freeUser(self: *OIDCProvider, user: *User) void {
        self.allocator.free(@constCast(user.sub));
        if (user.email) |e| self.allocator.free(@constCast(e));
        if (user.name) |n| self.allocator.free(@constCast(n));
        if (user.given_name) |g| self.allocator.free(@constCast(g));
        if (user.family_name) |f| self.allocator.free(@constCast(f));
        if (user.picture) |p| self.allocator.free(@constCast(p));
        if (user.locale) |l| self.allocator.free(@constCast(l));
    }
};
