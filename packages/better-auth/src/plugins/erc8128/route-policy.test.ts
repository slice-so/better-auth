import { describe, expect, it } from "vitest";
import { resolveRoutePolicy } from "./route-policy";

function fakeRequest(method: string, path: string): Request {
	return new Request(`https://example.com${path}`, { method });
}

describe("resolveRoutePolicy — multi-method keys", () => {
	const policy = { replayable: false } as const;

	it("matches comma-separated methods to a single path", () => {
		const routePolicy = { "POST,GET,PUT /api/orders": policy };

		const post = resolveRoutePolicy(
			routePolicy,
			fakeRequest("POST", "/api/orders"),
		);
		expect(post.requireAuth).toBe(true);

		const get = resolveRoutePolicy(
			routePolicy,
			fakeRequest("GET", "/api/orders"),
		);
		expect(get.requireAuth).toBe(true);

		const put = resolveRoutePolicy(
			routePolicy,
			fakeRequest("PUT", "/api/orders"),
		);
		expect(put.requireAuth).toBe(true);
	});

	it("does not match unlisted methods", () => {
		const routePolicy = { "POST,GET /api/orders": policy };

		const del = resolveRoutePolicy(
			routePolicy,
			fakeRequest("DELETE", "/api/orders"),
		);
		expect(del.requireAuth).toBe(false);
	});

	it("works with wildcards in the path", () => {
		const routePolicy = { "GET,POST /api/items/*": policy };

		const get = resolveRoutePolicy(
			routePolicy,
			fakeRequest("GET", "/api/items/123"),
		);
		expect(get.requireAuth).toBe(true);

		const post = resolveRoutePolicy(
			routePolicy,
			fakeRequest("POST", "/api/items/456"),
		);
		expect(post.requireAuth).toBe(true);

		const put = resolveRoutePolicy(
			routePolicy,
			fakeRequest("PUT", "/api/items/789"),
		);
		expect(put.requireAuth).toBe(false);
	});

	it("supports false to skip verification for multiple methods", () => {
		const routePolicy = { "GET,POST /api/public": false as const };

		const get = resolveRoutePolicy(
			routePolicy,
			fakeRequest("GET", "/api/public"),
		);
		expect(get.skipVerification).toBe(true);

		const post = resolveRoutePolicy(
			routePolicy,
			fakeRequest("POST", "/api/public"),
		);
		expect(post.skipVerification).toBe(true);
	});

	it("handles spaces around commas", () => {
		const routePolicy = { "GET , POST /api/orders": policy };

		const get = resolveRoutePolicy(
			routePolicy,
			fakeRequest("GET", "/api/orders"),
		);
		expect(get.requireAuth).toBe(true);

		const post = resolveRoutePolicy(
			routePolicy,
			fakeRequest("POST", "/api/orders"),
		);
		expect(post.requireAuth).toBe(true);
	});

	it("case-insensitive method matching via uppercase normalization", () => {
		const routePolicy = { "get,post /api/orders": policy };

		const get = resolveRoutePolicy(
			routePolicy,
			fakeRequest("GET", "/api/orders"),
		);
		expect(get.requireAuth).toBe(true);
	});
});
