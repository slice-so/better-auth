import type { VerifyPolicy } from "@slicekit/erc8128";
import { wildcardMatch } from "../../utils/wildcard";

type RoutePolicy =
	| (Record<string, VerifyPolicy | false> & { default?: VerifyPolicy })
	| undefined;

export type ResolvedRoutePolicy =
	| {
			policy?: VerifyPolicy;
			requireAuth: false;
			skipVerification: false;
	  }
	| {
			policy: VerifyPolicy;
			requireAuth: true;
			skipVerification: false;
	  }
	| {
			policy?: VerifyPolicy;
			requireAuth: false;
			skipVerification: true;
	  };

const pluginPaths = [
	"/erc8128/verify",
	"/erc8128/invalidate",
	"/.well-known/erc8128",
];

export function isPluginEndpoint(request: Request, baseURL?: string) {
	const pathname = new URL(request.url).pathname;
	const basePath = baseURL ? new URL(baseURL).pathname : "";
	const normalizedBasePath =
		basePath && basePath !== "/" ? basePath.replace(/\/$/, "") : "";
	const relativePath =
		normalizedBasePath && pathname.startsWith(normalizedBasePath)
			? pathname.slice(normalizedBasePath.length) || "/"
			: pathname;

	return pluginPaths.some(
		(p) => pathname.endsWith(p) || relativePath.endsWith(p),
	);
}

/**
 * Expands a route key that may contain comma-separated methods into
 * individual `"METHOD /path"` strings.
 *
 * `"POST,GET,PUT /api/orders"` → `["POST /api/orders", "GET /api/orders", "PUT /api/orders"]`
 * `"GET /api/products"` → `["GET /api/products"]`
 */
function expandMethods(key: string): string[] {
	const pathIdx = key.indexOf(" /");
	if (pathIdx === -1) return [key];
	const methodPart = key.slice(0, pathIdx);
	const pathPart = key.slice(pathIdx + 1);
	if (!methodPart.includes(",")) return [key];
	return methodPart
		.split(",")
		.map((m) => `${m.trim().toUpperCase()} ${pathPart}`);
}

export function resolveRoutePolicy(
	routePolicy: RoutePolicy,
	request: Request,
): ResolvedRoutePolicy {
	if (!routePolicy) {
		return { requireAuth: false, skipVerification: false };
	}

	const method = request.method.toUpperCase();
	const pathname = new URL(request.url).pathname;
	const routeKey = `${method} ${pathname}`;
	const entries = Object.entries(routePolicy).filter(
		([key]) => key !== "default",
	);

	const exactMatch = entries.find(
		([key]) =>
			key === routeKey || expandMethods(key).some((k) => k === routeKey),
	);
	const wildcardEntry =
		exactMatch ??
		entries.find(([pattern]) => {
			const expanded = expandMethods(pattern);
			return expanded.some((p) =>
				p.includes("*") ? wildcardMatch(p)(routeKey) : p === routeKey,
			);
		});

	if (wildcardEntry) {
		const [, policy] = wildcardEntry;
		if (policy === false) {
			return { requireAuth: false, skipVerification: true };
		}
		return { policy, requireAuth: true, skipVerification: false };
	}

	if (routePolicy.default) {
		return {
			policy: routePolicy.default,
			requireAuth: true,
			skipVerification: false,
		};
	}

	return { requireAuth: false, skipVerification: false };
}
