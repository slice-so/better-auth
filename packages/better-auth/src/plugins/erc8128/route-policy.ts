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

export function resolveRoutePolicy(
	routePolicy: RoutePolicy,
	request: Request,
): ResolvedRoutePolicy {
	if (!routePolicy) {
		return { requireAuth: false, skipVerification: false };
	}

	const routeKey = `${request.method.toUpperCase()} ${new URL(request.url).pathname}`;
	const entries = Object.entries(routePolicy).filter(
		([key]) => key !== "default",
	);

	const exactMatch = entries.find(([key]) => key === routeKey);
	const wildcardEntry =
		exactMatch ??
		entries.find(([pattern]) => {
			if (!pattern.includes("*")) {
				return false;
			}
			return wildcardMatch(pattern)(routeKey);
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
