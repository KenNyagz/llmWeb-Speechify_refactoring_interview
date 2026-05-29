import { afterEach, describe, expect, it } from "vitest";
import { createSessionToken, validateSessionToken } from "./auth";

describe("auth middleware", () => {
	const originalJwtSecret = process.env.GRPC_JWT_SECRET;
	const originalNodeEnv = process.env.NODE_ENV;

	afterEach(() => {
		process.env.GRPC_JWT_SECRET = originalJwtSecret;
		process.env.NODE_ENV = originalNodeEnv;
	});

	it("requires GRPC_JWT_SECRET outside test environment", () => {
		process.env.NODE_ENV = "production";
		process.env.GRPC_JWT_SECRET = "";

		expect(() =>
			createSessionToken({
				userId: "user-1",
				username: "user",
				role: "user",
			}),
		).toThrow("GRPC_JWT_SECRET environment variable is required");
	});

	it("allows test fallback secret when NODE_ENV is test", () => {
		process.env.NODE_ENV = "test";
		process.env.GRPC_JWT_SECRET = "";

		const token = createSessionToken({
			userId: "user-1",
			username: "user",
			role: "user",
		});

		expect(token).toBeDefined();
		expect(validateSessionToken(token).userId).toBe("user-1");
	});
});
