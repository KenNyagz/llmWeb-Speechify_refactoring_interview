import { createHash, randomBytes, scrypt as scryptCallback } from "crypto";
import { promisify } from "util";

const scrypt = promisify(scryptCallback) as (
	password: string | Buffer,
	salt: string | Buffer,
	keylen: number,
	options?: { N: number; r: number; p: number },
) => Promise<Buffer>;

const LEGACY_HASH_PREFIX = "sha256";
const SECURE_HASH_PREFIX = "scrypt";
const SCRYPT_KEY_LENGTH = 64;
const SCRYPT_SALT_BYTES = 16;
const SCRYPT_OPTIONS = { N: 2 ** 14, r: 8, p: 1 };

/**
 * Generate a simple ID
 */
export function generateId(): string {
	return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
}

function createLegacyHash(password: string) {
	const hash = createHash("sha256");
	hash.update(password + "salt");
	return hash.digest("hex");
}

async function createSecureHash(password: string) {
	const salt = randomBytes(SCRYPT_SALT_BYTES).toString("hex");
	const derived = await scrypt(password, salt, SCRYPT_KEY_LENGTH, SCRYPT_OPTIONS);
	return `${SECURE_HASH_PREFIX}$${salt}$${derived.toString("hex")}`;
}

export function isLegacyPasswordHash(hashedPassword: string): boolean {
	return !hashedPassword.startsWith(`${SECURE_HASH_PREFIX}$`);
}

export async function hashPassword(password: string): Promise<string> {
	return createSecureHash(password);
}

export async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
	if (!hashedPassword.includes("$")) {
		return createLegacyHash(password) === hashedPassword;
	}

	const [prefix, salt, derivedHash] = hashedPassword.split("$");

	if (prefix === SECURE_HASH_PREFIX && salt && derivedHash) {
		const derived = await scrypt(password, salt, SCRYPT_KEY_LENGTH, SCRYPT_OPTIONS);
		return derived.toString("hex") === derivedHash;
	}

	if (prefix === LEGACY_HASH_PREFIX && salt) {
		return createLegacyHash(password) === salt;
	}

	return false;
}

/**
 * Convert Date to protobuf Timestamp
 */
export function toProtoTimestamp(date: Date): { seconds: bigint; nanos: number } {
	const ms = date.getTime();
	return {
		seconds: BigInt(Math.floor(ms / 1000)),
		nanos: (ms % 1000) * 1000000,
	};
}

/**
 * Convert protobuf Timestamp to Date
 */
export function fromProtoTimestamp(timestamp: { seconds: bigint; nanos: number }): Date {
	return new Date(Number(timestamp.seconds) * 1000 + timestamp.nanos / 1000000);
}
