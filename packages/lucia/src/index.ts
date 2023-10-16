export { lucia, DEFAULT_SESSION_COOKIE_NAME } from "./auth/index.js";
export { LuciaError } from "./auth/error.js";
export { createKeyId } from "./auth/database.js";

export type GlobalAuth = Lucia.Auth;
export type GlobalDatabaseUserAttributes = Lucia.DatabaseUserAttributes;
export type GlobalDatabaseSessionAttributes = Lucia.DatabaseSessionAttributes;

export type {
	User,
	Key,
	Session,
	Configuration,
	Env,
	Auth
} from "./auth/index.js";
export type {
	Adapter,
	InitializeAdapter,
	UserAdapter,
	SessionAdapter
} from "./auth/adapter.js";
export type { UserSchema, KeySchema, SessionSchema } from "./auth/database.js";
export type {
	RequestContext,
	Middleware,
	AuthRequest
} from "./auth/request.js";
export type { LuciaErrorConstructor } from "./auth/error.js";
