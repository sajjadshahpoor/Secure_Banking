BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "accounts" (
	"id"	TEXT,
	"user_id"	TEXT NOT NULL,
	"iban"	TEXT NOT NULL UNIQUE,
	"account_number"	TEXT NOT NULL UNIQUE,
	"account_type"	TEXT NOT NULL,
	"currency"	TEXT NOT NULL DEFAULT 'EUR',
	"balance"	NUMERIC NOT NULL DEFAULT 0,
	"daily_transfer_limit"	NUMERIC NOT NULL DEFAULT 0,
	"status"	TEXT NOT NULL DEFAULT 'Active' CHECK("status" IN ('Active', 'Frozen', 'Closed')),
	"created_at"	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	"updated_at"	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY("id"),
	FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS "audit_logs" (
	"id"	TEXT,
	"user_id"	TEXT,
	"action"	TEXT NOT NULL,
	"resource"	TEXT NOT NULL,
	"description"	TEXT,
	"ip_address"	TEXT,
	"user_agent"	TEXT,
	"created_at"	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY("id"),
	FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS "beneficiaries" (
	"id"	TEXT,
	"user_id"	TEXT NOT NULL,
	"beneficiary_name"	TEXT NOT NULL,
	"iban"	TEXT NOT NULL,
	"nickname"	TEXT,
	"created_at"	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY("id"),
	FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS "credit_cards" (
	"id"	TEXT,
	"account_id"	TEXT NOT NULL,
	"encrypted_card_number"	TEXT NOT NULL,
	"last_four_digits"	CHAR(4) NOT NULL,
	"expiry_month"	INTEGER NOT NULL,
	"expiry_year"	INTEGER NOT NULL,
	"card_type"	TEXT NOT NULL,
	"credit_limit"	NUMERIC NOT NULL DEFAULT 0,
	"available_credit"	NUMERIC NOT NULL DEFAULT 0,
	"status"	TEXT NOT NULL DEFAULT 'Active' CHECK("status" IN ('Active', 'Blocked')),
	"issued_at"	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY("id"),
	FOREIGN KEY("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS "email_verification_tokens" (
	"id"	TEXT,
	"user_id"	TEXT NOT NULL,
	"otp"	TEXT NOT NULL,
	"expires_at"	TEXT NOT NULL,
	"attempts"	INTEGER NOT NULL DEFAULT 0,
	"used"	INTEGER NOT NULL DEFAULT 0,
	"created_at"	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY("id"),
	FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS "login_history" (
	"id"	TEXT,
	"user_id"	TEXT,
	"login_time"	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	"logout_time"	TEXT,
	"ip_address"	TEXT,
	"user_agent"	TEXT,
	"success"	INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY("id"),
	FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS "notifications" (
	"id"	TEXT,
	"user_id"	TEXT NOT NULL,
	"title"	TEXT NOT NULL,
	"message"	TEXT NOT NULL,
	"notification_type"	TEXT NOT NULL CHECK("notification_type" IN ('Security', 'Transaction')),
	"is_read"	INTEGER NOT NULL DEFAULT 0,
	"created_at"	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY("id"),
	FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS "roles" (
	"id"	INTEGER,
	"role_name"	TEXT NOT NULL UNIQUE,
	PRIMARY KEY("id" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "security_events" (
	"id"	TEXT,
	"user_id"	TEXT,
	"event_type"	TEXT NOT NULL,
	"severity"	TEXT NOT NULL CHECK("severity" IN ('Low', 'Medium', 'High', 'Critical')),
	"source_ip"	TEXT,
	"target_resource"	TEXT,
	"description"	TEXT NOT NULL,
	"detected_by"	TEXT NOT NULL,
	"status"	TEXT NOT NULL CHECK("status" IN ('Open', 'Investigating', 'Closed')),
	"created_at"	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY("id"),
	FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS "transactions" (
	"id"	TEXT,
	"sender_account_id"	TEXT,
	"receiver_account_id"	TEXT,
	"amount"	NUMERIC NOT NULL,
	"currency"	TEXT NOT NULL,
	"transaction_type"	TEXT NOT NULL CHECK("transaction_type" IN ('Transfer', 'Deposit', 'Withdrawal')),
	"status"	TEXT NOT NULL CHECK("status" IN ('Pending', 'Completed', 'Failed')),
	"description"	TEXT,
	"reference"	TEXT UNIQUE,
	"fee"	NUMERIC NOT NULL DEFAULT 0,
	"ip_address"	TEXT,
	"created_at"	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY("id"),
	FOREIGN KEY("receiver_account_id") REFERENCES "accounts"("id") ON DELETE SET NULL,
	FOREIGN KEY("sender_account_id") REFERENCES "accounts"("id") ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS "user_roles" (
	"user_id"	TEXT NOT NULL,
	"role_id"	INTEGER NOT NULL,
	PRIMARY KEY("user_id","role_id"),
	FOREIGN KEY("role_id") REFERENCES "roles"("id") ON DELETE CASCADE,
	FOREIGN KEY("user_id") REFERENCES "users"("id") ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS "users" (
	"id"	TEXT,
	"username"	TEXT NOT NULL UNIQUE,
	"email"	TEXT NOT NULL UNIQUE,
	"password_hash"	TEXT NOT NULL,
	"first_name"	TEXT NOT NULL,
	"last_name"	TEXT NOT NULL,
	"phone"	TEXT,
	"address"	TEXT,
	"date_of_birth"	TEXT,
	"is_active"	INTEGER NOT NULL DEFAULT 1,
	"email_verified"	INTEGER NOT NULL DEFAULT 0,
	"mfa_enabled"	INTEGER NOT NULL DEFAULT 0,
	"failed_login_attempts"	INTEGER NOT NULL DEFAULT 0,
	"account_locked_until"	TEXT,
	"last_login"	TEXT,
	"created_at"	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	"updated_at"	TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY("id")
);
CREATE INDEX IF NOT EXISTS "idx_accounts_user_id" ON "accounts" (
	"user_id"
);
CREATE INDEX IF NOT EXISTS "idx_audit_logs_user_id" ON "audit_logs" (
	"user_id"
);
CREATE INDEX IF NOT EXISTS "idx_beneficiaries_user_id" ON "beneficiaries" (
	"user_id"
);
CREATE INDEX IF NOT EXISTS "idx_login_history_user_id" ON "login_history" (
	"user_id"
);
CREATE INDEX IF NOT EXISTS "idx_notifications_user_id" ON "notifications" (
	"user_id"
);
CREATE INDEX IF NOT EXISTS "idx_security_events_user_id" ON "security_events" (
	"user_id"
);
CREATE INDEX IF NOT EXISTS "idx_transactions_receiver_account_id" ON "transactions" (
	"receiver_account_id"
);
CREATE INDEX IF NOT EXISTS "idx_transactions_sender_account_id" ON "transactions" (
	"sender_account_id"
);
COMMIT;
