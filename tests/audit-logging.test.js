import {
    readFileSync
} from "node:fs";
import {
    describe,
    expect,
    test
} from "vitest";

const migration = readFileSync(
    new URL(
        "../migrations/20260727000100_harden_members_and_add_audit.sql",
        import.meta.url
    ),
    "utf8"
).toLowerCase();

describe("Trusted member audit migration", () => {
    test("keeps the audit log private from application roles", () => {
        expect(migration).toContain(
            "create schema if not exists private"
        );
        expect(migration).toMatch(
            /revoke all privileges\s+on schema private\s+from public, anon, authenticated/
        );
        expect(migration).toMatch(
            /revoke all privileges\s+on table private\.member_audit_log\s+from public, anon, authenticated/
        );
    });

    test("uses a hardened database trigger for member changes", () => {
        expect(migration).toMatch(
            /create or replace function private\.log_member_change\(\)[\s\S]*security definer[\s\S]*set search_path = ''/
        );
        expect(migration).toMatch(
            /after insert or update or delete\s+on public\.members/
        );
        expect(migration).toContain("auth.uid()");
        expect(migration).toContain("auth.jwt()");
    });

    test("records correlation and ownership evidence without row PII", () => {
        expect(migration).toContain("transaction_id");
        expect(migration).toContain("request_id");
        expect(migration).toContain("owner_user_id_before");
        expect(migration).toContain("owner_user_id_after");
        expect(migration).toContain("changed_columns");
        expect(migration).not.toMatch(
            /\b(old_record|new_record|row_data)\b/
        );
    });

    test("enforces append-only storage", () => {
        expect(migration).toContain(
            "member_audit_log_append_only"
        );
        expect(migration).toMatch(
            /before insert or update or delete\s+on private\.member_audit_log/
        );
        expect(migration).toMatch(
            /before truncate\s+on private\.member_audit_log/
        );
        expect(migration).toContain(
            "member audit records are append-only"
        );
    });
});
