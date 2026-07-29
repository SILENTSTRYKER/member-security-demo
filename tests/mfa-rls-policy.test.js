import fs from "node:fs";
import path from "node:path";
import {
    describe,
    expect,
    test
} from "vitest";

const migrationPath = path.join(
    process.cwd(),
    "migrations",
    "20260729000100_require_aal2_for_members.sql"
);

const migration = fs.readFileSync(
    migrationPath,
    "utf8"
);

describe("Members AAL2 RLS policy", () => {
    test(
        "keeps row level security enabled and forced",
        () => {
            expect(migration).toMatch(
                /alter\s+table\s+public\.members[\s\S]*enable\s+row\s+level\s+security/i
            );

            expect(migration).toMatch(
                /alter\s+table\s+public\.members[\s\S]*force\s+row\s+level\s+security/i
            );
        }
    );

    test(
        "restricts records to their authenticated owner",
        () => {
            expect(migration).toMatch(
                /auth\.uid\(\)[\s\S]*=\s*user_id/i
            );
        }
    );

    test(
        "requires the AAL2 JWT assurance level",
        () => {
            expect(migration).toMatch(
                /auth\.jwt\(\)\s*->>\s*'aal'/i
            );

            expect(migration).toMatch(
                /=\s*'aal2'/i
            );
        }
    );

    test(
        "applies the policy only to authenticated users",
        () => {
            expect(migration).toMatch(
                /for\s+select\s+to\s+authenticated/i
            );
        }
    );

    test(
        "preserves read-only member access",
        () => {
            expect(migration).toMatch(
                /revoke\s+insert,\s*update,\s*delete,\s*truncate,\s*references,\s*trigger[\s\S]*from\s+authenticated/i
            );

            expect(migration).toMatch(
                /grant\s+select[\s\S]*to\s+authenticated/i
            );
        }
    );
});