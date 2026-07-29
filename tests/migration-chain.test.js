import {
    readFileSync
} from "node:fs";

import {
    describe,
    expect,
    test
} from "vitest";

function readMigration(filename) {
    return readFileSync(
        new URL(
            `../migrations/${filename}`,
            import.meta.url
        ),
        "utf8"
    ).toLowerCase();
}

const createTableMigration = readMigration(
    "20260723100100_create_members_table.sql"
);

const enableRlsMigration = readMigration(
    "20260723100200_enable_members_rls.sql"
);

const selectPolicyMigration = readMigration(
    "20260723100300_create_members_select_policy.sql"
);

const updatePolicyMigration = readMigration(
    "20260723100400_create_members_update_policy.sql"
);

const indexMigration = readMigration(
    "20260723100500_add_members_user_id_index.sql"
);

const finalHardeningMigration = readMigration(
    "20260727000100_harden_members_and_add_audit.sql"
);

describe("Member database migration chain", () => {
    test("creates the members table first", () => {
        expect(createTableMigration).toContain(
            "create table if not exists public.members"
        );

        expect(createTableMigration).toContain(
            "references auth.users(id)"
        );

        expect(createTableMigration).toContain(
            "user_id uuid not null"
        );
    });

    test("enables and forces RLS after table creation", () => {
        expect(enableRlsMigration).toMatch(
            /alter table public\.members\s+enable row level security/
        );

        expect(enableRlsMigration).toMatch(
            /alter table public\.members\s+force row level security/
        );

        expect(enableRlsMigration).not.toContain(
            "create index"
        );
    });

    test("creates ownership-based select protection", () => {
        expect(selectPolicyMigration).toContain(
            "for select"
        );

        expect(selectPolicyMigration).toContain(
            "to authenticated"
        );

        expect(selectPolicyMigration).toContain(
            "(select auth.uid()) = user_id"
        );
    });

    test("protects updates and ownership changes", () => {
        expect(updatePolicyMigration).toContain(
            "for update"
        );

        expect(updatePolicyMigration).toContain(
            "using"
        );

        expect(updatePolicyMigration).toContain(
            "with check"
        );

        expect(updatePolicyMigration).toContain(
            "(select auth.uid()) = user_id"
        );
    });

    test("creates the ownership lookup index", () => {
        expect(indexMigration).toMatch(
            /create index if not exists members_user_id_idx\s+on public\.members \(user_id\)/
        );
    });

    test("final hardening leaves authenticated access read-only", () => {
        expect(finalHardeningMigration).toMatch(
            /revoke all privileges\s+on table public\.members\s+from authenticated/
        );

        expect(finalHardeningMigration).toMatch(
            /grant select\s+on table public\.members\s+to authenticated/
        );

        expect(finalHardeningMigration).toContain(
            "drop policy if exists"
        );

        expect(finalHardeningMigration).toContain(
            "\"users can update their own member record\""
        );
    });
});