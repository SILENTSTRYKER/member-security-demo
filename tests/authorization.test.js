import "dotenv/config";
import {
    afterAll,
    beforeAll,
    describe,
    expect,
    test
} from "vitest";

import { createClient } from "@supabase/supabase-js";

// =========================================
// Environment Variables
// =========================================

const {
    SUPABASE_URL,
    SUPABASE_KEY,
    DEMO_EMAIL,
    DEMO_PASSWORD
} = process.env;

const requiredVariables = {
    SUPABASE_URL,
    SUPABASE_KEY,
    DEMO_EMAIL,
    DEMO_PASSWORD
};

const missingVariables = Object.entries(requiredVariables)
    .filter(([, value]) => !value)
    .map(([name]) => name);

if (missingVariables.length > 0) {
    throw new Error(
        `Missing environment variables: ${missingVariables.join(", ")}`
    );
}

// =========================================
// Supabase Client
// =========================================

const client = createClient(
    SUPABASE_URL,
    SUPABASE_KEY,
    {
        auth: {
            persistSession: false,
            autoRefreshToken: false
        }
    }
);

let authenticatedUser;

// =========================================
// Security Tests
// =========================================

describe("Member authorization security", () => {

    beforeAll(async () => {
        const {
            data,
            error
        } = await client.auth.signInWithPassword({
            email: DEMO_EMAIL,
            password: DEMO_PASSWORD
        });

        if (error) {
            throw new Error(
                `Test login failed: ${error.message}`
            );
        }

        authenticatedUser = data.user;

        if (!authenticatedUser) {
            throw new Error(
                "Authentication completed without returning a user."
            );
        }
    });

    afterAll(async () => {
        await client.auth.signOut();
    });

    test(
        "authenticated user can only read records they own",
        async () => {
            const {
                data,
                error
            } = await client
                .from("members")
                .select(
                    "id, user_id, name, email, membership"
                );

            expect(error).toBeNull();
            expect(Array.isArray(data)).toBe(true);

            // The demo account should have a linked member record.
            expect(data.length).toBeGreaterThan(0);

            // Every returned row must belong to the authenticated user.
            const unauthorizedRecords = data.filter(
                record =>
                    record.user_id !== authenticatedUser.id
            );

            expect(unauthorizedRecords).toHaveLength(0);

            data.forEach(record => {
                expect(record.user_id)
                    .toBe(authenticatedUser.id);
            });
        }
    );

    test(
        "authenticated user cannot read records owned by other users",
        async () => {
            const {
                data,
                error
            } = await client
                .from("members")
                .select("id, user_id, name")
                .neq(
                    "user_id",
                    authenticatedUser.id
                );

            expect(error).toBeNull();
            expect(Array.isArray(data)).toBe(true);

            // RLS should filter out every row owned by another user.
            expect(data).toHaveLength(0);
        }
    );

});