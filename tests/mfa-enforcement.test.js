import fs from "node:fs";
import path from "node:path";
import {
    describe,
    expect,
    test
} from "vitest";

const projectRoot = process.cwd();

function readProjectFile(fileName) {
    return fs.readFileSync(
        path.join(projectRoot, fileName),
        "utf8"
    );
}

describe("Mandatory MFA enforcement", () => {
    const appSource = readProjectFile("app.js");

    const dashboardSource =
        readProjectFile("dashboard.js");

    const mfaSource = readProjectFile("mfa.js");

    const mfaHtml = readProjectFile("mfa.html");

    test(
        "routes password-authenticated users through MFA",
        () => {
            expect(appSource).toContain(
                "getAuthenticatorAssuranceLevel"
            );

            expect(appSource).toContain(
                '"aal2"'
            );

            expect(appSource).toContain(
                '"mfa.html"'
            );
        }
    );

    test(
        "blocks dashboard access without AAL2",
        () => {
            expect(dashboardSource).toContain(
                "getAuthenticatorAssuranceLevel"
            );

            expect(dashboardSource).toMatch(
                /currentLevel\s*!==\s*"aal2"/
            );

            expect(dashboardSource).toContain(
                'window.location.replace("mfa.html")'
            );

            expect(dashboardSource).toContain(
                "MFA-Protected Session"
            );

            expect(dashboardSource).toContain(
                "AAL2 Active"
            );
        }
    );

    test(
        "supports secure TOTP enrollment",
        () => {
            expect(mfaSource).toContain(
                "mfa.enroll"
            );

            expect(mfaSource).toContain(
                'factorType: "totp"'
            );

            expect(mfaSource).toContain(
                "totp.qr_code"
            );

            expect(mfaSource).toContain(
                "totp.secret"
            );
        }
    );

    test(
        "challenges and verifies the TOTP factor",
        () => {
            expect(mfaSource).toContain(
                "challengeAndVerify"
            );

            expect(mfaSource).toContain(
                "factorId"
            );

            expect(mfaSource).toContain(
                "code"
            );
        }
    );

    test(
        "confirms AAL2 before dashboard access",
        () => {
            expect(mfaSource).toContain(
                "getAuthenticatorAssuranceLevel"
            );

            expect(mfaSource).toContain(
                '"aal2"'
            );

            expect(mfaSource).toContain(
                '"index.html"'
            );
        }
    );

    test(
        "provides an accessible MFA verification form",
        () => {
            expect(mfaHtml).toContain(
                'id="mfaForm"'
            );

            expect(mfaHtml).toContain(
                'autocomplete="one-time-code"'
            );

            expect(mfaHtml).toContain(
                'inputmode="numeric"'
            );

            expect(mfaHtml).toContain(
                'aria-live="polite"'
            );
        }
    );

    test(
        "does not expose privileged Supabase credentials",
        () => {
            const combinedSource = [
                appSource,
                dashboardSource,
                mfaSource,
                mfaHtml
            ].join("\n");

            expect(combinedSource).not.toMatch(
                /service[_-]?role/i
            );

            expect(combinedSource).not.toMatch(
                /SUPABASE_SERVICE/i
            );
        }
    );
});