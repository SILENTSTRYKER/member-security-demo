// =========================================
// Nexark Multi-Factor Authentication
// mfa.js
// =========================================

const client = window.supabase.createClient(
    SUPABASE_URL,
    SUPABASE_KEY
);

const mfaHeading =
    document.getElementById("mfaHeading");

const mfaDescription =
    document.getElementById("mfaDescription");

const mfaLoading =
    document.getElementById("mfaLoading");

const enrollmentPanel =
    document.getElementById("enrollmentPanel");

const challengePanel =
    document.getElementById("challengePanel");

const mfaForm =
    document.getElementById("mfaForm");

const mfaCodeInput =
    document.getElementById("mfaCode");

const mfaMessage =
    document.getElementById("mfaMessage");

const mfaButton =
    document.getElementById("mfaButton");

const mfaSignOutButton =
    document.getElementById("mfaSignOutButton");

const mfaQrCode =
    document.getElementById("mfaQrCode");

const mfaSecret =
    document.getElementById("mfaSecret");

let activeFactorId = null;

function showMfaMessage(message, type = "") {
    mfaMessage.textContent = message;
    mfaMessage.className =
        `loginMessage ${type}`;
}

function setMfaButtonLoading(isLoading) {
    mfaButton.disabled = isLoading;
    mfaButton.replaceChildren();

    if (isLoading) {
        const spinner =
            document.createElement("span");

        spinner.className = "spinner";
        spinner.setAttribute(
            "aria-hidden",
            "true"
        );

        mfaButton.append(
            spinner,
            document.createTextNode(
                "Verifying Code"
            )
        );

        mfaButton.setAttribute(
            "aria-busy",
            "true"
        );

        return;
    }

    mfaButton.removeAttribute("aria-busy");
    mfaButton.textContent =
        "Verify Authenticator Code";
}

function clearEnrollmentSecret() {
    mfaSecret.textContent = "";
    mfaQrCode.removeAttribute("src");
}

function redirectToLogin() {
    clearEnrollmentSecret();
    window.location.replace("login.html");
}

function redirectToDashboard() {
    clearEnrollmentSecret();
    window.location.replace("index.html");
}

async function removeUnverifiedFactors(
    factors
) {
    const unverifiedFactors =
        factors.filter(
            factor =>
                factor.status === "unverified"
        );

    for (const factor of unverifiedFactors) {
        const { error } =
            await client.auth.mfa.unenroll({
                factorId: factor.id
            });

        if (error) {
            throw new Error(
                "Unable to reset incomplete MFA enrollment."
            );
        }
    }
}

async function prepareEnrollment(
    existingFactors
) {
    await removeUnverifiedFactors(
        existingFactors
    );

    const { data, error } =
        await client.auth.mfa.enroll({
            factorType: "totp",
            friendlyName:
                "Nexark Security Portal"
        });

    if (
        error ||
        !data?.id ||
        !data?.totp?.qr_code ||
        !data?.totp?.secret
    ) {
        throw new Error(
            "Unable to start MFA enrollment."
        );
    }

    activeFactorId = data.id;

    mfaQrCode.src = data.totp.qr_code;
    mfaSecret.textContent =
        data.totp.secret;

    mfaHeading.textContent =
        "Set up your authenticator";

    mfaDescription.textContent =
        "Enrollment is required before protected member data can be accessed.";

    mfaLoading.hidden = true;
    enrollmentPanel.hidden = false;
    challengePanel.hidden = true;
    mfaForm.hidden = false;

    mfaCodeInput.focus();
}

function prepareChallenge(factor) {
    activeFactorId = factor.id;

    mfaHeading.textContent =
        "Confirm your identity";

    mfaDescription.textContent =
        "Your password was accepted. Complete the second authentication factor.";

    mfaLoading.hidden = true;
    enrollmentPanel.hidden = true;
    challengePanel.hidden = false;
    mfaForm.hidden = false;

    mfaCodeInput.focus();
}

async function initializeMfa() {
    try {
        const {
            data: { user },
            error: userError
        } = await client.auth.getUser();

        if (userError || !user) {
            redirectToLogin();
            return;
        }

        const {
            data: assuranceData,
            error: assuranceError
        } =
            await client.auth.mfa
                .getAuthenticatorAssuranceLevel();

        if (assuranceError) {
            throw new Error(
                "Unable to verify authentication level."
            );
        }

        if (
            assuranceData
                ?.currentAuthenticationMethods
                ?.some(
                    method =>
                        method.method === "totp"
                ) &&
            assuranceData.currentLevel === "aal2"
        ) {
            redirectToDashboard();
            return;
        }

        const {
            data: factorData,
            error: factorError
        } =
            await client.auth.mfa.listFactors();

        if (factorError) {
            throw new Error(
                "Unable to load MFA factors."
            );
        }

        const totpFactors =
            Array.isArray(factorData?.totp)
                ? factorData.totp
                : [];

        const verifiedFactor =
            totpFactors.find(
                factor =>
                    factor.status === "verified"
            );

        if (verifiedFactor) {
            prepareChallenge(
                verifiedFactor
            );

            return;
        }

        await prepareEnrollment(
            totpFactors
        );
    } catch {
        mfaLoading.hidden = true;

        mfaHeading.textContent =
            "Verification unavailable";

        mfaDescription.textContent =
            "Multi-factor authentication could not be prepared.";

        showMfaMessage(
            "Sign out and try again. If the problem continues, contact the system administrator.",
            "errorMessage"
        );
    }
}

mfaForm.addEventListener(
    "submit",
    async event => {
        event.preventDefault();

        const code =
            mfaCodeInput.value
                .replace(/\s/g, "");

        showMfaMessage("");

        if (!/^\d{6}$/.test(code)) {
            showMfaMessage(
                "Enter the six-digit code from your authenticator app.",
                "errorMessage"
            );

            mfaCodeInput.focus();
            return;
        }

        if (!activeFactorId) {
            showMfaMessage(
                "The authentication factor is unavailable. Sign out and try again.",
                "errorMessage"
            );

            return;
        }

        setMfaButtonLoading(true);

        try {
            const { error } =
                await client.auth.mfa
                    .challengeAndVerify({
                        factorId:
                            activeFactorId,
                        code
                    });

            if (error) {
                throw new Error(
                    "Authenticator verification failed."
                );
            }

            const {
                data: assuranceData,
                error: assuranceError
            } =
                await client.auth.mfa
                    .getAuthenticatorAssuranceLevel();

            if (
                assuranceError ||
                assuranceData?.currentLevel
                    !== "aal2"
            ) {
                throw new Error(
                    "AAL2 session was not established."
                );
            }

            showMfaMessage(
                "Identity verified. Redirecting...",
                "successMessage"
            );

            redirectToDashboard();
        } catch {
            mfaCodeInput.value = "";

            showMfaMessage(
                "Verification failed. Enter the newest code from your authenticator app.",
                "errorMessage"
            );

            mfaCodeInput.focus();
            setMfaButtonLoading(false);
        }
    }
);

mfaSignOutButton.addEventListener(
    "click",
    async () => {
        mfaSignOutButton.disabled = true;
        clearEnrollmentSecret();

        await client.auth.signOut({
            scope: "global"
        });

        redirectToLogin();
    }
);

client.auth.onAuthStateChange(event => {
    if (event === "SIGNED_OUT") {
        redirectToLogin();
    }
});

window.addEventListener(
    "pagehide",
    clearEnrollmentSecret
);

initializeMfa();