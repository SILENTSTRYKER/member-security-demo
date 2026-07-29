// =========================================
// Nexark Security Portal
// app.js
// =========================================

const client = window.supabase.createClient(
    SUPABASE_URL,
    SUPABASE_KEY
);

const loginForm =
    document.getElementById("loginForm");

const loginButton =
    document.getElementById("loginButton");

const loginMessage =
    document.getElementById("loginMessage");

const emailInput =
    document.getElementById("email");

const passwordInput =
    document.getElementById("password");

function showLoginMessage(
    message,
    type = ""
) {
    loginMessage.textContent = message;
    loginMessage.className =
        `loginMessage ${type}`;
}

function setLoginButtonLoading(
    isLoading
) {
    loginButton.disabled = isLoading;
    loginButton.replaceChildren();

    if (isLoading) {
        const spinner =
            document.createElement("span");

        spinner.className = "spinner";

        spinner.setAttribute(
            "aria-hidden",
            "true"
        );

        loginButton.append(
            spinner,
            document.createTextNode(
                "Authenticating"
            )
        );

        loginButton.setAttribute(
            "aria-busy",
            "true"
        );

        return;
    }

    loginButton.removeAttribute(
        "aria-busy"
    );

    loginButton.textContent = "Sign In";
}

function getCaptchaToken() {
    if (
        !window.turnstile ||
        typeof window.turnstile.getResponse
            !== "function"
    ) {
        return "";
    }

    return window.turnstile.getResponse();
}

function resetCaptcha() {
    if (
        window.turnstile &&
        typeof window.turnstile.reset
            === "function"
    ) {
        window.turnstile.reset();
    }
}

async function routeAuthenticatedUser() {
    const {
        data,
        error
    } =
        await client.auth.mfa
            .getAuthenticatorAssuranceLevel();

    if (error || !data) {
        throw new Error(
            "Unable to determine authentication level."
        );
    }

    if (data.currentLevel === "aal2") {
        window.location.replace(
            "index.html"
        );

        return;
    }

    window.location.replace("mfa.html");
}

async function checkExistingUser() {
    try {
        const {
            data: { user },
            error
        } = await client.auth.getUser();

        if (error || !user) {
            return;
        }

        await routeAuthenticatedUser();
    } catch {
        // Keep the login page available if session
        // validation temporarily fails.
    }
}

checkExistingUser();

loginForm.addEventListener(
    "submit",
    async event => {
        event.preventDefault();

        const email =
            emailInput.value.trim();

        const password =
            passwordInput.value;

        const captchaToken =
            getCaptchaToken();

        showLoginMessage("");

        if (!captchaToken) {
            showLoginMessage(
                "Complete the security verification before signing in.",
                "errorMessage"
            );

            return;
        }

        setLoginButtonLoading(true);

        let redirecting = false;

        try {
            const { error } =
                await client.auth
                    .signInWithPassword({
                        email,
                        password,
                        options: {
                            captchaToken
                        }
                    });

            if (error) {
                showLoginMessage(
                    "Sign-in failed. Check your credentials and complete the security verification again.",
                    "errorMessage"
                );

                resetCaptcha();
                return;
            }

            passwordInput.value = "";

            showLoginMessage(
                "Password accepted. Continuing to identity verification...",
                "successMessage"
            );

            await routeAuthenticatedUser();

            redirecting = true;
        } catch {
            showLoginMessage(
                "Sign-in is temporarily unavailable. Please try again.",
                "errorMessage"
            );

            resetCaptcha();
        } finally {
            if (!redirecting) {
                setLoginButtonLoading(
                    false
                );
            }
        }
    }
);