// =========================================
// Nexark Security Portal
// app.js
// =========================================

const client = window.supabase.createClient(
    SUPABASE_URL,
    SUPABASE_KEY
);

const loginForm = document.getElementById("loginForm");
const loginButton = document.getElementById("loginButton");
const loginMessage = document.getElementById("loginMessage");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");

function showLoginMessage(message, type = "") {
    loginMessage.textContent = message;
    loginMessage.className = `loginMessage ${type}`;
}

function setLoginButtonLoading(isLoading) {
    loginButton.disabled = isLoading;
    loginButton.replaceChildren();

    if (isLoading) {
        const spinner = document.createElement("span");

        spinner.className = "spinner";
        spinner.setAttribute("aria-hidden", "true");

        loginButton.append(
            spinner,
            document.createTextNode("Authenticating")
        );

        loginButton.setAttribute("aria-busy", "true");
        return;
    }

    loginButton.removeAttribute("aria-busy");
    loginButton.textContent = "Sign In";
}

async function checkExistingUser() {
    try {
        const {
            data: { user },
            error
        } = await client.auth.getUser();

        if (!error && user) {
            window.location.replace("index.html");
        }
    } catch {
        // Keep the login page available if validation
        // temporarily fails.
    }
}

checkExistingUser();

loginForm.addEventListener("submit", async event => {
    event.preventDefault();

    const email = emailInput.value.trim();
    const password = passwordInput.value;

    showLoginMessage("");
    setLoginButtonLoading(true);

    let redirecting = false;

    try {
        const { error } =
            await client.auth.signInWithPassword({
                email,
                password
            });

        if (error) {
            showLoginMessage(
                "Sign-in failed. Check your email and password.",
                "errorMessage"
            );

            return;
        }

        passwordInput.value = "";

        showLoginMessage(
            "Authentication successful. Redirecting...",
            "successMessage"
        );

        redirecting = true;
        window.location.replace("index.html");
    } catch {
        showLoginMessage(
            "Sign-in is temporarily unavailable. Please try again.",
            "errorMessage"
        );
    } finally {
        if (!redirecting) {
            setLoginButtonLoading(false);
        }
    }
});