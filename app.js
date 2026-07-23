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

// =========================================
// Show Login Message
// =========================================

function showLoginMessage(message, type = "") {
    loginMessage.textContent = message;
    loginMessage.className = `loginMessage ${type}`;
}

// =========================================
// Redirect Existing Session
// =========================================

async function checkExistingSession() {
    const {
        data: { session }
    } = await client.auth.getSession();

    if (session) {
        window.location.href = "index.html";
    }
}

checkExistingSession();

// =========================================
// Login
// =========================================

loginForm.addEventListener("submit", async event => {
    event.preventDefault();

    const email = document
        .getElementById("email")
        .value
        .trim();

    const password = document
        .getElementById("password")
        .value;

    showLoginMessage("");

    loginButton.disabled = true;
    loginButton.innerHTML =
        `<span class="spinner"></span>Authenticating`;

    const { error } = await client.auth.signInWithPassword({
        email,
        password
    });

    if (error) {
        showLoginMessage(
            "Sign-in failed. Check your email and password.",
            "errorMessage"
        );

        loginButton.disabled = false;
        loginButton.textContent = "Sign In";

        return;
    }

    showLoginMessage(
        "Authentication successful. Redirecting...",
        "successMessage"
    );

    window.location.href = "index.html";
});