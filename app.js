console.log(window.supabase);

const client = window.supabase.createClient(
    SUPABASE_URL,
    SUPABASE_KEY
);

// Wait until the Sign In button is clicked
document
    .getElementById("loginButton")
    .addEventListener("click", async () => {

        // Get what the user typed
        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;

        // Try logging in
        const { data, error } = await client.auth.signInWithPassword({
            email: email,
            password: password
        });

        if (error) {
            alert(error.message);
            return;
        }

        

        // Later we'll send the user to the dashboard
        window.location.href = "index.html";
    });