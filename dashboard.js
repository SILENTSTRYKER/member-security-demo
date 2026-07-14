// Connect to Supabase
const client = window.supabase.createClient(
    SUPABASE_URL,
    SUPABASE_KEY
);

// Display the currently logged in user
async function loadCurrentUser() {

    const {
        data: { user }
    } = await client.auth.getUser();

    if (user) {

        document.getElementById("currentUser").innerHTML = `
            <h3>👤 Current User</h3>

            <p><strong>${user.email}</strong></p>

            <p style="color:#34C759; font-weight:600;">
                ● Secure Session Active
            </p>
        `;

    }

}

// Load the current user when the page opens
loadCurrentUser();


// Load member records
document
    .getElementById("loadMembers")
    .addEventListener("click", async () => {

        const { data, error } = await client
            .from("members")
            .select("*");

        if (error) {
            alert(error.message);
            return;
        }

        // Show how many records were returned
        document.getElementById("memberCount").innerHTML =
            `<strong>${data.length}</strong> Secure Member Record${data.length === 1 ? "" : "s"} Loaded`;

        const membersDiv = document.getElementById("members");
        membersDiv.innerHTML = "";

        // Display each member
        data.forEach(member => {

            membersDiv.innerHTML += `
                <div class="card">

                    <h2>${member.name}</h2>

                    <hr>

                    <p><strong>Membership</strong></p>
                    <p>${member.membership}</p>

                    <p><strong>Email</strong></p>
                    <p>${member.email}</p>

                </div>
            `;

        });

    });


// Logout button
document
    .getElementById("logoutButton")
    .addEventListener("click", async () => {

        await client.auth.signOut();

        window.location.href = "login.html";

    });