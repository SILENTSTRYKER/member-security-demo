// =========================================
// Nexark Security Operations Dashboard
// dashboard.js
// =========================================

const client = window.supabase.createClient(
    SUPABASE_URL,
    SUPABASE_KEY
);

let currentUser = null;

// =========================================
// DOM Elements
// =========================================

const loadMembersButton =
    document.getElementById("loadMembers");

const unauthorizedTestButton =
    document.getElementById("testUnauthorizedAccess");

const validationResults =
    document.getElementById("validationResults");

const membersDiv =
    document.getElementById("members");

const validationMessage =
    document.getElementById("validationMessage");

// =========================================
// Utility Functions
// =========================================

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function formatTime(date = new Date()) {
    return date.toLocaleTimeString([], {
        hour: "numeric",
        minute: "2-digit",
        second: "2-digit"
    });
}

function updateStatus(elementId, text, type) {
    const element = document.getElementById(elementId);

    element.textContent = `● ${text}`;

    element.classList.remove(
        "successStatus",
        "failureStatus",
        "pendingStatus"
    );

    element.classList.add(type);
}

function showMessage(message, type = "warningMessage") {
    validationMessage.hidden = false;
    validationMessage.textContent = message;

    validationMessage.className =
        `messageBox ${type}`;
}

function clearMessage() {
    validationMessage.hidden = true;
    validationMessage.textContent = "";
    validationMessage.className = "messageBox";
}

function setButtonLoading(button, loadingText) {
    button.disabled = true;

    button.innerHTML =
        `<span class="spinner"></span>${loadingText}`;
}

function resetButtons() {
    loadMembersButton.disabled = false;
    loadMembersButton.textContent =
        "Validate My Access";

    unauthorizedTestButton.disabled = false;
    unauthorizedTestButton.textContent =
        "Test Unauthorized Access";
}

// =========================================
// Client Activity Timeline
// =========================================

function addAuditEvent(message) {
    const auditLog =
        document.getElementById("auditLog");

    const placeholder =
        document.getElementById("auditPlaceholder");

    if (placeholder) {
        placeholder.remove();
    }

    const item =
        document.createElement("div");

    item.className = "logItem";

    const time =
        document.createElement("span");

    time.className = "logTime";
    time.textContent = formatTime();

    const eventMessage =
        document.createElement("span");

    eventMessage.textContent = message;

    item.append(time, eventMessage);
    auditLog.prepend(item);
}

// =========================================
// Session Handling
// =========================================

async function loadCurrentUser() {
    const {
        data: { user },
        error
    } = await client.auth.getUser();

    if (error || !user) {
        window.location.href = "login.html";
        return;
    }

    currentUser = user;

    document.getElementById(
        "currentUser"
    ).innerHTML = `
        <div class="sessionGrid">

            <div class="sessionItem">
                <span class="sessionLabel">
                    User
                </span>

                <span class="sessionValue">
                    ${escapeHtml(user.email)}
                </span>
            </div>

            <div class="sessionItem">
                <span class="sessionLabel">
                    Status
                </span>

                <span class="sessionValue successText">
                    Secure Session Active
                </span>
            </div>

            <div class="sessionItem">
                <span class="sessionLabel">
                    Session Validated
                </span>

                <span class="sessionValue">
                    ${escapeHtml(formatTime())}
                </span>
            </div>

        </div>
    `;

    updateStatus(
        "authenticationStatus",
        "Healthy",
        "successStatus"
    );

    updateStatus(
        "sessionStatus",
        "Active",
        "successStatus"
    );

    resetButtons();

    addAuditEvent("Authentication token validated.");
    addAuditEvent("Secure session established.");
}

client.auth.onAuthStateChange((event, session) => {
    if (
        event === "SIGNED_OUT" ||
        !session
    ) {
        window.location.href = "login.html";
    }
});

loadCurrentUser();

// =========================================
// Authorized Access Validation
// =========================================

loadMembersButton.addEventListener(
    "click",
    async () => {
        clearMessage();

        setButtonLoading(
            loadMembersButton,
            "Validating Access"
        );

        unauthorizedTestButton.disabled = true;

        addAuditEvent(
            "Authorized-access validation started."
        );

        const { data, error } = await client
            .from("members")
            .select(
                "id, user_id, name, email, membership"
            );

        if (error) {
            updateStatus(
                "databaseStatus",
                "Query Failed",
                "failureStatus"
            );

            updateStatus(
                "rlsStatus",
                "Not Verified",
                "failureStatus"
            );

            showMessage(
                `Protected query failed: ${error.message}`,
                "errorMessage"
            );

            validationResults.innerHTML = `
                <div class="securityResult">
                    <span class="resultLabel">
                        Protected Query
                    </span>

                    <span class="fail">
                        Failed
                    </span>
                </div>
            `;

            addAuditEvent(
                `Protected query failed: ${error.message}`
            );

            resetButtons();
            return;
        }

        const records =
            Array.isArray(data) ? data : [];

        const recordAvailable =
            records.length > 0;

        const ownershipMatches =
            records.every(
                record =>
                    record.user_id === currentUser.id
            );

        const authorized =
            recordAvailable && ownershipMatches;

        updateStatus(
            "databaseStatus",
            "Connected",
            "successStatus"
        );

        if (authorized) {
            updateStatus(
                "rlsStatus",
                "Isolation Validated",
                "successStatus"
            );

            showMessage(
                "Authorized access verified. Every returned row belongs to the authenticated user.",
                "successMessage"
            );
        } else if (!recordAvailable) {
            updateStatus(
                "rlsStatus",
                "No Record to Verify",
                "pendingStatus"
            );

            showMessage(
                "No member row was returned. Confirm that this authenticated user has a linked record.",
                "warningMessage"
            );
        } else {
            updateStatus(
                "rlsStatus",
                "Isolation Failed",
                "failureStatus"
            );

            showMessage(
                "Security validation failed. At least one returned row belongs to another user.",
                "errorMessage"
            );
        }

        const passedChecks =
            authorized ? 5 : recordAvailable ? 3 : 4;

        const score =
            Math.round(
                (passedChecks / 5) * 100
            );

        document.getElementById(
            "memberCount"
        ).innerHTML = `
            <div class="scoreCard">

                <div class="scoreNumber ${
                    score === 100
                        ? ""
                        : "warningScore"
                }">
                    ${score}%
                </div>

                <div>
                    <p class="scoreTitle">
                        Authorized-Access Validation
                    </p>

                    <p class="scoreDescription">
                        ${passedChecks}/5 checks passed •
                        ${records.length}
                        protected record${records.length === 1 ? "" : "s"}
                        returned
                    </p>
                </div>

            </div>
        `;

        validationResults.innerHTML = `
            <div class="securityResult">
                <span class="resultLabel">
                    Authentication
                </span>

                <span class="pass">
                    Operational
                </span>
            </div>

            <div class="securityResult">
                <span class="resultLabel">
                    Secure Session
                </span>

                <span class="pass">
                    Active
                </span>
            </div>

            <div class="securityResult">
                <span class="resultLabel">
                    Database Connection
                </span>

                <span class="pass">
                    Connected
                </span>
            </div>

            <div class="securityResult">
                <span class="resultLabel">
                    Returned-Row Ownership
                </span>

                <span class="${
                    ownershipMatches && recordAvailable
                        ? "pass"
                        : recordAvailable
                            ? "fail"
                            : "warning"
                }">
                    ${
                        ownershipMatches && recordAvailable
                            ? "Validated"
                            : recordAvailable
                                ? "Failed"
                                : "No Record to Verify"
                    }
                </span>
            </div>

            <div class="securityResult">
                <span class="resultLabel">
                    Authorized Record Access
                </span>

                <span class="${
                    authorized
                        ? "pass"
                        : recordAvailable
                            ? "fail"
                            : "warning"
                }">
                    ${
                        authorized
                            ? "Verified"
                            : recordAvailable
                                ? "Failed"
                                : "No Accessible Record"
                    }
                </span>
            </div>

            <div class="securityResult">
                <span class="resultLabel">
                    Protected Records Returned
                </span>

                <span>
                    ${records.length}
                </span>
            </div>
        `;

        membersDiv.innerHTML = "";

        if (!recordAvailable) {
            membersDiv.innerHTML = `
                <div class="emptyState">
                    No accessible member record was returned.
                </div>
            `;
        } else if (!ownershipMatches) {
            membersDiv.innerHTML = `
                <div class="emptyState failureText">
                    Returned records were hidden because ownership
                    validation failed.
                </div>
            `;
        } else {
            records.forEach(record => {
                const card =
                    document.createElement("article");

                card.className = "card";

                card.innerHTML = `
                    <h3>
                        ${escapeHtml(record.name)}
                    </h3>

                    <hr>

                    <div class="recordField">
                        <span class="recordLabel">
                            Membership
                        </span>

                        <p class="recordValue">
                            ${escapeHtml(record.membership)}
                        </p>
                    </div>

                    <div class="recordField">
                        <span class="recordLabel">
                            Email
                        </span>

                        <p class="recordValue">
                            ${escapeHtml(record.email)}
                        </p>
                    </div>

                    <div class="recordField">
                        <span class="recordLabel">
                            Data Classification
                        </span>

                        <span class="classificationBadge">
                            Protected
                        </span>
                    </div>
                `;

                membersDiv.appendChild(card);
            });
        }

        addAuditEvent(
            `${records.length} authorized record${records.length === 1 ? "" : "s"} returned.`
        );

        addAuditEvent(
            authorized
                ? "Authorized-access validation passed."
                : "Authorized-access validation requires attention."
        );

        resetButtons();
    }
);

// =========================================
// Unauthorized Access Test
// =========================================

unauthorizedTestButton.addEventListener(
    "click",
    async () => {
        clearMessage();

        setButtonLoading(
            unauthorizedTestButton,
            "Testing Isolation"
        );

        loadMembersButton.disabled = true;

        addAuditEvent(
            "Unauthorized-access simulation started."
        );

        /*
         * Request rows whose owner is not the current user.
         * With the SELECT RLS policy enabled, the authenticated
         * client should receive zero rows.
         */
        const { data, error } = await client
            .from("members")
            .select("id, user_id, name")
            .neq("user_id", currentUser.id);

        if (error) {
            showMessage(
                `Unauthorized-access test could not run: ${error.message}`,
                "errorMessage"
            );

            addAuditEvent(
                `Unauthorized-access test failed to execute: ${error.message}`
            );

            resetButtons();
            return;
        }

        const exposedRecords =
            Array.isArray(data) ? data : [];

        const blocked =
            exposedRecords.length === 0;

        if (blocked) {
            updateStatus(
                "rlsStatus",
                "Unauthorized Access Blocked",
                "successStatus"
            );

            showMessage(
                "Unauthorized-access test passed. The request returned zero records belonging to other users.",
                "successMessage"
            );
        } else {
            updateStatus(
                "rlsStatus",
                "Data Exposure Detected",
                "failureStatus"
            );

            showMessage(
                `Critical: ${exposedRecords.length} unauthorized record(s) were exposed.`,
                "errorMessage"
            );
        }

        validationResults.innerHTML = `
            <div class="securityResult">
                <span class="resultLabel">
                    Test Type
                </span>

                <span>
                    Cross-User Record Request
                </span>
            </div>

            <div class="securityResult">
                <span class="resultLabel">
                    Requested Owner
                </span>

                <span>
                    Any user other than the current user
                </span>
            </div>

            <div class="securityResult">
                <span class="resultLabel">
                    Unauthorized Records Exposed
                </span>

                <span class="${
                    blocked ? "pass" : "fail"
                }">
                    ${exposedRecords.length}
                </span>
            </div>

            <div class="securityResult">
                <span class="resultLabel">
                    Isolation Result
                </span>

                <span class="${
                    blocked ? "pass" : "fail"
                }">
                    ${
                        blocked
                            ? "Blocked"
                            : "Failed"
                    }
                </span>
            </div>
        `;

        document.getElementById(
            "memberCount"
        ).innerHTML = `
            <div class="scoreCard">

                <div class="scoreNumber ${
                    blocked
                        ? ""
                        : "failureScore"
                }">
                    ${blocked ? "PASS" : "FAIL"}
                </div>

                <div>
                    <p class="scoreTitle">
                        Unauthorized-Access Simulation
                    </p>

                    <p class="scoreDescription">
                        ${
                            blocked
                                ? "The database returned no cross-user records."
                                : `${exposedRecords.length} unauthorized record(s) were exposed.`
                        }
                    </p>
                </div>

            </div>
        `;

        addAuditEvent(
            blocked
                ? "Unauthorized cross-user request returned zero records."
                : `${exposedRecords.length} unauthorized record(s) were exposed.`
        );

        addAuditEvent(
            blocked
                ? "Unauthorized-access simulation passed."
                : "Unauthorized-access simulation failed."
        );

        resetButtons();
    }
);

// =========================================
// Logout
// =========================================

document
    .getElementById("logoutButton")
    .addEventListener("click", async () => {
        const logoutButton =
            document.getElementById("logoutButton");

        logoutButton.disabled = true;

        logoutButton.innerHTML =
            `<span class="spinner"></span>Signing Out`;

        addAuditEvent("Secure logout initiated.");

        const { error } =
            await client.auth.signOut();

        if (error) {
            showMessage(
                `Logout failed: ${error.message}`,
                "errorMessage"
            );

            logoutButton.disabled = false;
            logoutButton.textContent = "Logout";
        }
    });