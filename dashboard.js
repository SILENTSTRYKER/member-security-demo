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

const logoutButton =
    document.getElementById("logoutButton");

const validationResults =
    document.getElementById("validationResults");

const membersDiv =
    document.getElementById("members");

const memberCountDiv =
    document.getElementById("memberCount");

const validationMessage =
    document.getElementById("validationMessage");

const currentUserDiv =
    document.getElementById("currentUser");

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

    if (!element) {
        return;
    }

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
    validationMessage.className = `messageBox ${type}`;
}

function clearMessage() {
    validationMessage.hidden = true;
    validationMessage.textContent = "";
    validationMessage.className = "messageBox";
}

function setButtonLoading(button, loadingText) {
    button.disabled = true;
    button.replaceChildren();
    button.setAttribute("aria-busy", "true");

    const spinner = document.createElement("span");

    spinner.className = "spinner";
    spinner.setAttribute("aria-hidden", "true");

    button.append(
        spinner,
        document.createTextNode(loadingText)
    );
}

function resetButtons() {
    const userIsAvailable = Boolean(currentUser);

    loadMembersButton.disabled = !userIsAvailable;
    loadMembersButton.removeAttribute("aria-busy");
    loadMembersButton.textContent = "Validate My Access";

    unauthorizedTestButton.disabled = !userIsAvailable;
    unauthorizedTestButton.removeAttribute("aria-busy");
    unauthorizedTestButton.textContent =
        "Test Unauthorized Access";
}

function redirectToLogin() {
    currentUser = null;
    window.location.replace("login.html");
}

// =========================================
// Client Activity Timeline
// =========================================

function addAuditEvent(message) {
    const auditLog = document.getElementById("auditLog");

    if (!auditLog) {
        return;
    }

    const placeholder =
        document.getElementById("auditPlaceholder");

    if (placeholder) {
        placeholder.remove();
    }

    const item = document.createElement("div");
    const time = document.createElement("span");
    const eventMessage = document.createElement("span");

    item.className = "logItem";

    time.className = "logTime";
    time.textContent = formatTime();

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
        window.location.replace("login.html");
        return;
    }

    const {
        data: assuranceData,
        error: assuranceError
    } = await client.auth.mfa
        .getAuthenticatorAssuranceLevel();

    if (
        assuranceError ||
        assuranceData?.currentLevel !== "aal2"
    ) {
        window.location.replace("mfa.html");
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
                    MFA-Protected Session
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
        "AAL2 Active",
        "successStatus"
    );

    resetButtons();

    addAuditEvent(
        "Authentication token and MFA assurance level validated."
    );

    addAuditEvent(
        "AAL2-protected session established."
    );
}

client.auth.onAuthStateChange((event, session) => {
    if (event === "SIGNED_OUT" || !session) {
        redirectToLogin();
    }
});

loadCurrentUser();

// =========================================
// Authorized Access Validation
// =========================================

loadMembersButton.addEventListener(
    "click",
    async () => {
        if (!currentUser) {
            redirectToLogin();
            return;
        }

        clearMessage();

        setButtonLoading(
            loadMembersButton,
            "Validating Access"
        );

        unauthorizedTestButton.disabled = true;

        addAuditEvent(
            "Authorized-access validation started."
        );

        try {
            const { data, error } = await client
                .from("members")
                .select(
                    "id, user_id, name, email, membership"
                );

            if (error) {
                throw new Error("Protected query failed.");
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
                    "No member row was returned. Confirm that this user has a linked record.",
                    "warningMessage"
                );
            } else {
                updateStatus(
                    "rlsStatus",
                    "Isolation Failed",
                    "failureStatus"
                );

                showMessage(
                    "Security validation failed. A returned row belongs to another user.",
                    "errorMessage"
                );
            }

            const passedChecks =
                authorized ? 5 : recordAvailable ? 3 : 4;

            const score =
                Math.round((passedChecks / 5) * 100);

            memberCountDiv.innerHTML = `
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
                            protected record${
                                records.length === 1
                                    ? ""
                                    : "s"
                            } returned
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

            membersDiv.replaceChildren();

            if (!recordAvailable) {
                const emptyState =
                    document.createElement("div");

                emptyState.className = "emptyState";
                emptyState.textContent =
                    "No accessible member record was returned.";

                membersDiv.appendChild(emptyState);
            } else if (!ownershipMatches) {
                const failureState =
                    document.createElement("div");

                failureState.className =
                    "emptyState failureText";

                failureState.textContent =
                    "Returned records were hidden because ownership validation failed.";

                membersDiv.appendChild(failureState);
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
                `${records.length} authorized record${
                    records.length === 1 ? "" : "s"
                } returned.`
            );

            addAuditEvent(
                authorized
                    ? "Authorized-access validation passed."
                    : "Authorized-access validation requires attention."
            );
        } catch {
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
                "Protected query failed. Please try again.",
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

            addAuditEvent("Protected query failed.");
        } finally {
            resetButtons();
        }
    }
);

// =========================================
// Unauthorized Access Test
// =========================================

unauthorizedTestButton.addEventListener(
    "click",
    async () => {
        if (!currentUser) {
            redirectToLogin();
            return;
        }

        clearMessage();

        setButtonLoading(
            unauthorizedTestButton,
            "Testing Isolation"
        );

        loadMembersButton.disabled = true;

        addAuditEvent(
            "Unauthorized-access simulation started."
        );

        try {
            /*
             * Deliberately request rows not owned by the
             * authenticated user. RLS should return zero rows.
             */
            const { data, error } = await client
                .from("members")
                .select("id, user_id, name")
                .neq("user_id", currentUser.id);

            if (error) {
                throw new Error(
                    "Unauthorized-access test failed."
                );
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
                        ${blocked ? "Blocked" : "Failed"}
                    </span>
                </div>
            `;

            memberCountDiv.innerHTML = `
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
        } catch {
            updateStatus(
                "rlsStatus",
                "Test Failed",
                "failureStatus"
            );

            showMessage(
                "Unauthorized-access test could not be completed. Please try again.",
                "errorMessage"
            );

            addAuditEvent(
                "Unauthorized-access test failed to execute."
            );
        } finally {
            resetButtons();
        }
    }
);

// =========================================
// Logout
// =========================================

logoutButton.addEventListener("click", async () => {
    setButtonLoading(
        logoutButton,
        "Signing Out"
    );

    addAuditEvent("Secure logout initiated.");

    // Remove protected records from the page immediately.
    membersDiv.replaceChildren();
    validationResults.replaceChildren();
    memberCountDiv.replaceChildren();

    try {
        const { error } =
            await client.auth.signOut({
                scope: "global"
            });

        if (error) {
            throw new Error("Logout failed.");
        }

        currentUser = null;
        window.location.replace("login.html");
    } catch {
        showMessage(
            "Logout could not be completed. Please try again.",
            "errorMessage"
        );

        logoutButton.disabled = false;
        logoutButton.removeAttribute("aria-busy");
        logoutButton.textContent = "Logout";
    }
});