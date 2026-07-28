# Nexark Security Portal Incident-Response Runbook

## Purpose and scope

Use this runbook for suspected unauthorized access, account compromise,
unexpected changes to `public.members`, leaked credentials, authentication
abuse, or loss of audit visibility.

The database audit log is the authoritative record of changes to member rows.
The dashboard's activity timeline is a client-side display only and is not
trusted evidence.

Never place passwords, access or refresh tokens, Supabase secret or
service-role keys, Turnstile secret keys, or private environment values in an
incident ticket, chat, screenshot, query output, or Git commit.

## Roles

- Incident commander: owns severity, decisions, timeline, and closure.
- Technical responder: preserves evidence, investigates, and contains.
- Communications owner: handles required user, customer, or regulatory notice.

For a small team, one person may fill multiple roles, but every action and
timestamp should still be recorded.

## Severity

- **SEV-1:** confirmed cross-user disclosure, secret-key compromise, destructive
  member changes, or active attacker access.
- **SEV-2:** suspected account compromise, unexplained audit activity, or a
  security control failing without confirmed disclosure.
- **SEV-3:** blocked attack, isolated misconfiguration, or monitoring anomaly
  with no evidence of unauthorized access.

## First 15 minutes

1. Open an incident record with UTC time, reporter, observed behavior, affected
   user or member IDs, and current severity. Do not copy credentials or tokens.
2. Preserve evidence before making broad changes. Record database, Auth,
   hosting, and Cloudflare time ranges and request identifiers.
3. For active compromise, contain the narrowest confirmed path:
   disable the affected account, revoke its sessions, remove a compromised
   server-side secret, or temporarily restrict the affected operation.
4. Do not disable RLS, loosen grants, expose the `private` schema, or delete
   audit records during investigation.
5. Assign an incident commander and record every containment action in UTC.

## Collect trusted database evidence

Run audit queries only from an authorized administrative database session.
The browser's publishable key and authenticated role intentionally cannot read
the `private` schema.

```sql
select
    id,
    occurred_at,
    transaction_id,
    operation,
    member_id,
    actor_user_id,
    actor_role,
    database_role,
    request_id,
    client_address,
    owner_user_id_before,
    owner_user_id_after,
    changed_columns
from private.member_audit_log
where occurred_at >= :incident_start_utc
  and occurred_at < :incident_end_utc
order by id;
```

Narrow by `member_id`, `actor_user_id`, `transaction_id`, or `request_id` when
possible. A null actor ID can be legitimate for an administrative SQL session
or background process, but it must be reconciled with the change owner and the
maintenance timeline.

Correlate the audit rows with:

- Supabase Auth events for sign-in, token refresh, logout, and account changes.
- Supabase database and API logs for the same UTC window.
- Netlify request/deployment logs.
- Cloudflare Turnstile and edge events.
- Git and deployment history for unexpected code or configuration changes.

The audit table deliberately stores member IDs, ownership transitions, and
changed column names instead of full member rows. Retrieve member PII only when
required for the investigation and restrict it to responders with a need to
know.

## Preserve and handle evidence

1. Export the smallest relevant audit time range to encrypted, access-controlled
   incident storage.
2. Record the query, UTC export time, responder, source project, row count, and
   first and last audit IDs.
3. Generate and record a SHA-256 digest of the exported file.
4. Keep the original export read-only. Perform analysis on a working copy.
5. Do not purge audit data while an incident, legal hold, or notification
   decision is open.

The append-only trigger prevents ordinary inserts, updates, deletes, and
truncation of audit rows, including accidental administrative DML. A database
owner can still alter or disable database protections, so off-platform exports
are required for durable evidence and separation of duties.

## Containment and eradication

- Revoke affected sessions and reset affected user credentials.
- If a server-side secret may be exposed, rotate it in Supabase or Cloudflare,
  update the deployment through the approved secret store, and revoke the old
  value. Never place either value in Git.
- Verify `anon` has no `members` privileges, `authenticated` has only `SELECT`,
  RLS is enabled and forced, and the ownership policy remains
  `auth.uid() = user_id`.
- Review recent migrations, deployments, administrator activity, OAuth
  settings, allowed redirect URLs, CAPTCHA settings, and authentication rate
  limits.
- Correct the root cause through a reviewed migration or code change. Never
  edit audit history to make it match the expected state.

## Recovery validation

Before closing containment:

1. Confirm login and logout still work with a legitimate browser CAPTCHA.
2. Confirm an authenticated user can read only their own member row.
3. Confirm cross-user reads return zero rows.
4. Confirm anonymous reads and authenticated writes remain blocked.
5. In a non-production verification transaction, change and roll back a test
   member row; confirm the trigger produces the expected audit evidence before
   rollback and that the rollback removes both the test change and its audit
   row.
6. Confirm application roles cannot read or write `private.member_audit_log`.
7. Monitor Auth, API, database, hosting, and edge logs for recurrence.

## Notification and closure

The incident commander determines notification obligations with appropriate
legal or privacy guidance based on affected data and jurisdictions. Record the
decision even when notification is not required.

Close only after the attack path is contained, evidence is preserved, recovery
checks pass, monitoring is stable, and follow-up owners and due dates exist.
Document the root cause, scope, UTC timeline, affected records, actions taken,
and lessons learned without including secrets or unnecessary PII.

## Retention and routine review

The system owner must approve an audit retention period based on operational,
contractual, privacy, and legal requirements. Until that policy exists, do not
automate deletion. Review audit access quarterly and test this runbook and an
evidence export at least annually.
