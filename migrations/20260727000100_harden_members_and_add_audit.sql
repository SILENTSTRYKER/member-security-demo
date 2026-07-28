-- =========================================================
-- Harden members permissions and add trusted audit logging.
--
-- Run this migration as the Supabase migration owner.
-- Audit records are stored outside the exposed public schema
-- and cannot be accessed through ordinary browser roles.
-- =========================================================

begin;

-- =========================================================
-- Members table security
-- =========================================================

alter table public.members
enable row level security;

alter table public.members
force row level security;

-- Anonymous visitors receive no table privileges.
revoke all privileges
on table public.members
from public, anon;

-- Authenticated application users receive read access only.
revoke all privileges
on table public.members
from authenticated;

grant select
on table public.members
to authenticated;

-- Remove the obsolete UPDATE policy.
drop policy if exists
"Users can update their own member record"
on public.members;

-- Recreate the ownership-based SELECT policy.
drop policy if exists
"Users can view their own member record"
on public.members;

create policy
"Users can view their own member record"
on public.members
for select
to authenticated
using (
    (select auth.uid()) = user_id
);

-- =========================================================
-- Private server-side audit storage
-- =========================================================

create schema if not exists private;

revoke all privileges
on schema private
from public, anon, authenticated;

create table if not exists private.member_audit_log (
    id bigint generated always as identity primary key,

    operation text not null
        check (
            operation in (
                'INSERT',
                'UPDATE',
                'DELETE'
            )
        ),

    member_id uuid,

    actor_user_id uuid,

    actor_role text,

    database_role text not null,

    transaction_id bigint not null,

    request_id text,

    client_address inet,

    owner_user_id_before uuid,

    owner_user_id_after uuid,

    changed_columns text[]
        not null
        default '{}',

        occurred_at timestamptz
        not null
        default clock_timestamp()
);

-- Defense in depth: block all access unless a policy
-- is deliberately created in the future.
alter table private.member_audit_log
enable row level security;

revoke all privileges
on table private.member_audit_log
from public, anon, authenticated;

revoke all privileges
on sequence private.member_audit_log_id_seq
from public, anon, authenticated;

comment on table private.member_audit_log is
'Append-only evidence for changes made to public.members.';

comment on column private.member_audit_log.request_id is
'Correlation identifier only; it must not be treated as authenticated identity.';

comment on column private.member_audit_log.client_address is
'Database connection peer address; it is not guaranteed to be the original end-user IP address.';

-- =========================================================
-- Append-only audit enforcement
-- =========================================================

create or replace function private.guard_member_audit_log()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    /*
     * A legitimate audit INSERT is nested inside the
     * public.members audit trigger.
     *
     * Direct INSERT operations, along with every UPDATE
     * and DELETE operation, are rejected.
     */
    if (
        tg_op = 'INSERT'
        and pg_catalog.pg_trigger_depth() > 1
    ) then
        return new;
    end if;

    raise exception
        'member audit records are append-only';
end;
$$;

revoke all privileges
on function private.guard_member_audit_log()
from public, anon, authenticated;

drop trigger if exists
member_audit_log_append_only
on private.member_audit_log;

create trigger member_audit_log_append_only
before insert or update or delete
on private.member_audit_log
for each row
execute function private.guard_member_audit_log();

create or replace function private.guard_member_audit_truncate()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    raise exception
        'member audit records are append-only';
end;
$$;

revoke all privileges
on function private.guard_member_audit_truncate()
from public, anon, authenticated;

drop trigger if exists
member_audit_log_no_truncate
on private.member_audit_log;

create trigger member_audit_log_no_truncate
before truncate
on private.member_audit_log
for each statement
execute function private.guard_member_audit_truncate();

-- =========================================================
-- Trusted members-table audit trigger
-- =========================================================

create or replace function private.log_member_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
    affected_member_id uuid;

    authenticated_role text;

    headers jsonb := '{}'::jsonb;

    request_identifier text;

    changed_fields text[] := '{}';
begin
    if tg_op = 'DELETE' then
        affected_member_id := old.id;
    else
        affected_member_id := new.id;
    end if;

    /*
     * Record the role from the Supabase JWT when one exists.
     * Administrative SQL may not contain JWT claims.
     */
    authenticated_role :=
        nullif(
            auth.jwt() ->> 'role',
            ''
        );

    /*
     * PostgREST supplies request headers through a database
     * setting. Administrative SQL and background jobs may not
     * include those headers.
     *
     * Missing or malformed header data must not prevent the
     * underlying database operation from being audited.
     */
    begin
        headers := coalesce(
            nullif(
                pg_catalog.current_setting(
                    'request.headers',
                    true
                ),
                ''
            )::jsonb,
            '{}'::jsonb
        );
    exception
        when others then
            headers := '{}'::jsonb;
    end;

    /*
     * Prefer Cloudflare's correlation identifier when present.
     * Limit the stored value to prevent unexpectedly large
     * header content from entering the audit table.
     */
    request_identifier :=
        pg_catalog.left(
            nullif(
                coalesce(
                    headers ->> 'cf-ray',
                    headers ->> 'x-request-id'
                ),
                ''
            ),
            200
        );

    /*
     * Record only changed column names.
     * Do not copy names, email addresses, membership values,
     * passwords, tokens, or other member data into the audit log.
     */
    if tg_op = 'UPDATE' then
        select coalesce(
            pg_catalog.array_agg(
                new_field.key
                order by new_field.key
            ),
            '{}'::text[]
        )
        into changed_fields
        from pg_catalog.jsonb_each(
            pg_catalog.to_jsonb(new)
        ) as new_field
        where (
            pg_catalog.to_jsonb(old)
                -> new_field.key
        ) is distinct from new_field.value;

    elsif tg_op = 'INSERT' then
        changed_fields := array[
            'id',
            'user_id',
            'name',
            'email',
            'membership'
        ];

    else
        changed_fields := array[
            'id',
            'user_id',
            'name',
            'email',
            'membership'
        ];
    end if;

    insert into private.member_audit_log (
        operation,
        member_id,
        actor_user_id,
        actor_role,
        database_role,
        transaction_id,
        request_id,
        client_address,
        owner_user_id_before,
        owner_user_id_after,
        changed_columns
    )
    values (
        tg_op,
        affected_member_id,
        auth.uid(),
        authenticated_role,
        session_user::text,
        pg_catalog.txid_current(),
        request_identifier,
        pg_catalog.inet_client_addr(),

        case
            when tg_op in ('UPDATE', 'DELETE')
                then old.user_id
        end,

        case
            when tg_op in ('INSERT', 'UPDATE')
                then new.user_id
        end,

        changed_fields
    );

    if tg_op = 'DELETE' then
        return old;
    end if;

    return new;
end;
$$;

revoke all privileges
on function private.log_member_change()
from public, anon, authenticated;

drop trigger if exists
members_security_audit
on public.members;

create trigger members_security_audit
after insert or update or delete
on public.members
for each row
execute function private.log_member_change();

commit;