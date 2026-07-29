-- =========================================================
-- Require MFA assurance level 2 for protected member data.
--
-- Password authentication alone produces an AAL1 session.
-- This policy requires a successfully verified MFA factor
-- before PostgreSQL returns a member record.
-- =========================================================

alter table public.members
enable row level security;

alter table public.members
force row level security;

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
    and
    coalesce(
        (select auth.jwt() ->> 'aal'),
        'aal1'
    ) = 'aal2'
);

-- Preserve the application's read-only permission model.
revoke insert, update, delete, truncate, references, trigger
on table public.members
from authenticated;

grant select
on table public.members
to authenticated;