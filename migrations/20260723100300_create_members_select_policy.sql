-- Allow authenticated users to read only their own member records.

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