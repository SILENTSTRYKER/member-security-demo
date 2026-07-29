-- Allow authenticated users to update only records they own.
-- WITH CHECK prevents changing a record's owner.

drop policy if exists
"Users can update their own member record"
on public.members;

create policy
"Users can update their own member record"
on public.members
for update
to authenticated
using (
    (select auth.uid()) = user_id
)
with check (
    (select auth.uid()) = user_id
);