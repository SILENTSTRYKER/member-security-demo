-- Improve ownership-filter performance used by the RLS policies.

create index if not exists members_user_id_idx
on public.members (user_id);
