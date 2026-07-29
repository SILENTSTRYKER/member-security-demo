-- Improve performance for ownership checks used by RLS policies.

create index if not exists members_user_id_idx
on public.members (user_id);