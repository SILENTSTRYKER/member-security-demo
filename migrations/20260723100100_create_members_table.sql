-- Require PostgreSQL Row Level Security for all API access.

alter table public.members
enable row level security;

-- FORCE applies RLS even to the table owner in normal queries.
-- Supabase service-role requests can still bypass RLS and must remain server-side.
alter table public.members
force row level security;
