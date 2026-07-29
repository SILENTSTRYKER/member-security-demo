-- Enable PostgreSQL Row Level Security for API access.

alter table public.members
enable row level security;

-- FORCE also applies RLS to the table owner during normal queries.
-- Supabase service-role requests can still bypass RLS and must
-- never be exposed in browser code.

alter table public.members
force row level security;