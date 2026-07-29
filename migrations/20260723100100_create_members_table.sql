-- Create the protected members table.
-- This is the first migration and must run before RLS,
-- indexes, or security policies are created.

create table if not exists public.members (
    id uuid primary key default gen_random_uuid(),

    user_id uuid not null
        unique
        references auth.users(id)
        on delete cascade,

    name text not null,

    email text not null,

    membership text not null,

    created_at timestamptz
        not null
        default now()
);

comment on table public.members is
'Protected member records linked to Supabase Auth users.';

comment on column public.members.user_id is
'The Supabase Auth user that owns this member record.';