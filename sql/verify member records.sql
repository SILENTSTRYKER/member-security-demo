create table members (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references auth.users(id),
    name text not null,
    email text not null,
    membership text not null
);