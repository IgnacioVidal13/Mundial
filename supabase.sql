-- Ejecutá este script en Supabase → SQL Editor (una sola vez por proyecto).
-- Después: Authentication → Providers → activá Email si hace falta.

-- Álbum por usuario (JSON de figuritas)
create table if not exists public.progreso_album (
  id uuid primary key references auth.users (id) on delete cascade,
  email text,
  data jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.progreso_album enable row level security;

drop policy if exists "progreso_album_select_own" on public.progreso_album;
create policy "progreso_album_select_own"
  on public.progreso_album for select
  using (auth.uid() = id);

drop policy if exists "progreso_album_insert_own" on public.progreso_album;
create policy "progreso_album_insert_own"
  on public.progreso_album for insert
  with check (auth.uid() = id);

drop policy if exists "progreso_album_update_own" on public.progreso_album;
create policy "progreso_album_update_own"
  on public.progreso_album for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- Un código corto por usuario para QR (payload = string album comprimido)
create table if not exists public.album_intercambios (
  owner_id uuid primary key references auth.users (id) on delete cascade,
  code text not null unique,
  payload text not null,
  expires_at timestamptz not null default (now() + interval '14 days'),
  updated_at timestamptz not null default now()
);

create index if not exists album_intercambios_code_idx on public.album_intercambios (code);

alter table public.album_intercambios enable row level security;

drop policy if exists "album_intercambios_insert_own" on public.album_intercambios;
create policy "album_intercambios_insert_own"
  on public.album_intercambios for insert
  to authenticated
  with check (auth.uid() = owner_id);

drop policy if exists "album_intercambios_update_own" on public.album_intercambios;
create policy "album_intercambios_update_own"
  on public.album_intercambios for update
  to authenticated
  using (auth.uid() = owner_id)
  with check (auth.uid() = owner_id);

drop policy if exists "album_intercambios_delete_own" on public.album_intercambios;
create policy "album_intercambios_delete_own"
  on public.album_intercambios for delete
  to authenticated
  using (auth.uid() = owner_id);

-- Lectura solo por función (evita listar todos los códigos con anon)
create or replace function public.get_album_share(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  pl text;
  exp timestamptz;
begin
  if p_code is null or length(trim(p_code)) < 6 then
    return jsonb_build_object('ok', false);
  end if;

  select i.payload, i.expires_at into pl, exp
  from public.album_intercambios i
  where upper(i.code) = upper(trim(p_code))
  limit 1;

  if not found then
    return jsonb_build_object('ok', false);
  end if;

  if exp <= now() then
    return jsonb_build_object('ok', false, 'expired', true);
  end if;

  return jsonb_build_object('ok', true, 'payload', pl);
end;
$$;

grant execute on function public.get_album_share(text) to anon, authenticated;

-- Nombre público único (lo ven tus amigos en el cruce / QR)
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  username text not null unique,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own"
  on public.profiles for select
  using (auth.uid() = id);

drop policy if exists "profiles_insert_own" on public.profiles;
create policy "profiles_insert_own"
  on public.profiles for insert
  to authenticated
  with check (auth.uid() = id);

drop policy if exists "profiles_update_own" on public.profiles;
create policy "profiles_update_own"
  on public.profiles for update
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

drop policy if exists "profiles_delete_own" on public.profiles;
create policy "profiles_delete_own"
  on public.profiles for delete
  to authenticated
  using (auth.uid() = id);

-- Anónimos: solo saber si el nombre está libre (no listar tabla)
create or replace function public.username_disponible(p_username text)
returns boolean
language sql
security definer
set search_path = public
as $$
  select not exists (
    select 1 from public.profiles p
    where lower(p.username) = lower(trim(p_username))
  );
$$;

grant execute on function public.username_disponible(text) to anon, authenticated;
