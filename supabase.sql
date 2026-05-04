-- Ejecutar en Supabase SQL Editor.
-- Aplica RLS, permisos minimos y RPCs para las operaciones expuestas desde index.html.

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

-- Album por usuario (JSON de figuritas)
create table if not exists public.progreso_album (
  id uuid primary key references auth.users (id) on delete cascade,
  email text,
  data jsonb not null default '[]'::jsonb,
  updated_at timestamptz not null default now()
);

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'progreso_album_data_is_array'
      and conrelid = 'public.progreso_album'::regclass
  ) then
    alter table public.progreso_album
      add constraint progreso_album_data_is_array
      check (jsonb_typeof(data) = 'array') not valid;
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'progreso_album_data_reasonable_size'
      and conrelid = 'public.progreso_album'::regclass
  ) then
    alter table public.progreso_album
      add constraint progreso_album_data_reasonable_size
      check (octet_length(data::text) <= 200000) not valid;
  end if;
end;
$$;

alter table public.progreso_album validate constraint progreso_album_data_is_array;
alter table public.progreso_album validate constraint progreso_album_data_reasonable_size;

alter table public.progreso_album enable row level security;
alter table public.progreso_album force row level security;

drop policy if exists "progreso_album_select_own" on public.progreso_album;
create policy "progreso_album_select_own"
  on public.progreso_album for select
  to authenticated
  using (auth.uid() = id);

drop policy if exists "progreso_album_insert_own" on public.progreso_album;
create policy "progreso_album_insert_own"
  on public.progreso_album for insert
  to authenticated
  with check (
    auth.uid() = id
    and (email is null or email = (auth.jwt() ->> 'email'))
  );

drop policy if exists "progreso_album_update_own" on public.progreso_album;
create policy "progreso_album_update_own"
  on public.progreso_album for update
  to authenticated
  using (auth.uid() = id)
  with check (
    auth.uid() = id
    and (email is null or email = (auth.jwt() ->> 'email'))
  );

revoke all on public.progreso_album from anon, authenticated;
grant select, insert, update on public.progreso_album to authenticated;

-- Nombre publico unico (lo ven tus amigos en el cruce / QR)
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  username text not null unique,
  created_at timestamptz not null default now()
);

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'profiles_username_format'
      and conrelid = 'public.profiles'::regclass
  ) then
    alter table public.profiles
      add constraint profiles_username_format
      check (
        username = lower(username)
        and username ~ '^[a-z0-9_]{3,20}$'
      ) not valid;
  end if;
end;
$$;

create unique index if not exists profiles_username_lower_key
  on public.profiles (lower(username));

alter table public.profiles validate constraint profiles_username_format;

alter table public.profiles enable row level security;

drop policy if exists "profiles_select_own" on public.profiles;
create policy "profiles_select_own"
  on public.profiles for select
  to authenticated
  using (auth.uid() = id);

drop policy if exists "profiles_insert_own" on public.profiles;
drop policy if exists "profiles_update_own" on public.profiles;
drop policy if exists "profiles_delete_own" on public.profiles;

revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;

-- El cliente no escribe profiles directo: alta/sync quedan server-side.
create or replace function public.ensure_user_profile()
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_username text := lower(trim(coalesce(auth.jwt() -> 'user_metadata' ->> 'username', '')));
  v_saved text;
begin
  if v_uid is null then
    raise exception 'not_authenticated' using errcode = '28000';
  end if;

  if v_username !~ '^[a-z0-9_]{3,20}$' then
    return null;
  end if;

  begin
    insert into public.profiles (id, username)
    values (v_uid, v_username)
    on conflict (id) do nothing;
  exception
    when unique_violation then
      return null;
  end;

  select username into v_saved
  from public.profiles
  where id = v_uid;

  return v_saved;
end;
$$;

revoke all on function public.ensure_user_profile() from public;
grant execute on function public.ensure_user_profile() to authenticated;

create or replace function public.handle_new_user_profile()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_username text := lower(trim(coalesce(new.raw_user_meta_data ->> 'username', '')));
begin
  if v_username ~ '^[a-z0-9_]{3,20}$' then
    begin
      insert into public.profiles (id, username)
      values (new.id, v_username)
      on conflict (id) do nothing;
    exception
      when unique_violation then
        null;
    end;
  end if;

  return new;
end;
$$;

revoke all on function public.handle_new_user_profile() from public;

drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile
  after insert on auth.users
  for each row execute function public.handle_new_user_profile();

-- Anonimos: solo saber si el nombre esta libre (no listar tabla).
create or replace function public.username_disponible(p_username text)
returns boolean
language sql
security definer
set search_path = public
as $$
  select case
    when p_username is null then false
    when lower(trim(p_username)) !~ '^[a-z0-9_]{3,20}$' then false
    else not exists (
      select 1 from public.profiles p
      where lower(p.username) = lower(trim(p_username))
    )
  end;
$$;

revoke all on function public.username_disponible(text) from public;
grant execute on function public.username_disponible(text) to anon, authenticated;

-- Un codigo corto por usuario para QR (payload = string album comprimido).
-- La tabla no se expone por PostgREST; se escribe/lee solamente via RPC.
create table if not exists public.album_intercambios (
  owner_id uuid primary key references auth.users (id) on delete cascade,
  code text not null unique,
  payload text not null,
  expires_at timestamptz not null default (now() + interval '14 days'),
  updated_at timestamptz not null default now()
);

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conname = 'album_intercambios_code_format'
      and conrelid = 'public.album_intercambios'::regclass
  ) then
    alter table public.album_intercambios
      add constraint album_intercambios_code_format
      check (code ~ '^[A-Z0-9]{6,14}$') not valid;
  end if;

  if not exists (
    select 1 from pg_constraint
    where conname = 'album_intercambios_payload_reasonable_size'
      and conrelid = 'public.album_intercambios'::regclass
  ) then
    alter table public.album_intercambios
      add constraint album_intercambios_payload_reasonable_size
      check (char_length(payload) between 1 and 50000) not valid;
  end if;
end;
$$;

alter table public.album_intercambios validate constraint album_intercambios_code_format;
alter table public.album_intercambios validate constraint album_intercambios_payload_reasonable_size;

create index if not exists album_intercambios_code_idx on public.album_intercambios (code);

alter table public.album_intercambios enable row level security;

drop policy if exists "album_intercambios_insert_own" on public.album_intercambios;
drop policy if exists "album_intercambios_update_own" on public.album_intercambios;
drop policy if exists "album_intercambios_delete_own" on public.album_intercambios;
drop policy if exists "album_intercambios_select_own" on public.album_intercambios;

revoke all on public.album_intercambios from anon, authenticated;

create or replace function public.upsert_album_share(
  p_payload text,
  p_expires_at timestamptz default (now() + interval '14 days')
)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_uid uuid := auth.uid();
  v_code text;
  v_expires_at timestamptz;
  v_attempt int;
  v_i int;
  v_has_existing boolean := false;
begin
  if v_uid is null then
    raise exception 'not_authenticated' using errcode = '28000';
  end if;

  if p_payload is null or char_length(p_payload) = 0 or char_length(p_payload) > 50000 then
    raise exception 'invalid_payload' using errcode = '22023';
  end if;

  v_expires_at := greatest(
    now() + interval '1 hour',
    least(coalesce(p_expires_at, now() + interval '14 days'), now() + interval '30 days')
  );

  select code into v_code
  from public.album_intercambios
  where owner_id = v_uid;

  v_has_existing := found;

  if v_has_existing and char_length(v_code) = 10 then
    update public.album_intercambios
    set payload = p_payload,
        expires_at = v_expires_at,
        updated_at = now()
    where owner_id = v_uid
    returning code into v_code;

    return v_code;
  end if;

  for v_attempt in 1..10 loop
    v_code := '';
    for v_i in 1..10 loop
      v_code := v_code || substr('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', 1 + (get_byte(gen_random_bytes(1), 0) % 32), 1);
    end loop;

    begin
      if v_has_existing then
        update public.album_intercambios
        set code = v_code,
            payload = p_payload,
            expires_at = v_expires_at,
            updated_at = now()
        where owner_id = v_uid
        returning code into v_code;
      else
        insert into public.album_intercambios (owner_id, code, payload, expires_at, updated_at)
        values (v_uid, v_code, p_payload, v_expires_at, now());
      end if;

      return v_code;
    exception
      when unique_violation then
        null;
    end;
  end loop;

  raise exception 'could_not_generate_code' using errcode = '23505';
end;
$$;

revoke all on function public.upsert_album_share(text, timestamptz) from public;
grant execute on function public.upsert_album_share(text, timestamptz) to authenticated;

-- Lectura publica solo por funcion (evita listar todos los codigos con anon).
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
  if p_code is null or upper(trim(p_code)) !~ '^[A-Z0-9]{6,14}$' then
    return jsonb_build_object('ok', false);
  end if;

  select i.payload, i.expires_at into pl, exp
  from public.album_intercambios i
  where i.code = upper(trim(p_code))
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

revoke all on function public.get_album_share(text) from public;
grant execute on function public.get_album_share(text) to anon, authenticated;

-- Amigos guardados: relacion unidireccional. Quien conoce tu codigo puede agregarte.
create table if not exists public.album_amigos (
  owner_id uuid not null references auth.users (id) on delete cascade,
  friend_id uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (owner_id, friend_id),
  check (owner_id <> friend_id)
);

alter table public.album_amigos enable row level security;
alter table public.album_amigos force row level security;

drop policy if exists "album_amigos_select_own" on public.album_amigos;
create policy "album_amigos_select_own"
  on public.album_amigos for select
  to authenticated
  using (auth.uid() = owner_id);

drop policy if exists "album_amigos_insert_own" on public.album_amigos;
create policy "album_amigos_insert_own"
  on public.album_amigos for insert
  to authenticated
  with check (auth.uid() = owner_id);

drop policy if exists "album_amigos_update_own" on public.album_amigos;
drop policy if exists "album_amigos_delete_own" on public.album_amigos;
create policy "album_amigos_delete_own"
  on public.album_amigos for delete
  to authenticated
  using (auth.uid() = owner_id);

revoke all on public.album_amigos from anon, authenticated;
grant select, insert, delete on public.album_amigos to authenticated;

create or replace function public.add_friend_by_code(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_friend uuid;
  v_username text;
  v_code text := upper(trim(coalesce(p_code, '')));
begin
  if v_uid is null then
    raise exception 'not_authenticated' using errcode = '28000';
  end if;

  if v_code !~ '^[A-Z0-9]{6,14}$' then
    return jsonb_build_object('ok', false, 'reason', 'invalid_code');
  end if;

  select owner_id into v_friend
  from public.album_intercambios
  where code = v_code
    and expires_at > now()
  limit 1;

  if not found then
    return jsonb_build_object('ok', false, 'reason', 'not_found');
  end if;

  if v_friend = v_uid then
    return jsonb_build_object('ok', false, 'reason', 'self');
  end if;

  insert into public.album_amigos (owner_id, friend_id)
  values (v_uid, v_friend)
  on conflict (owner_id, friend_id) do nothing;

  select username into v_username
  from public.profiles
  where id = v_friend;

  return jsonb_build_object(
    'ok', true,
    'friend_id', v_friend,
    'username', coalesce(v_username, 'Amigo')
  );
end;
$$;

revoke all on function public.add_friend_by_code(text) from public;
grant execute on function public.add_friend_by_code(text) to authenticated;

create or replace function public.list_friend_albums()
returns jsonb
language sql
security definer
set search_path = public
as $$
  select coalesce(jsonb_agg(
    jsonb_build_object(
      'friend_id', a.friend_id,
      'username', coalesce(p.username, 'Amigo'),
      'code', i.code,
      'payload', i.payload,
      'updated_at', i.updated_at,
      'expires_at', i.expires_at
    )
    order by coalesce(p.username, 'Amigo')
  ), '[]'::jsonb)
  from public.album_amigos a
  left join public.profiles p on p.id = a.friend_id
  left join public.album_intercambios i
    on i.owner_id = a.friend_id
   and i.expires_at > now()
  where a.owner_id = auth.uid();
$$;

revoke all on function public.list_friend_albums() from public;
grant execute on function public.list_friend_albums() to authenticated;

create or replace function public.remove_friend(p_friend_id uuid)
returns boolean
language sql
security definer
set search_path = public
as $$
  delete from public.album_amigos
  where owner_id = auth.uid()
    and friend_id = p_friend_id
  returning true;
$$;

revoke all on function public.remove_friend(uuid) from public;
grant execute on function public.remove_friend(uuid) to authenticated;
