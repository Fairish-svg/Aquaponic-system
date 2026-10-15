-- Run in the Supabase SQL Editor for a new project.
create extension if not exists pgcrypto;

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

create table if not exists public.collections (
  id uuid primary key default gen_random_uuid(),
  collection_number bigint generated always as identity unique,
  title text not null default 'A little collection',
  description text not null default '',
  published boolean not null default false,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create table if not exists public.photos (
  id uuid primary key default gen_random_uuid(),
  collection_id uuid not null references public.collections(id) on delete cascade,
  storage_path text not null unique,
  original_name text not null,
  sort_order integer not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists public.frame_assets (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  storage_path text not null unique,
  active boolean not null default true,
  created_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);

create index if not exists photos_collection_sort_idx on public.photos(collection_id, sort_order);
create index if not exists collections_published_number_idx on public.collections(published, collection_number desc);

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.admin_users where user_id = auth.uid()); $$;
revoke all on function public.is_admin() from public;
grant execute on function public.is_admin() to anon, authenticated;

create or replace function public.create_collection(p_title text, p_description text default '', p_published boolean default false)
returns public.collections language plpgsql security invoker set search_path = public
as $$
declare new_row public.collections;
begin
  if not public.is_admin() then raise exception 'Administrator permission required'; end if;
  insert into public.collections(title, description, published, created_by)
  values (coalesce(nullif(trim(p_title),''),'A little collection'), coalesce(p_description,''), coalesce(p_published,false), auth.uid())
  returning * into new_row;
  return new_row;
end; $$;
grant execute on function public.create_collection(text,text,boolean) to authenticated;

alter table public.admin_users enable row level security;
alter table public.collections enable row level security;
alter table public.photos enable row level security;
alter table public.frame_assets enable row level security;

drop policy if exists "admins can read admin list" on public.admin_users;
create policy "admins can read admin list" on public.admin_users for select to authenticated using (public.is_admin());

drop policy if exists "public sees published collections" on public.collections;
create policy "public sees published collections" on public.collections for select to anon, authenticated using (published or public.is_admin());
drop policy if exists "admins manage collections" on public.collections;
create policy "admins manage collections" on public.collections for all to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "public sees photos in published collections" on public.photos;
create policy "public sees photos in published collections" on public.photos for select to anon, authenticated using (exists(select 1 from public.collections c where c.id=collection_id and (c.published or public.is_admin())));
drop policy if exists "admins manage photos" on public.photos;
create policy "admins manage photos" on public.photos for all to authenticated using (public.is_admin()) with check (public.is_admin());

drop policy if exists "public sees active frames" on public.frame_assets;
create policy "public sees active frames" on public.frame_assets for select to anon, authenticated using (active or public.is_admin());
drop policy if exists "admins manage frames" on public.frame_assets;
create policy "admins manage frames" on public.frame_assets for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- Create two Storage buckets in the Supabase dashboard with these exact names:
-- gallery-photos (public bucket for direct original-file downloads)
-- frame-assets (public bucket for transparent frame overlays)
-- Then add these policies. Database policies still protect collection visibility; random storage paths are not a substitute for private-bucket security.
insert into storage.buckets (id, name, public) values ('gallery-photos','gallery-photos',true) on conflict (id) do update set public=true;
insert into storage.buckets (id, name, public) values ('frame-assets','frame-assets',true) on conflict (id) do update set public=true;

drop policy if exists "admins upload gallery photos" on storage.objects;
create policy "admins upload gallery photos" on storage.objects for insert to authenticated with check (bucket_id='gallery-photos' and public.is_admin());
drop policy if exists "admins update gallery photos" on storage.objects;
create policy "admins update gallery photos" on storage.objects for update to authenticated using (bucket_id='gallery-photos' and public.is_admin()) with check (bucket_id='gallery-photos' and public.is_admin());
drop policy if exists "admins delete gallery photos" on storage.objects;
create policy "admins delete gallery photos" on storage.objects for delete to authenticated using (bucket_id='gallery-photos' and public.is_admin());
drop policy if exists "admins upload frame assets" on storage.objects;
create policy "admins upload frame assets" on storage.objects for insert to authenticated with check (bucket_id='frame-assets' and public.is_admin());
drop policy if exists "admins update frame assets" on storage.objects;
create policy "admins update frame assets" on storage.objects for update to authenticated using (bucket_id='frame-assets' and public.is_admin()) with check (bucket_id='frame-assets' and public.is_admin());
drop policy if exists "admins delete frame assets" on storage.objects;
create policy "admins delete frame assets" on storage.objects for delete to authenticated using (bucket_id='frame-assets' and public.is_admin());

-- After creating your first user in Supabase Authentication, authorize that exact user:
-- insert into public.admin_users(user_id) values ('PASTE-AUTH-USER-UUID-HERE');
-- Disable public sign-ups in Authentication settings after creating the owner account.
