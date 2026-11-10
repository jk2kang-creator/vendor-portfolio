-- ============================================================
-- 01. 벤더 포트폴리오: 관리자 계정(app_users) + portfolio_vendors 테이블 + 접근 정책
-- Supabase 프로젝트: etevers-bundle-hub (tghfiwrjjfzmipguvgti)
--   · 조회: 누구나(로그인 불필요)
--   · 추가/수정/삭제: app_users.role = 'admin' 이고 승인된 계정만
-- 같은 프로젝트의 번들 허브용 vendors 테이블과 겹치지 않도록 portfolio_vendors 이름을 씁니다.
-- 여러 번 실행해도 안전합니다.
-- ============================================================

-- ---------- 1. app_users: 로그인 계정 프로필 (영업 파이프라인 migration_03과 같은 구조) ----------
create table if not exists public.app_users (
  id           uuid primary key references auth.users(id) on delete cascade,
  email        text not null,
  name         text,
  department   text,
  role         text not null default 'pending'
                 check (role in ('admin','manager','rep','viewer','pending')),
  is_approved  boolean not null default false,
  created_at   timestamptz not null default now()
);
alter table public.app_users enable row level security;

-- 신규 가입(Authentication > Add user 포함) 시 app_users 행 자동 생성 — 관리자 지정 전까지 pending
create or replace function public.handle_new_auth_user()
returns trigger language plpgsql security definer set search_path = public as
$$
begin
  insert into public.app_users (id, email) values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_auth_user();

create or replace function public.app_role()
returns text language sql security definer set search_path = public stable as
$$ select coalesce((select role from app_users where id = auth.uid()), 'pending') $$;

create or replace function public.app_is_approved()
returns boolean language sql security definer set search_path = public stable as
$$ select coalesce((select is_approved from app_users where id = auth.uid()), false) $$;

drop policy if exists "app_users_select" on public.app_users;
create policy "app_users_select" on public.app_users for select to authenticated
  using (id = auth.uid() or app_role() = 'admin');
drop policy if exists "app_users_admin_write" on public.app_users;
create policy "app_users_admin_write" on public.app_users for update to authenticated
  using (app_role() = 'admin') with check (app_role() = 'admin');

-- ---------- 2. portfolio_vendors ----------
create table if not exists public.portfolio_vendors (
  id              uuid primary key default gen_random_uuid(),
  orgkey          text not null check (orgkey in ('ETV','ETS','EPA')),   -- 그룹사
  no              text not null default '',                              -- 표시 번호 (예: 01)
  name            text not null check (length(trim(name)) > 0),          -- 벤더명
  tagline         text not null default '',                              -- 한 줄 설명
  cluster         text not null check (cluster in ('인프라/클라우드','데이터/AI','보안/보호','비즈니스 운영')),
  issue_tags      text[] not null default '{}',                          -- 핫이슈
  target          text not null default '',                              -- 고객타겟
  revenue         text not null default '',                              -- 매출모델
  owner           text not null default '',                              -- 담당자
  email           text not null default '',
  company         text not null default '',                              -- 담당자 소속
  scope           text not null default '',                              -- 담당영역 (표시용 원문)
  scope_tags      text[] not null default '{}',                          -- 담당영역 (필터용 태그)
  insight_segs    jsonb not null default '[]'::jsonb,                    -- [{label, body}] 세일즈 인사이트
  features        text not null default '',                              -- 핵심 기능
  edge            text not null default '',                              -- 경쟁 우위
  flags           text[] not null default '{}',                          -- 데이터 보완 플래그 (관리자에게만 표시)
  money_mentions  text[] not null default '{}',                          -- 리베이트·마진 등 수익조건 언급 키워드
  sort_order      integer not null default 0,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now(),
  updated_by      uuid references auth.users(id) on delete set null,
  updated_by_email text
);

create index if not exists portfolio_vendors_org_idx on public.portfolio_vendors (orgkey, no);

-- 저장할 때마다 수정 시각·수정자를 자동 기록
create or replace function public.portfolio_vendors_touch()
returns trigger language plpgsql security definer set search_path = public as
$$
begin
  new.updated_at := now();
  new.updated_by := auth.uid();
  new.updated_by_email := (select email from app_users where id = auth.uid());
  return new;
end;
$$;

drop trigger if exists portfolio_vendors_touch on public.portfolio_vendors;
create trigger portfolio_vendors_touch
  before insert or update on public.portfolio_vendors
  for each row execute function public.portfolio_vendors_touch();

-- ---------- 3. RLS ----------
alter table public.portfolio_vendors enable row level security;

drop policy if exists "portfolio_vendors_read" on public.portfolio_vendors;
create policy "portfolio_vendors_read" on public.portfolio_vendors for select
  to anon, authenticated using (true);

drop policy if exists "portfolio_vendors_admin_insert" on public.portfolio_vendors;
create policy "portfolio_vendors_admin_insert" on public.portfolio_vendors for insert to authenticated
  with check (app_role() = 'admin' and app_is_approved());

drop policy if exists "portfolio_vendors_admin_update" on public.portfolio_vendors;
create policy "portfolio_vendors_admin_update" on public.portfolio_vendors for update to authenticated
  using (app_role() = 'admin' and app_is_approved())
  with check (app_role() = 'admin' and app_is_approved());

drop policy if exists "portfolio_vendors_admin_delete" on public.portfolio_vendors;
create policy "portfolio_vendors_admin_delete" on public.portfolio_vendors for delete to authenticated
  using (app_role() = 'admin' and app_is_approved());

-- 로그인 후 본인이 포트폴리오 관리자인지 확인하는 함수 (화면의 관리자 모드 전환에 사용)
create or replace function public.is_portfolio_admin()
returns boolean language sql security definer set search_path = public stable as
$$ select app_role() = 'admin' and app_is_approved() $$;
revoke execute on function public.is_portfolio_admin() from anon, public;
grant execute on function public.is_portfolio_admin() to authenticated;

-- ============================================================
-- 최초 관리자 지정 (한 번만)
-- 1) Supabase 대시보드 > Authentication > Users > Add user 로 관리자 계정 생성
-- 2) 아래 이메일을 바꿔 실행
--   update public.app_users set role = 'admin', is_approved = true where email = '관리자이메일@etevers.com';
-- ============================================================
