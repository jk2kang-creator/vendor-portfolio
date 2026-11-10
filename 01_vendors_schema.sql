-- ============================================================
-- 01. 벤더 포트폴리오: vendors 테이블 + 접근 정책
-- 영업 파이프라인과 같은 Supabase 프로젝트의 SQL Editor에서 실행하세요.
-- 전제: 파이프라인 migration_03 이 적용되어 app_users / app_role() / app_is_approved() 가 있어야 합니다.
--   · 조회: 누구나(로그인 불필요)
--   · 추가/수정/삭제: app_users.role = 'admin' 이고 승인된 계정만
-- ============================================================

create table if not exists public.vendors (
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

create index if not exists vendors_org_idx on public.vendors (orgkey, no);

-- 저장할 때마다 수정 시각·수정자를 자동 기록
create or replace function public.vendors_touch()
returns trigger language plpgsql security definer set search_path = public as
$$
begin
  new.updated_at := now();
  new.updated_by := auth.uid();
  new.updated_by_email := (select email from app_users where id = auth.uid());
  return new;
end;
$$;

drop trigger if exists vendors_touch on public.vendors;
create trigger vendors_touch
  before insert or update on public.vendors
  for each row execute function public.vendors_touch();

-- ---------- RLS ----------
alter table public.vendors enable row level security;

drop policy if exists "vendors_read" on public.vendors;
create policy "vendors_read" on public.vendors for select
  to anon, authenticated using (true);

drop policy if exists "vendors_admin_insert" on public.vendors;
create policy "vendors_admin_insert" on public.vendors for insert to authenticated
  with check (app_role() = 'admin' and app_is_approved());

drop policy if exists "vendors_admin_update" on public.vendors;
create policy "vendors_admin_update" on public.vendors for update to authenticated
  using (app_role() = 'admin' and app_is_approved())
  with check (app_role() = 'admin' and app_is_approved());

drop policy if exists "vendors_admin_delete" on public.vendors;
create policy "vendors_admin_delete" on public.vendors for delete to authenticated
  using (app_role() = 'admin' and app_is_approved());

-- 로그인 후 본인이 포트폴리오 관리자인지 확인하는 함수 (화면의 관리자 모드 전환에 사용)
create or replace function public.is_portfolio_admin()
returns boolean language sql security definer set search_path = public stable as
$$ select app_role() = 'admin' and app_is_approved() $$;
grant execute on function public.is_portfolio_admin() to authenticated;
