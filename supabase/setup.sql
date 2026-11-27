-- =====================================================================
-- Aristo Contract Manpower — shared database (Supabase)
-- Run ONCE in your Supabase project: SQL Editor → New query → paste all → Run.
-- Safe to run again: it only adds what is missing and refreshes the functions.
--
-- How access works
--   * The tables are locked (row-level security on, no policies), so the public
--     Supabase key alone can read or change nothing.
--   * The website calls two functions, cw_load and cw_save. Each checks the
--     person's sign-in key against app_users, then applies their role:
--       HR Admin           everything
--       GM Production      requisitions, candidates, workers; may update requisitions
--       Production Manager / Supervisor   their division's workers, requisitions,
--                          resignations, exit clearances, attendance; may write
--                          requisitions and exit clearances for their division
--       Contractor         only their own records; may submit workers, candidates,
--                          resignations and invoices, and confirm/query payroll
-- =====================================================================

create table if not exists app_users (
  user_id    text primary key,
  fp         text not null,        -- one-way fingerprint of the sign-in key (same as middleware.js)
  role       text not null check (role in ('hr_admin','gm_production','production_manager','supervisor','contractor')),
  contractor text,
  division   text,
  name       text
);

create table if not exists records (
  collection text not null,
  id         text not null,
  data       jsonb not null,
  contractor text,
  division   text,
  updated_at timestamptz not null default now(),
  updated_by text,
  primary key (collection, id)
);
create index if not exists records_contractor_idx on records (collection, lower(trim(contractor)));
create index if not exists records_division_idx on records (collection, division);

create table if not exists app_settings (
  key        text primary key,
  value      jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by text
);

create table if not exists audit_log (
  id      bigint generated always as identity primary key,
  at      timestamptz not null default now(),
  user_id text,
  text    text not null
);

-- logins live here; the Admin Portal manages them
alter table app_users add column if not exists salt       text;          -- per-login salt for the password key
alter table app_users add column if not exists active     boolean not null default true;
alter table app_users add column if not exists created_at timestamptz not null default now();
alter table app_users add column if not exists last_login timestamptz;
alter table app_users add column if not exists emp_id      text;          -- for worker logins: their Employee ID
alter table app_users add column if not exists must_change boolean not null default false;  -- change password at next sign-in
alter table app_users add column if not exists access text not null default 'editor';   -- editor: can change things / viewer: can only look
alter table app_users drop constraint if exists app_users_access_check;
alter table app_users add constraint app_users_access_check check (access in ('editor', 'viewer'));
alter table app_users drop constraint if exists app_users_role_check;
alter table app_users add constraint app_users_role_check
  check (role in ('admin','hr_admin','gm_production','production_manager','supervisor','contractor','employee','store'));
create unique index if not exists app_users_emp_idx on app_users (emp_id) where emp_id is not null;

-- which worker a record belongs to (leave, attendance, payslips…) so workers see only their own
alter table records add column if not exists emp_id text;
create index if not exists records_emp_idx on records (collection, emp_id);

-- every sign-in attempt, good or bad
create table if not exists login_events (
  id         bigint generated always as identity primary key,
  at         timestamptz not null default now(),
  user_id    text,
  success    boolean not null,
  ip         text,
  user_agent text,
  note       text
);
create index if not exists login_events_user_idx on login_events (user_id, at desc);

-- usage signals for the Admin dashboard: app opened, first key action, documents read
create table if not exists app_events (
  id      bigint generated always as identity primary key,
  at      timestamptz not null default now(),
  user_id text,
  kind    text not null,
  meta    jsonb
);
create index if not exists app_events_idx on app_events (kind, at desc);

alter table app_users    enable row level security;
alter table records      enable row level security;
alter table app_settings enable row level security;
alter table audit_log    enable row level security;
alter table login_events enable row level security;
alter table app_events   enable row level security;
revoke all on app_users, records, app_settings, audit_log, login_events, app_events from anon, authenticated;

-- ---------------------------------------------------------------------
-- helpers
-- ---------------------------------------------------------------------
create or replace function cw_norm(t text) returns text language sql immutable as $$ select lower(trim(coalesce(t, ''))) $$;
-- a login may cover more than one division, stored as 'Division A|Division B' (e.g. a HOD common to two sections)
create or replace function cw_in_div(u_div text, d text) returns boolean language sql immutable as $$
  select d is not null and exists (select 1 from unnest(string_to_array(coalesce(u_div, ''), '|')) s where trim(s) = d) $$;

create or replace function cw_auth(p_user text, p_key text) returns app_users
language plpgsql stable security definer set search_path = public as $$
declare u app_users;
begin
  select * into u from app_users where user_id = lower(trim(p_user));
  if not found or not coalesce(u.active, false) or coalesce(p_key, '') !~ '^[0-9a-f]{64}$'
     or encode(sha256(convert_to(p_key, 'UTF8')), 'hex') is distinct from u.fp then
    raise exception 'not signed in' using errcode = '28000';
  end if;
  return u;
end $$;

-- HR Head: final candidate approval and salary fixing. The list is the admin-only setting 'admin_hr_heads'
-- (never sent to browsers, never writable from the app), so an HR Officer cannot make themselves Head.
create or replace function cw_is_hr_head(u app_users) returns boolean language sql stable as $$
  select u.role = 'admin' or (u.role = 'hr_admin' and exists (
    select 1 from app_settings s where s.key = 'admin_hr_heads' and jsonb_typeof(s.value) = 'array' and s.value ? u.user_id))
$$;
-- PPE desks: setting 'ppeDesk' {"admin": [user ids who confirm PPE needs], "store": [user ids who issue]}; the store role is always a store desk
create or replace function cw_ppe_desk(u app_users, which text) returns boolean language sql stable as $$
  select (which = 'store' and u.role = 'store') or exists (
    select 1 from app_settings s where s.key = 'ppeDesk' and jsonb_typeof(s.value) = 'object'
      and coalesce(s.value->which, '[]'::jsonb) ? u.user_id)
$$;

create or replace function cw_user_json(u app_users) returns jsonb language sql stable as $$
  select jsonb_build_object('user', u.user_id, 'role', u.role, 'contractor', u.contractor, 'division', u.division, 'name', u.name,
                            'empId', u.emp_id, 'mustChange', u.must_change, 'hrHead', cw_is_hr_head(u),
                            'ppeAdmin', cw_ppe_desk(u, 'admin'), 'ppeStore', cw_ppe_desk(u, 'store'), 'access', coalesce(u.access, 'editor'))
$$;

-- where events are copied to (the admin's Google Sheet); only the sign-in layer and admins receive it
create or replace function cw_sheet() returns jsonb language sql stable security definer set search_path = public as $$
  select coalesce((select jsonb_build_object('sheet', value) from app_settings
                   where key = 'admin_sheet' and coalesce(value->>'url', '') <> '' and coalesce((value->>'enabled')::boolean, true)), '{}'::jsonb)
$$;

-- ---------------------------------------------------------------------
-- signing in (called by middleware.js)
-- ---------------------------------------------------------------------
-- the salt for a login; unknown IDs get a stable made-up salt so they look the same as real ones
create or replace function cw_login_salt(p_user text) returns text
language sql stable security definer set search_path = public as $$
  select coalesce((select salt from app_users where user_id = lower(trim(p_user)) and salt is not null),
                  substr(encode(sha256(convert_to('aw-unknown:' || lower(trim(coalesce(p_user, ''))), 'UTF8')), 'hex'), 1, 32))
$$;

-- checks a sign-in, records the attempt, pauses a login after 10 failures in 15 minutes
create or replace function cw_login(p_user text, p_key text, p_ip text, p_ua text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare u app_users; fails int; uid text := lower(trim(coalesce(p_user, '')));
begin
  select count(*) into fails from login_events where user_id = uid and not success and at > now() - interval '15 minutes';
  if fails >= 10 then
    insert into login_events (user_id, success, ip, user_agent, note) values (uid, false, left(p_ip, 80), left(p_ua, 300), 'paused: too many attempts');
    return jsonb_build_object('ok', false, 'locked', true);
  end if;
  select * into u from app_users where user_id = uid;
  if not found or coalesce(p_key, '') !~ '^[0-9a-f]{64}$'
     or encode(sha256(convert_to(p_key, 'UTF8')), 'hex') is distinct from u.fp then
    insert into login_events (user_id, success, ip, user_agent, note) values (uid, false, left(p_ip, 80), left(p_ua, 300), case when u.user_id is null then 'unknown user ID' else 'wrong password' end);
    return jsonb_build_object('ok', false);
  end if;
  if not u.active then
    insert into login_events (user_id, success, ip, user_agent, note) values (uid, false, left(p_ip, 80), left(p_ua, 300), 'login deactivated');
    return jsonb_build_object('ok', false, 'inactive', true);
  end if;
  update app_users set last_login = now() where user_id = uid;
  insert into login_events (user_id, success, ip, user_agent) values (uid, true, left(p_ip, 80), left(p_ua, 300));
  return jsonb_build_object('ok', true) || cw_user_json(u);
end $$;

-- who is this session? (every page load; fails once a login is deactivated, deleted or its password reset)
create or replace function cw_whoami(p_user text, p_key text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  return cw_user_json(cw_auth(p_user, p_key));
end $$;

-- usage signals for the dashboard
create or replace function cw_event(p_user text, p_key text, p_kind text, p_meta jsonb) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare u app_users;
begin
  u := cw_auth(p_user, p_key);
  if p_kind not in ('open', 'aha', 'docs_read') then return '{"ok":false}'::jsonb; end if;
  insert into app_events (user_id, kind, meta)
  values (u.user_id, p_kind, case when length(coalesce(p_meta, '{}'::jsonb)::text) > 2000 then '{}'::jsonb else coalesce(p_meta, '{}'::jsonb) end);
  return jsonb_build_object('ok', true) || cw_user_json(u);
end $$;

-- ---------------------------------------------------------------------
-- Announcements and tickets (shared by every role, including workers)
--   announcements: data {by, title, body, audience: ["all"] | ["contractors"] | [division, ...], status}
--   tickets:       data {raisedBy, toDept, status, ...}; ticket departments and their handlers are the
--                  app setting 'ticketDepartments' [{name, handlers: [user_id, ...]}], edited by HR
-- ---------------------------------------------------------------------
create or replace function cw_ticket_handler(u app_users, dept text) returns boolean
language sql stable as $$
  select u.role in ('hr_admin', 'admin') or exists (
    select 1 from app_settings s,
      jsonb_array_elements(case when jsonb_typeof(s.value) = 'array' then s.value else '[]'::jsonb end) dd
    where s.key = 'ticketDepartments' and dd->>'name' = dept
      and coalesce(dd->'handlers', '[]'::jsonb) ? u.user_id)
$$;

create or replace function cw_social_read(u app_users, r records) returns boolean
language sql stable as $$
  select case
    when u.role in ('hr_admin', 'admin') then true
    -- PPE: the Admin and Store desks see every request and the stock; a division sees its own requests
    when r.collection in ('ppeRequests', 'ppeStock') then
      cw_ppe_desk(u, 'admin') or cw_ppe_desk(u, 'store')
      or (r.collection = 'ppeRequests' and u.role in ('production_manager', 'supervisor', 'gm_production') and cw_in_div(u.division, r.division))
      or (r.collection = 'ppeRequests' and u.role = 'contractor' and cw_norm(r.contractor) = cw_norm(u.contractor))
    when r.collection = 'tickets' then
      r.data->>'raisedBy' = u.user_id or cw_ticket_handler(u, r.data->>'toDept')
      -- the raising department's HOD / Manager follows up on tickets raised from their division
      or (u.role in ('production_manager', 'gm_production') and cw_in_div(u.division, r.division))
    when r.collection = 'announcements' then
      r.data->>'by' = u.user_id
      or (coalesce(r.data->>'status', 'Published') = 'Published' and (
            u.role = 'gm_production'
            or coalesce(r.data->'audience', '["all"]'::jsonb) ? 'all'
            or (u.role = 'contractor' and coalesce(r.data->'audience', '[]'::jsonb) ? 'contractors')
            or (u.role <> 'contractor' and exists (
                  select 1 from jsonb_array_elements_text(coalesce(r.data->'audience', '[]'::jsonb)) a
                  where cw_in_div(u.division, a)))))
    else false
  end
$$;

create or replace function cw_social_write(u app_users, p_coll text, prev records, d jsonb) returns boolean
language sql stable as $$
  select case
    when u.role in ('hr_admin', 'admin') then true
    when p_coll = 'ppeStock' then cw_ppe_desk(u, 'store')
    when p_coll = 'ppeRequests' then
      case when prev.collection is null then
             coalesce(d->>'status', '') = 'Pending Admin' and (
               -- raised with a requisition by its division, or by the contractor when their worker joins
               (u.role in ('production_manager', 'supervisor', 'gm_production') and cw_in_div(u.division, d->>'division'))
               or (u.role = 'contractor' and d->>'type' = 'joining' and cw_norm(d->>'contractor') = cw_norm(u.contractor)))
           when cw_ppe_desk(u, 'admin') and coalesce(prev.data->>'status', '') = 'Pending Admin' then
             coalesce(d->>'status', '') in ('Pending Admin', 'Pending Store', 'Not Required')
           when cw_ppe_desk(u, 'store') and coalesce(prev.data->>'status', '') in ('Pending Store', 'Partly Issued') then
             coalesce(d->>'status', '') in ('Pending Store', 'Partly Issued', 'Issued')
           else false end
    when p_coll = 'announcements' then
      -- GM and HODs / Managers post their own; a HOD / Manager only to their own division(s)
      u.role in ('gm_production', 'production_manager')
      and d->>'by' = u.user_id
      and (prev.collection is null or prev.data->>'by' = u.user_id)
      and (u.role = 'gm_production' or not exists (
            select 1 from jsonb_array_elements_text(coalesce(d->'audience', '[]'::jsonb)) a
            where not cw_in_div(u.division, a)))
      and jsonb_array_length(coalesce(d->'audience', '[]'::jsonb)) > 0
    when p_coll = 'tickets' then
      case when prev.collection is null
        then d->>'raisedBy' = u.user_id and coalesce(d->>'status', '') = 'Open'           -- raise your own ticket
        else d->>'raisedBy' = prev.data->>'raisedBy'                                       -- who raised it never changes
             and (cw_ticket_handler(u, prev.data->>'toDept')                               -- the department works on it
                  or ((prev.data->>'raisedBy' = u.user_id                                    -- the raiser follows up,
                       or (u.role in ('production_manager', 'gm_production') and cw_in_div(u.division, prev.division)))  -- or their HOD / Manager
                      and d->>'toDept' = prev.data->>'toDept'))
      end
    else false
  end
$$;

-- may this person see this row?
create or replace function cw_can_read(u app_users, r records) returns boolean
language sql stable as $$
  select case when r.collection in ('announcements', 'tickets', 'ppeRequests', 'ppeStock') then cw_social_read(u, r) else
  case (case when u.role = 'admin' then 'hr_admin' else u.role end)
    when 'hr_admin' then true
    when 'gm_production' then r.collection in ('requisitions','candidates','workers',
                                               -- GM dashboard: attendance and attrition across all divisions (no payroll)
                                               'attendanceRecords','punches','leaveRequests','resignations')
      -- a GM who is also a division's HOD (division set on the login) sees that division like its HOD does
      or (r.collection in ('exitClearances','regularizations') and cw_in_div(u.division, r.division))
    when 'contractor' then
      (r.collection in ('workers','pendingSubmissions','candidates','resignations','payrollRuns',
                        'wageRegisters','invoices','attendanceRecords','exitClearances',
                        'punches','leaveRequests',   -- contractor dashboard: their own workers present / on leave today
                        'contractorDocs')            -- Document Center: their own agreements, licence, Form II
        and cw_norm(r.contractor) = cw_norm(u.contractor))
      or (r.collection = 'requisitions' and exists (
            select 1 from jsonb_array_elements_text(coalesce(r.data->'assignedContractors', '[]'::jsonb)) a
            where cw_norm(a) = cw_norm(u.contractor)))
    when 'employee' then   -- a worker sees only their own records
      (r.collection = 'workers' and r.id = u.emp_id)
      or (r.collection in ('attendanceRecords','payrollRuns','leaveRequests','regularizations','profileChanges','resignations','punches')
          and coalesce(r.emp_id, r.data->>'empId') = u.emp_id)
    else -- production_manager, supervisor
      r.collection in ('workers','requisitions','resignations','exitClearances','attendanceRecords','candidates',
                       'leaveRequests','regularizations','punches')
        and cw_in_div(u.division, r.division)
  end end
$$;

-- may this person write this row? (old = row already stored, or null for a new one)
create or replace function cw_can_write(u app_users, p_coll text, prev records, new_contractor text, new_division text)
returns boolean language sql stable as $$
  select case (case when u.role = 'admin' then 'hr_admin' else u.role end)
    when 'hr_admin' then true
    when 'contractor' then
      cw_norm(new_contractor) = cw_norm(u.contractor)
      and (prev is null or prev.collection is null or cw_norm(prev.contractor) = cw_norm(u.contractor))
      and (
        p_coll in ('pendingSubmissions','candidates','resignations')
        or (p_coll = 'payrollRuns' and prev.collection is not null)      -- confirm / query existing rows only
        or (p_coll = 'invoices' and (prev is null or prev.collection is null))  -- raise new invoices only
        or p_coll = 'contractorDocs'                                            -- their own documents (HR validates; see cw_save)
      )
    when 'gm_production' then (p_coll = 'requisitions' and prev.collection is not null)
      -- GM who is also a division's HOD: the HOD's rights in that division
      or (p_coll in ('requisitions','exitClearances')
        and cw_in_div(u.division, new_division)
        and (prev is null or prev.collection is null or cw_in_div(u.division, prev.division)))
      or (p_coll = 'candidates' and prev.collection is not null and cw_in_div(u.division, prev.division))
    when 'employee' then false   -- handled in cw_save: own requests only
    else -- production_manager, supervisor
      (p_coll in ('requisitions','exitClearances')
        and cw_in_div(u.division, new_division)
        and (prev is null or prev.collection is null or cw_in_div(u.division, prev.division)))
      -- interview decision on a candidate HR forwarded to their division
      or (p_coll = 'candidates' and prev.collection is not null and cw_in_div(u.division, prev.division))
  end
$$;

-- ---------------------------------------------------------------------
-- cw_load: everything this person may see
-- ---------------------------------------------------------------------
create or replace function cw_load(p_user text, p_key text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare u app_users;
begin
  u := cw_auth(p_user, p_key);
  return jsonb_build_object(
    'me', cw_user_json(u),
    'records', coalesce((select jsonb_agg(jsonb_build_object('c', r.collection, 'id', r.id, 'd', r.data))
                         from records r where cw_can_read(u, r)), '[]'::jsonb),
    'settings', coalesce((select jsonb_object_agg(key, value) from app_settings where key not like 'admin_%'), '{}'::jsonb),  -- admin-only settings stay private
    'empty', not exists (select 1 from records)
  );
end $$;

-- ---------------------------------------------------------------------
-- cw_save: apply this person's changes, refusing anything their role can't do
--   p_upserts  [{c, id, d, contractor, division}]
--   p_deletes  [{c, id}]
--   p_settings {key: value}   (only the keys that changed)
--   p_audit    ["text", ...]
-- ---------------------------------------------------------------------
create or replace function cw_save(p_user text, p_key text, p_upserts jsonb, p_deletes jsonb, p_settings jsonb, p_audit jsonb)
returns jsonb language plpgsql volatile security definer set search_path = public as $$
declare
  u app_users; x jsonb; prev records; d jsonb; k text; v jsonb; cur jsonb;
  rejected jsonb := '[]'::jsonb; saved int := 0;
  w_con text; w_div text; n_con text; n_div text; n_emp text;
begin
  u := cw_auth(p_user, p_key);
  if coalesce(u.access, 'editor') = 'viewer' then   -- view-only logins can look but never change anything
    return jsonb_build_object('saved', 0, 'viewOnly', true, 'rejected', coalesce((select jsonb_agg(jsonb_build_object('c', e->>'c', 'id', e->>'id'))
      from jsonb_array_elements(coalesce(p_upserts, '[]'::jsonb) || coalesce(p_deletes, '[]'::jsonb)) e), '[]'::jsonb));
  end if;
  if u.role = 'employee' then   -- a worker's contractor and division always come from their own worker record
    select contractor, division into w_con, w_div from records where collection = 'workers' and id = u.emp_id;
  end if;

  for x in select * from jsonb_array_elements(coalesce(p_upserts, '[]'::jsonb)) loop
    prev := null;
    select * into prev from records where collection = x->>'c' and id = x->>'id';
    d := x->'d';
    n_con := x->>'contractor'; n_div := x->>'division'; n_emp := coalesce(x->>'empId', d->>'empId');

    if x->>'c' in ('announcements', 'tickets', 'ppeRequests', 'ppeStock') then
      -- open to every role, workers included, under their own rules (cw_social_write)
      if not coalesce(cw_social_write(u, x->>'c', prev, d), false) then
        rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
      end if;
      n_con := coalesce(w_con, u.contractor); n_div := coalesce(w_div, split_part(coalesce(u.division, ''), '|', 1)); n_emp := u.emp_id;
      if x->>'c' = 'ppeRequests' then   -- a PPE request belongs to the division and contractor it is for
        n_div := coalesce(nullif(d->>'division', ''), n_div); n_con := coalesce(nullif(d->>'contractor', ''), n_con); n_emp := nullif(d->>'empId', '');
      end if;
    elsif u.role = 'employee' then
      -- workers raise and cancel their own requests and record their own check-in / check-out
      if x->>'c' not in ('leaveRequests', 'regularizations', 'profileChanges', 'resignations', 'punches')
         or coalesce(d->>'empId', '') <> u.emp_id
         or (prev.collection is not null and coalesce(prev.emp_id, prev.data->>'empId') is distinct from u.emp_id)
         or (x->>'c' <> 'punches' and (
               coalesce(d->>'status', '') not in ('Pending Supervisor', 'Pending HR', 'Cancelled')
               or (x->>'c' <> 'profileChanges' and coalesce(d->>'status', '') = 'Pending HR')   -- only profile changes skip the supervisor
               or (prev.collection is not null and coalesce(prev.data->>'status', '') not in ('Pending Supervisor', 'Pending HR')))) then
        rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
      end if;
      n_con := w_con; n_div := w_div; n_emp := u.emp_id;
    elsif u.role in ('production_manager', 'supervisor', 'gm_production') and x->>'c' in ('leaveRequests', 'regularizations', 'resignations')
          and prev.collection is not null and coalesce(prev.data->>'status', '') = 'Pending Supervisor' then
      -- the supervisor's step: pass on to HR or reject, for their own division only; the request itself stays as raised
      if not cw_in_div(u.division, prev.division)
         or coalesce(d->>'status', '') not in ('Pending HR', 'Pending HR Review', 'Rejected by Supervisor') then
        rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
      end if;
      d := prev.data || jsonb_build_object('status', d->'status', 'supervisor', d->'supervisor', 'history', d->'history');
    elsif u.role in ('production_manager', 'supervisor', 'gm_production') and x->>'c' = 'resignations'
          and prev.collection is not null and coalesce(prev.data->>'status', '') = 'Pending Supervisor Clearance' then
      -- exit clearance by the division: accept and clear, or note what is pending; nothing else on the request changes
      if not cw_in_div(u.division, prev.division)
         or coalesce(d->>'status', '') not in ('Pending Supervisor Clearance', 'Production Cleared') then
        rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
      end if;
      d := prev.data || jsonb_build_object('status', d->'status', 'prodClearance', d->'prodClearance', 'history', d->'history');
    elsif not cw_can_write(u, x->>'c', prev, x->>'contractor', x->>'division') then
      rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
    end if;
    if u.role = 'contractor' and x->>'c' = 'payrollRuns' then
      -- contractors may only change the status (confirm / query) and their query note, never amounts
      if coalesce(d->>'status', '') not in ('Contractor Confirmed', 'Query Raised') then
        rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
      end if;
      d := prev.data || jsonb_build_object('status', d->'status', 'queryRemarks', coalesce(d->'queryRemarks', prev.data->'queryRemarks', 'null'::jsonb));
    end if;
    if x->>'c' = 'resignations' and u.role = 'contractor' then
      -- contractors raise a request (to HR), may edit it while HR has not looked at it, and close it after HR's exit clearance
      if prev.collection is null then
        if coalesce(d->>'status', '') <> 'Pending HR Review' then
          rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
        end if;
      elsif coalesce(prev.data->>'status', '') = 'HR Cleared' and coalesce(d->>'status', '') = 'Closed' then
        d := prev.data || jsonb_build_object('status', d->'status', 'contractorClosure', d->'contractorClosure', 'history', d->'history');
      elsif not (coalesce(prev.data->>'status', '') = 'Pending HR Review' and coalesce(d->>'status', '') = 'Pending HR Review') then
        rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
      end if;
    end if;
    if x->>'c' = 'contractorDocs' and u.role = 'contractor' then
      -- Document Center: a contractor uploads or renews their own document; it always goes back to HR for validation
      if coalesce(d->>'status', '') <> 'Pending HR Validation' or cw_norm(d->>'contractor') <> cw_norm(u.contractor) then
        rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
      end if;
    end if;
    if x->>'c' = 'candidates' and u.role = 'contractor' then
      if coalesce(prev.data->>'status', '') = 'Approved for Onboarding' and coalesce(d->>'status', '') in ('Joined', 'Not Joined') then
        -- the contractor confirms the actual joining (or that the candidate did not join); nothing else changes
        d := prev.data || jsonb_build_object('status', d->'status', 'joining', d->'joining', 'history', d->'history', 'stageAt', d->'stageAt');
      elsif coalesce(prev.data->>'status', '') = 'HR Interview Scheduled' and coalesce(d->>'status', '') = 'HR Interview Scheduled' then
        -- the contractor confirms the candidate will attend the scheduled interview
        d := prev.data || jsonb_build_object('contractorAck', d->'contractorAck', 'history', d->'history');
      -- otherwise contractors submit or resubmit; they can't move a candidate further along
      elsif coalesce(d->>'status', '') <> 'Submitted'
         or (prev.collection is not null and coalesce(prev.data->>'status', '') not in ('Submitted', 'Returned to Contractor')) then
        rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
      end if;
    end if;
    if x->>'c' = 'candidates' and u.role in ('production_manager', 'supervisor', 'gm_production') then
      -- each interview panel records only its own step; candidate details stay as submitted
      if coalesce(prev.data->>'status', '') = 'Supervisor Interview'
         and coalesce(d->>'status', '') in ('Supervisor Interview', 'PM Review', 'Rejected by Supervisor') then
        d := prev.data || jsonb_build_object('status', d->'status', 'supInterview', d->'supInterview', 'recommendedGrade', d->'recommendedGrade',
                                             'history', d->'history', 'stageAt', d->'stageAt');
      elsif u.role in ('production_manager', 'gm_production') and coalesce(prev.data->>'status', '') = 'PM Review'
         and coalesce(d->>'status', '') in ('PM Review', 'HR Officer Verification', 'Rejected by PM') then
        d := prev.data || jsonb_build_object('status', d->'status', 'pmReview', d->'pmReview', 'recommendedGrade', d->'recommendedGrade',
                                             'history', d->'history', 'stageAt', d->'stageAt');
      elsif coalesce(prev.data->>'status', '') in ('Forwarded to Production', 'On Hold')   -- candidates from before the staged interviews
         and coalesce(d->>'status', '') in ('Selected', 'Rejected by Production', 'On Hold') then
        d := prev.data || jsonb_build_object('status', d->'status', 'interview', d->'interview',
                                             'decisionBy', d->'decisionBy', 'history', d->'history');
      else
        rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
      end if;
    end if;
    if x->>'c' = 'candidates' and u.role in ('hr_admin', 'admin')
       and coalesce(d->>'status', '') in ('Approved for Onboarding', 'Rejected by HR Head', 'Returned for Clarification')
       and coalesce(prev.data->>'status', '') is distinct from d->>'status' and not cw_is_hr_head(u) then
      -- only the HR Head gives the final approval and fixes the salary
      rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
    end if;
    insert into records (collection, id, data, contractor, division, emp_id, updated_at, updated_by)
    values (x->>'c', x->>'id', d, n_con, n_div, n_emp, now(), u.user_id)
    on conflict (collection, id) do update
      set data = excluded.data,
          contractor = case when u.role in ('hr_admin', 'admin') then excluded.contractor else records.contractor end,
          division   = case when u.role in ('hr_admin', 'admin') then excluded.division   else records.division end,
          emp_id     = case when u.role in ('hr_admin', 'admin') then coalesce(excluded.emp_id, records.emp_id) else records.emp_id end,
          updated_at = now(), updated_by = u.user_id;
    saved := saved + 1;
  end loop;

  for x in select * from jsonb_array_elements(coalesce(p_deletes, '[]'::jsonb)) loop
    if u.role in ('hr_admin', 'admin') then
      delete from records where collection = x->>'c' and id = x->>'id';
    else
      rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id'));
    end if;
  end loop;

  for k, v in select * from jsonb_each(coalesce(p_settings, '{}'::jsonb)) loop
    select value into cur from app_settings where key = k;
    if k in ('nextReqId','nextCandId','nextResId','nextClearId','nextInvoiceNo') then
      -- ID counters only ever go up, so two people can't reuse a number
      v := to_jsonb(greatest(coalesce((cur#>>'{}')::numeric, 0), coalesce((v#>>'{}')::numeric, 0)));
    elsif k = 'empIdCounters' then
      v := coalesce((select jsonb_object_agg(key, greatest(coalesce((cur->>key)::numeric, 0), coalesce((v->>key)::numeric, 0)))
                     from (select jsonb_object_keys(coalesce(cur, '{}'::jsonb) || v) as key) s), '{}'::jsonb);
    elsif k = 'knownContractors' then
      v := (select coalesce(jsonb_agg(distinct e), '[]'::jsonb)
            from jsonb_array_elements(coalesce(cur, '[]'::jsonb) || coalesce(v, '[]'::jsonb)) e);
    elsif k like 'admin_%' then
      continue; -- admin-only settings are changed in the Admin Portal
    elsif u.role not in ('hr_admin', 'admin') then
      continue; -- pay rates, grade budgets and attendance verification are HR-only
    end if;
    insert into app_settings (key, value, updated_at, updated_by) values (k, v, now(), u.user_id)
    on conflict (key) do update set value = excluded.value, updated_at = now(), updated_by = u.user_id;
  end loop;

  insert into audit_log (user_id, text)
  select u.user_id, t from jsonb_array_elements_text(coalesce(p_audit, '[]'::jsonb)) t;

  return jsonb_build_object('saved', saved, 'rejected', rejected);
end $$;

-- ---------------------------------------------------------------------
-- Candidate documents (Aadhaar card, CV, education certificates).
-- Kept apart from the records so pages load fast; fetched one at a time when opened.
-- Who can open a file: HR, the contractor who uploaded it, and the Production
-- Manager / Supervisor of the division it is for.
-- ---------------------------------------------------------------------
create table if not exists documents (
  id          text primary key,
  candidate_id text,
  kind        text not null,              -- aadhaar | cv | education | other
  name        text not null,
  mime        text not null,
  size        int  not null,
  data        text not null,              -- base64
  contractor  text,
  division    text,
  uploaded_by text,
  uploaded_at timestamptz not null default now()
);
alter table documents enable row level security;
revoke all on documents from anon, authenticated;

create or replace function cw_doc_put(p_user text, p_key text, p_id text, p_candidate text, p_kind text,
                                      p_name text, p_mime text, p_data text, p_contractor text, p_division text)
returns jsonb language plpgsql volatile security definer set search_path = public as $$
declare u app_users; prev documents;
begin
  u := cw_auth(p_user, p_key);
  if u.role not in ('hr_admin', 'admin', 'contractor') or coalesce(u.access, 'editor') = 'viewer' then raise exception 'not allowed' using errcode = '42501'; end if;
  if p_id !~ '^[A-Za-z0-9_-]{8,64}$' then raise exception 'bad id' using errcode = '22023'; end if;
  if length(coalesce(p_data, '')) > 4000000 then raise exception 'file too large' using errcode = '54000'; end if;
  if p_kind not in ('aadhaar', 'cv', 'education', 'other') then p_kind := 'other'; end if;
  select * into prev from documents where id = p_id;
  if u.role = 'contractor' then
    p_contractor := u.contractor;                       -- a contractor can only file under their own name
    if prev.id is not null and cw_norm(prev.contractor) <> cw_norm(u.contractor) then
      raise exception 'not allowed' using errcode = '42501';
    end if;
  end if;
  insert into documents (id, candidate_id, kind, name, mime, size, data, contractor, division, uploaded_by)
  values (p_id, p_candidate, p_kind, left(p_name, 200), left(p_mime, 100), (length(p_data) * 3 / 4), p_data,
          p_contractor, p_division, u.user_id)
  on conflict (id) do update set candidate_id = excluded.candidate_id, kind = excluded.kind, name = excluded.name,
    mime = excluded.mime, size = excluded.size, data = excluded.data, division = excluded.division,
    uploaded_by = excluded.uploaded_by, uploaded_at = now();
  return jsonb_build_object('id', p_id, 'size', length(p_data) * 3 / 4);
end $$;

create or replace function cw_doc_get(p_user text, p_key text, p_id text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare u app_users; dd documents;
begin
  u := cw_auth(p_user, p_key);
  select * into dd from documents where id = p_id;
  if dd.id is null then raise exception 'not found' using errcode = 'P0002'; end if;
  if not (u.role in ('hr_admin', 'admin')
          or (u.role = 'contractor' and cw_norm(dd.contractor) = cw_norm(u.contractor))
          or (u.role in ('production_manager', 'supervisor', 'gm_production') and cw_in_div(u.division, dd.division))) then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  return jsonb_build_object('id', dd.id, 'name', dd.name, 'mime', dd.mime, 'kind', dd.kind, 'data', dd.data);
end $$;

revoke all on function cw_doc_put(text, text, text, text, text, text, text, text, text, text), cw_doc_get(text, text, text) from public;
grant execute on function cw_doc_put(text, text, text, text, text, text, text, text, text, text) to anon, authenticated;
grant execute on function cw_doc_get(text, text, text) to anon, authenticated;

-- ---------------------------------------------------------------------
-- Admin Portal (role 'admin' only)
-- ---------------------------------------------------------------------
create or replace function cw_admin(p_user text, p_key text) returns app_users
language plpgsql stable security definer set search_path = public as $$
declare u app_users;
begin
  u := cw_auth(p_user, p_key);
  if u.role <> 'admin' then raise exception 'admins only' using errcode = '42501'; end if;
  return u;
end $$;

-- everything the dashboard and lists need, in one call
create or replace function cw_admin_overview(p_user text, p_key text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare u app_users;
begin
  u := cw_admin(p_user, p_key);
  return jsonb_build_object(
    'users', coalesce((select jsonb_agg(jsonb_build_object('user', user_id, 'role', role, 'contractor', contractor, 'division', division,
                          'name', name, 'active', active, 'created_at', created_at, 'last_login', last_login, 'has_password', fp is not null,
                          'empId', emp_id, 'mustChange', must_change, 'email', email, 'access', coalesce(access, 'editor'))
                        order by role, user_id) from app_users), '[]'::jsonb),
    'logins', coalesce((select jsonb_agg(x order by x.at desc) from
                        (select at, user_id, success, ip, user_agent, note from login_events order by at desc limit 500) x), '[]'::jsonb),
    'audit', coalesce((select jsonb_agg(x order by x.id desc) from
                       (select id, at, user_id, text from audit_log order by id desc limit 500) x), '[]'::jsonb),
    'events', coalesce((select jsonb_agg(x order by x.at) from
                        (select at, user_id, kind, meta from app_events where at > now() - interval '90 days' order by at desc limit 5000) x), '[]'::jsonb),
    'candidates', coalesce((select jsonb_agg(jsonb_build_object('id', id, 'status', data->>'status', 'workerEmpId', data->>'workerEmpId',
                              'contractor', contractor, 'division', division, 'submittedOn', data->>'submittedOn',
                              'autoFilled', data->'autoFilled', 'history', data->'history')) from records where collection = 'candidates'), '[]'::jsonb),
    'workers', coalesce((select jsonb_agg(jsonb_build_object('empId', id, 'status', data->>'status', 'candidateId', data->>'candidateId',
                           'name', data->>'name', 'division', division, 'contractor', contractor))
                         from records where collection = 'workers'), '[]'::jsonb),
    'counts', coalesce((select jsonb_object_agg(collection, n) from (select collection, count(*) n from records group by collection) c), '{}'::jsonb),
    'recent_changes', coalesce((select jsonb_agg(x order by x.updated_at desc) from
                                (select collection, id, updated_at, updated_by from records order by updated_at desc limit 200) x), '[]'::jsonb),
    'contractors', (select value from app_settings where key = 'contractors'),
    'documents', (select count(*) from documents),
    'sheet', (select value from app_settings where key = 'admin_sheet')
  );
end $$;

-- the Google Sheet that events are copied to: {url, token, enabled}
create or replace function cw_admin_set_sheet(p_user text, p_key text, p_url text, p_token text, p_enabled boolean) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare u app_users;
begin
  u := cw_admin(p_user, p_key);
  if coalesce(p_url, '') <> '' and p_url !~ '^https://script\.google\.com/macros/s/[A-Za-z0-9_-]+/exec$' then
    raise exception 'Paste the web app link from Apps Script: it starts with https://script.google.com/macros/s/ and ends with /exec' using errcode = '22023';
  end if;
  if coalesce(p_url, '') <> '' and coalesce(p_token, '') !~ '^[A-Za-z0-9]{16,64}$' then raise exception 'bad secret code' using errcode = '22023'; end if;
  insert into app_settings (key, value, updated_at, updated_by)
  values ('admin_sheet', jsonb_build_object('url', coalesce(p_url, ''), 'token', coalesce(p_token, ''), 'enabled', coalesce(p_enabled, true)), now(), u.user_id)
  on conflict (key) do update set value = excluded.value, updated_at = now(), updated_by = u.user_id;
  insert into audit_log (user_id, text) values (u.user_id, case when coalesce(p_url, '') = '' then 'Admin disconnected the Google Sheet' else 'Admin connected the Google Sheet for events' end);
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- Events → Google Sheet. The database itself posts each new event to the admin's Apps Script
-- web app (Supabase's pg_net), so the sheet link and secret never leave the database.
-- ---------------------------------------------------------------------
create extension if not exists pg_net;

create or replace function cw_sheet_send(p_payload jsonb) returns void
language plpgsql volatile security definer set search_path = public as $$
declare s jsonb;
begin
  select value into s from app_settings where key = 'admin_sheet';
  if s is null or coalesce(s->>'url', '') = '' or not coalesce((s->>'enabled')::boolean, true) then return; end if;
  perform net.http_post(url := s->>'url', body := jsonb_build_object('token', s->>'token') || p_payload,
                        headers := '{"Content-Type": "application/json"}'::jsonb, timeout_milliseconds := 8000);
exception when others then
  null;  -- a sheet problem must never stop people signing in or working
end $$;

create or replace function cw_login_row(e login_events) returns jsonb language sql stable security definer set search_path = public as $$
  select jsonb_build_object('at', e.at, 'user', e.user_id, 'name', a.name, 'role', a.role,
    'event', case when e.success then 'Signed in' else 'Sign-in failed' end, 'detail', coalesce(e.note, ''),
    'seconds', null, 'device', left(coalesce(e.user_agent, ''), 140), 'ip', coalesce(e.ip, ''))
  from (select 1) one left join app_users a on a.user_id = e.user_id
$$;
create or replace function cw_event_row(e app_events) returns jsonb language sql stable security definer set search_path = public as $$
  select jsonb_build_object('at', e.at, 'user', e.user_id, 'name', a.name, 'role', a.role,
    'event', case e.kind when 'open' then 'Opened the app' when 'aha' then 'Aha moment' when 'docs_read' then 'Documents read' else e.kind end,
    'detail', case e.kind when 'aha' then coalesce(e.meta->>'action', '')
                          when 'docs_read' then coalesce(e.meta->>'docs', '0') || ' documents, ' || coalesce(e.meta->>'fields', '0') || ' fields filled' else '' end,
    'seconds', case when e.kind = 'aha' then e.meta->'secondsFromOpen' end, 'device', '', 'ip', '')
  from (select 1) one left join app_users a on a.user_id = e.user_id
$$;

create or replace function cw_login_to_sheet() returns trigger language plpgsql security definer set search_path = public as $$
begin perform cw_sheet_send(jsonb_build_object('rows', jsonb_build_array(cw_login_row(new)))); return new; end $$;
create or replace function cw_event_to_sheet() returns trigger language plpgsql security definer set search_path = public as $$
begin perform cw_sheet_send(jsonb_build_object('rows', jsonb_build_array(cw_event_row(new)))); return new; end $$;

drop trigger if exists login_events_to_sheet on login_events;
create trigger login_events_to_sheet after insert on login_events for each row execute function cw_login_to_sheet();
drop trigger if exists app_events_to_sheet on app_events;
create trigger app_events_to_sheet after insert on app_events for each row execute function cw_event_to_sheet();

-- Admin Portal buttons: send a test row, copy all past events, or write the six numbers to a Summary tab
create or replace function cw_admin_sheet_send(p_user text, p_key text, p_what text, p_summary jsonb) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare u app_users; s jsonb; batch jsonb; n int := 0;
begin
  u := cw_admin(p_user, p_key);
  select value into s from app_settings where key = 'admin_sheet';
  if s is null or coalesce(s->>'url', '') = '' then raise exception 'Connect the Google Sheet first' using errcode = '22023'; end if;
  if p_what = 'test' then
    perform cw_sheet_send(jsonb_build_object('rows', jsonb_build_array(jsonb_build_object('at', now(), 'user', u.user_id, 'name', u.name, 'role', u.role,
      'event', 'Test row', 'detail', 'Sent from the Admin Portal — the sheet is connected', 'seconds', null, 'device', '', 'ip', ''))));
    n := 1;
  elsif p_what = 'backfill' then
    for batch in
      select jsonb_agg(r order by r->>'at') from (
        select cw_login_row(l) r, row_number() over (order by l.at) rn from login_events l
        union all
        select cw_event_row(e) r, 1000000 + row_number() over (order by e.at) rn from app_events e
      ) x group by (rn % 1000000) / 200, rn >= 1000000
    loop
      perform cw_sheet_send(jsonb_build_object('rows', batch));
      n := n + jsonb_array_length(batch);
    end loop;
  elsif p_what = 'summary' then
    perform cw_sheet_send(jsonb_build_object('summary', coalesce(p_summary, '{}'::jsonb) || jsonb_build_object('at', now())));
    n := 1;
  else
    raise exception 'unknown action' using errcode = '22023';
  end if;
  insert into audit_log (user_id, text) values (u.user_id, 'Admin sent ' || n || ' row(s) to the Google Sheet (' || p_what || ')');
  return jsonb_build_object('ok', true, 'rows', n);
end $$;

-- ---------------------------------------------------------------------
-- EMAIL NOTIFICATIONS. When a request moves to a new step, the database works out who has to act or
-- be told, and posts the emails to the admin's Apps Script (same link as the Google Sheet), which sends
-- them from the admin's Google account. Each login's email is set in the Admin Portal. The person who
-- made the change is not emailed about it. A mail problem never stops anyone saving.
-- ---------------------------------------------------------------------
alter table app_users add column if not exists email text;

create or replace function cw_html(t text) returns text language sql immutable as $$
  select replace(replace(replace(coalesce(t, ''), '&', '&amp;'), '<', '&lt;'), '>', '&gt;') $$;

-- emails of active logins: by role (scoped to the division / contractor where that applies) or by user id
create or replace function cw_mail_to(p_roles text[], p_div text, p_con text, p_users text[]) returns text[]
language sql stable security definer set search_path = public as $$
  select coalesce(array_agg(distinct lower(trim(a.email))), '{}') from app_users a
  where a.active and coalesce(a.email, '') like '%_@_%.__%' and (
    (p_users is not null and a.user_id = any(p_users))
    or (a.role = any(coalesce(p_roles, '{}')) and (
          a.role in ('hr_admin', 'admin', 'gm_production', 'store')
          or (a.role in ('production_manager', 'supervisor') and cw_in_div(a.division, p_div))
          or (a.role = 'contractor' and cw_norm(a.contractor) = cw_norm(p_con))))
    -- a GM who is also a division's HOD hears what that division's managers hear
    or (a.role = 'gm_production' and 'production_manager' = any(coalesce(p_roles, '{}')) and cw_in_div(a.division, p_div)))
$$;
create or replace function cw_setting_users(p_key text, p_path text) returns text[] language sql stable security definer set search_path = public as $$
  select coalesce(array_agg(x), '{}') from app_settings s, jsonb_array_elements_text(
    case when p_path is null then (case when jsonb_typeof(s.value) = 'array' then s.value else '[]'::jsonb end) else coalesce(s.value->p_path, '[]'::jsonb) end) x
  where s.key = p_key $$;
create or replace function cw_ticket_users(p_dept text) returns text[] language sql stable security definer set search_path = public as $$
  select coalesce(array_agg(h), '{}') from app_settings s, jsonb_array_elements(case when jsonb_typeof(s.value) = 'array' then s.value else '[]'::jsonb end) d, jsonb_array_elements_text(coalesce(d->'handlers', '[]'::jsonb)) h
  where s.key = 'ticketDepartments' and d->>'name' = p_dept $$;
create or replace function cw_worker_email(p_emp text) returns text[] language sql stable security definer set search_path = public as $$
  select coalesce(array_agg(distinct lower(trim(e))) filter (where e like '%_@_%.__%'), '{}') from (
    select data->>'email' e from records where collection = 'workers' and id = p_emp
    union all select email from app_users where emp_id = p_emp and active) x $$;
create or replace function cw_mail_enabled() returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select coalesce((value->>'mail')::boolean, true) and coalesce(value->>'url', '') <> '' from app_settings where key = 'admin_sheet'), false) $$;

-- one message per recipient, posted in one call to the Apps Script
create or replace function cw_mail_send(p_msgs jsonb, p_skip text) returns void
language plpgsql volatile security definer set search_path = public as $$
declare s jsonb; out jsonb := '[]'::jsonb; m jsonb; t text;
begin
  if not cw_mail_enabled() or p_msgs is null or jsonb_array_length(p_msgs) = 0 then return; end if;
  select value into s from app_settings where key = 'admin_sheet';
  for m in select * from jsonb_array_elements(p_msgs) loop
    for t in select distinct lower(x) from jsonb_array_elements_text(coalesce(m->'to', '[]'::jsonb)) x loop
      if t is distinct from lower(coalesce(p_skip, '')) then out := out || jsonb_build_array(jsonb_build_object('to', t, 'subject', m->>'subject', 'html', m->>'html')); end if;
    end loop;
  end loop;
  if jsonb_array_length(out) = 0 then return; end if;
  perform net.http_post(url := s->>'url', body := jsonb_build_object('token', s->>'token', 'mail', out),
                        headers := '{"Content-Type": "application/json"}'::jsonb, timeout_milliseconds := 8000);
exception when others then null;
end $$;

create or replace function cw_mail_msg(p_to text[], p_title text, p_line text, p_rows jsonb) returns jsonb language sql immutable as $$
  select case when coalesce(array_length(p_to, 1), 0) = 0 then null else jsonb_build_object('to', to_jsonb(p_to), 'subject', 'Aristo HR · ' || p_title,
    'html', '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#1a1a1a;max-width:560px">'
      || '<div style="border-bottom:3px solid #b8945a;padding-bottom:6px;margin-bottom:12px;font-size:16px"><b>Aristo Contract Manpower</b></div>'
      || '<p style="font-size:15px">' || cw_html(p_line) || '</p>'
      || coalesce((select '<table style="border-collapse:collapse;font-size:13px;margin:8px 0">' || string_agg('<tr><td style="color:#777;padding:3px 12px 3px 0">' || cw_html(k) || '</td><td style="padding:3px 0"><b>' || cw_html(v) || '</b></td></tr>', '' order by ord) || '</table>'
                   from jsonb_each_text(coalesce(p_rows, '{}'::jsonb)) with ordinality as e(k, v, ord) where coalesce(v, '') <> ''), '')
      || '<p style="margin-top:16px"><a href="https://aristo-contract-manpower.vercel.app" style="background:#b8945a;color:#000;padding:8px 14px;text-decoration:none;font-weight:bold">Open the app</a></p>'
      || '<p style="color:#888;font-size:11px;margin-top:18px">Automatic message from the Aristo HR app — please do not reply.</p></div>') end $$;

-- who hears about which step
create or replace function cw_notify() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  d jsonb := new.data; st text := new.data->>'status'; ost text; c text := new.collection;
  dv text := coalesce(new.division, new.data->>'division'); cn text := coalesce(new.contractor, new.data->>'contractor');
  nm text := coalesce(new.data->>'name', ''); eid text := coalesce(new.data->>'empId', new.data->>'workerEmpId', '');
  hr text[]; actor text;
  msgs jsonb := '[]'::jsonb; info jsonb;
  -- helper: append a message if it has recipients
begin
  if tg_op = 'UPDATE' then ost := old.data->>'status'; end if;
  if st is null or st is not distinct from ost then return new; end if;
  hr := cw_mail_to(array['hr_admin'], null, null, null);
  select lower(email) into actor from app_users where user_id = new.updated_by;
  info := jsonb_strip_nulls(jsonb_build_object('Name', nullif(nm, ''), 'Employee ID', nullif(eid, ''), 'Division', dv, 'Contractor', cn, 'Status', st));

  if c = 'requisitions' then
    info := jsonb_strip_nulls(jsonb_build_object('Requisition', d->>'id', 'Position', d->>'position', 'Workers', d->>'count', 'Type', d->>'type', 'Division', dv, 'Status', st));
    if st = 'Pending PM Approval' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['production_manager'], dv, null, null), 'Requisition ' || (d->>'id') || ' needs your approval', 'A manpower requisition from your division is waiting for your approval.', info));
    elsif st = 'Pending GM Approval' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['gm_production'], null, null, null), 'Requisition ' || (d->>'id') || ' needs GM approval', 'A new manpower requisition is waiting for your approval.', info));
    elsif st = 'Pending HR Approval' then msgs := msgs || jsonb_build_array(cw_mail_msg(hr, 'Requisition ' || (d->>'id') || ' ready for HR', 'A requisition has been approved by Production and is waiting for HR to assign contractors.', info));
    elsif st = 'Approved' then
      msgs := msgs || jsonb_build_array(cw_mail_msg((select coalesce(array_agg(distinct e), '{}') from jsonb_array_elements_text(coalesce(d->'assignedContractors', '[]'::jsonb)) ac, unnest(cw_mail_to(array['contractor'], null, ac, null)) e),
                'New requirement ' || (d->>'id') || ' assigned to you', 'A manpower requirement has been assigned to you. Please submit suitable candidates within 7 days.', info || jsonb_strip_nulls(jsonb_build_object('Deadline', d->>'deadline'))));
      msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['production_manager', 'supervisor'], dv, null, null), 'Requisition ' || (d->>'id') || ' approved', 'Your requisition has been approved and assigned to contractors.', info));
    elsif st = 'Rejected' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['production_manager', 'supervisor'], dv, null, null), 'Requisition ' || (d->>'id') || ' rejected', 'Your requisition was not approved.', info));
    end if;

  elsif c = 'candidates' then
    info := jsonb_strip_nulls(jsonb_build_object('Candidate', nullif(nm, ''), 'Position', d->>'position', 'Requisition', d->>'requisitionId', 'Division', dv, 'Contractor', cn, 'Status', st));
    if st = 'Submitted' then msgs := msgs || jsonb_build_array(cw_mail_msg(hr, 'New candidate: ' || nm, 'A contractor has submitted a candidate for screening.', info));
    elsif st = 'Returned to Contractor' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['contractor'], null, cn, null), 'Candidate returned: ' || nm, 'HR sent the candidate back for corrections: ' || coalesce(d->>'hrRemarks', ''), info));
    elsif st = 'HR Interview Scheduled' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['contractor'], null, cn, null), 'HR interview: ' || nm, 'HR has scheduled an interview. Please make sure the candidate attends.', info || jsonb_strip_nulls(jsonb_build_object('Interview', concat_ws(' ', d->'hrInterview'->>'scheduled', d->'hrInterview'->>'time')))));
    elsif st = 'Supervisor Interview' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['supervisor'], dv, null, null), 'Interview needed: ' || nm, 'HR has selected this candidate. Please hold the department interview within one working day.', info));
    elsif st = 'PM Review' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['production_manager'], dv, null, null), 'Approval needed: ' || nm, 'The Supervisor has selected this candidate. Please verify and approve the grade.', info || jsonb_strip_nulls(jsonb_build_object('Recommended grade', d->>'recommendedGrade'))));
    elsif st in ('HR Officer Verification', 'Returned for Clarification') then msgs := msgs || jsonb_build_array(cw_mail_msg(hr, 'Verify candidate: ' || nm, case when st = 'Returned for Clarification' then 'The HR Head asked for clarification.' else 'Production has approved this candidate. Please verify and forward to the HR Head.' end, info));
    elsif st = 'HR Head Approval' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(null, null, null, cw_setting_users('admin_hr_heads', null)), 'HR Head approval: ' || nm, 'A candidate is waiting for your final approval and salary fixing.', info));
    elsif st = 'Approved for Onboarding' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['contractor'], null, cn, null) || hr, 'Approved: ' || nm, 'The candidate is approved. Please confirm the actual joining date in the app.', info));
    elsif st = 'Joined' then msgs := msgs || jsonb_build_array(cw_mail_msg(hr || cw_mail_to(array['supervisor'], dv, null, null), 'Joined: ' || nm, 'The contractor has confirmed the employee joined.', info || jsonb_strip_nulls(jsonb_build_object('Joined on', d->'joining'->>'date'))));
    elsif st like 'Rejected%' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['contractor'], null, cn, null), 'Candidate not selected: ' || nm, st || '.', info));
    end if;

  elsif c = 'resignations' then
    info := info || jsonb_strip_nulls(jsonb_build_object('Category', coalesce(d->>'category', d->>'type'), 'Last working day', d->>'lwd'));
    if st = 'Pending Supervisor' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['supervisor'], dv, null, null), 'Resignation: ' || nm, 'An employee has submitted a resignation for your review.', info));
    elsif st = 'Pending HR Review' then msgs := msgs || jsonb_build_array(cw_mail_msg(hr, 'Separation request: ' || nm, 'A separation request is waiting for HR confirmation.', info));
    elsif st = 'Pending Supervisor Clearance' then
      msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['supervisor'], dv, null, null), 'Exit clearance needed: ' || nm, 'HR has confirmed the resignation. Please accept it and complete the exit clearance.', info));
      msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['production_manager'], dv, null, null), 'For information — exit clearance: ' || nm, 'HR has confirmed this resignation; the Supervisor is completing the exit clearance.', info));
    elsif st = 'Production Cleared' then msgs := msgs || jsonb_build_array(cw_mail_msg(hr || cw_mail_to(array['contractor'], null, cn, null), 'Production formalities complete: ' || nm, 'The Supervisor has accepted the resignation and confirmed the production exit clearance. HR exit clearance is next.', info));
    elsif st = 'HR Cleared' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['contractor'], null, cn, null), 'Please confirm and close: ' || nm, 'HR has completed the exit clearance. Please confirm in the app to close the resignation.', info || jsonb_strip_nulls(jsonb_build_object('Relieving date', d->'hrClearance'->>'relievingDate'))));
    elsif st = 'Closed' then msgs := msgs || jsonb_build_array(cw_mail_msg(hr, 'Resignation closed: ' || nm, 'The contractor has confirmed. The resignation is closed.', info));
    elsif st like 'Rejected%' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['contractor'], null, cn, null) || cw_worker_email(eid), 'Separation request not accepted: ' || nm, st || coalesce(': ' || nullif(d->>'hrRemarks', ''), '') || '.', info));
    end if;

  elsif c in ('leaveRequests', 'regularizations', 'profileChanges') then
    info := info || jsonb_strip_nulls(jsonb_build_object('Type', coalesce(d->>'type', d->>'fieldLabel'), 'From', d->>'from', 'To', d->>'to', 'Date', d->>'date'));
    if st = 'Pending Supervisor' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['supervisor'], dv, null, null), 'Approval needed: ' || nm, 'A request is waiting for your approval.', info));
    elsif st = 'Pending HR' then msgs := msgs || jsonb_build_array(cw_mail_msg(hr, 'Approval needed: ' || nm, 'A request is waiting for HR approval.', info));
    elsif st = 'Approved' or st like 'Rejected%' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_worker_email(eid), 'Your request: ' || st, 'Your request has been ' || lower(st) || '.', info));
    end if;

  elsif c = 'pendingSubmissions' then
    if st = 'Pending HR Verification' then msgs := msgs || jsonb_build_array(cw_mail_msg(hr, 'Verify new employee: ' || nm, 'A contractor has registered a new employee for HR verification.', info));
    elsif st in ('Returned for Correction', 'Rejected') then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['contractor'], null, cn, null), 'Registration ' || lower(st) || ': ' || nm, coalesce(nullif(d->>'hrRemarks', ''), st), info));
    end if;

  elsif c = 'tickets' then
    info := jsonb_strip_nulls(jsonb_build_object('Ticket', d->>'no', 'Subject', d->>'subject', 'Department', d->>'toDept', 'Raised by', d->>'raisedByName', 'Due', d->>'dueDate', 'Status', st));
    if st in ('Open', 'Reopened') then msgs := msgs || jsonb_build_array(cw_mail_msg(case when coalesce(array_length(cw_ticket_users(d->>'toDept'), 1), 0) = 0 then hr else cw_mail_to(null, null, null, cw_ticket_users(d->>'toDept')) end, 'Ticket ' || (d->>'no') || ': ' || coalesce(d->>'subject', ''), case when st = 'Reopened' then 'The ticket has been reopened.' else 'A new ticket has been raised to your department.' end, info));
    else msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(null, null, null, array[d->>'raisedBy']), 'Ticket ' || (d->>'no') || ' — ' || st, case when st = 'Resolved' then 'Your ticket has been resolved. Please confirm and close it, or reopen it.' else 'Your ticket has been updated.' end, info));
    end if;

  elsif c = 'ppeRequests' then
    info := jsonb_strip_nulls(jsonb_build_object('For', coalesce(nullif(nm, ''), d->>'requisitionId'), 'Employee ID', nullif(eid, ''), 'Position', d->>'position', 'Division', dv, 'Status', st));
    if st = 'Pending Admin' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(null, null, null, cw_setting_users('ppeDesk', 'admin')), 'PPE to confirm: ' || coalesce(nullif(nm, ''), d->>'position', ''), 'Please confirm the PPE requirement.', info));
    elsif st = 'Pending Store' then msgs := msgs || jsonb_build_array(cw_mail_msg(cw_mail_to(array['store'], null, null, cw_setting_users('ppeDesk', 'store')), 'PPE to issue: ' || coalesce(nullif(nm, ''), d->>'position', ''), 'Admin has confirmed the PPE. Please issue it.', info));
    end if;
  end if;

  select coalesce(jsonb_agg(m), '[]'::jsonb) into msgs from jsonb_array_elements(msgs) m where m <> 'null'::jsonb;
  perform cw_mail_send(msgs, actor);
  return new;
exception when others then return new;   -- email must never block a save
end $$;

drop trigger if exists records_notify on records;
create trigger records_notify after insert or update on records for each row execute function cw_notify();

-- Admin Portal: Editor (can change things) or Viewer (can only look) for a login
create or replace function cw_admin_set_access(p_user text, p_key text, p_target text, p_access text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare u app_users; t text := lower(trim(coalesce(p_target, '')));
begin
  u := cw_admin(p_user, p_key);
  if p_access not in ('editor', 'viewer') then raise exception 'Choose Editor or Viewer' using errcode = '22023'; end if;
  if t = u.user_id and p_access = 'viewer' then raise exception 'You cannot make your own admin login view-only' using errcode = '22023'; end if;
  update app_users set access = p_access where user_id = t;
  if not found then raise exception 'no such login' using errcode = 'P0002'; end if;
  insert into audit_log (user_id, text) values (u.user_id, 'Admin set ' || t || ' to ' || case when p_access = 'viewer' then 'Viewer (view only)' else 'Editor' end);
  return jsonb_build_object('ok', true);
end $$;

-- Admin Portal: set a login's email, turn emails on / off, send a test email
create or replace function cw_admin_set_email(p_user text, p_key text, p_target text, p_email text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare u app_users; e text := lower(trim(coalesce(p_email, '')));
begin
  u := cw_admin(p_user, p_key);
  if e <> '' and e !~ '^[^@\s]+@[^@\s]+\.[a-z]{2,}$' then raise exception 'That email address does not look right' using errcode = '22023'; end if;
  update app_users set email = nullif(e, '') where user_id = lower(trim(p_target));
  if not found then raise exception 'no such login' using errcode = 'P0002'; end if;
  insert into audit_log (user_id, text) values (u.user_id, 'Admin set the email for ' || lower(trim(p_target)));
  return jsonb_build_object('ok', true);
end $$;
create or replace function cw_admin_mail(p_user text, p_key text, p_what text, p_to text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare u app_users; s jsonb;
begin
  u := cw_admin(p_user, p_key);
  select value into s from app_settings where key = 'admin_sheet';
  if s is null or coalesce(s->>'url', '') = '' then raise exception 'Connect the Google Sheet first' using errcode = '22023'; end if;
  if p_what in ('on', 'off') then
    update app_settings set value = value || jsonb_build_object('mail', p_what = 'on'), updated_at = now(), updated_by = u.user_id where key = 'admin_sheet';
    insert into audit_log (user_id, text) values (u.user_id, 'Admin turned email notifications ' || p_what);
  elsif p_what = 'test' then
    if coalesce(p_to, '') !~ '^[^@\s]+@[^@\s]+\.[a-z]{2,}$' then raise exception 'Enter an email address for the test' using errcode = '22023'; end if;
    perform net.http_post(url := s->>'url', body := jsonb_build_object('token', s->>'token', 'mail', jsonb_build_array(
      cw_mail_msg(array[lower(p_to)], 'Test email', 'Email notifications from the HR app are working.', jsonb_build_object('Sent by', u.user_id)) - 'to' || jsonb_build_object('to', lower(p_to)))),
      headers := '{"Content-Type": "application/json"}'::jsonb, timeout_milliseconds := 8000);
  else raise exception 'unknown action' using errcode = '22023';
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- add or change a login. p_fp / p_salt are null to keep the current password.
create or replace function cw_admin_save_user(p_user text, p_key text, p_target text, p_role text, p_contractor text,
                                              p_division text, p_name text, p_active boolean, p_fp text, p_salt text)
returns jsonb language plpgsql volatile security definer set search_path = public as $$
declare u app_users; t text := lower(trim(coalesce(p_target, ''))); existing app_users;
begin
  u := cw_admin(p_user, p_key);
  if t !~ '^[a-z0-9][a-z0-9._-]{1,39}$' then raise exception 'User ID: 2-40 letters, numbers, dot, dash or underscore' using errcode = '22023'; end if;
  if p_role not in ('admin','hr_admin','gm_production','production_manager','supervisor','contractor','employee','store') then raise exception 'unknown role' using errcode = '22023'; end if;
  if p_role = 'employee' and not exists (select 1 from app_users where user_id = lower(trim(coalesce(p_target, ''))) and role = 'employee') then
    raise exception 'Worker logins are created from the Employee Master: use Users → Create worker logins' using errcode = '22023';
  end if;
  if p_role = 'contractor' and coalesce(trim(p_contractor), '') = '' then raise exception 'choose the contractor for this login' using errcode = '22023'; end if;
  if p_role in ('production_manager','supervisor') and coalesce(trim(p_division), '') = '' then raise exception 'choose the division for this login' using errcode = '22023'; end if;
  if t = u.user_id and (p_role <> 'admin' or not coalesce(p_active, true)) then raise exception 'you cannot remove your own admin access' using errcode = '22023'; end if;
  if (p_fp is null) <> (p_salt is null) or (p_fp is not null and (p_fp !~ '^[0-9a-f]{64}$' or p_salt !~ '^[0-9a-f]{32}$')) then
    raise exception 'bad password data' using errcode = '22023';
  end if;
  select * into existing from app_users where user_id = t;
  if existing.user_id is null and p_fp is null then raise exception 'a new login needs a password' using errcode = '22023'; end if;
  insert into app_users (user_id, fp, salt, role, contractor, division, name, active)
  values (t, p_fp, p_salt, p_role, case when p_role = 'contractor' then nullif(trim(p_contractor), '') end,
          case when p_role in ('production_manager','supervisor','gm_production') then nullif(trim(p_division), '') end,
          nullif(trim(p_name), ''), coalesce(p_active, true))
  on conflict (user_id) do update set
    role = excluded.role,
    -- a worker login keeps the contractor and division of its worker record
    contractor = case when excluded.role = 'employee' then app_users.contractor else excluded.contractor end,
    division   = case when excluded.role = 'employee' then app_users.division   else excluded.division end,
    name = excluded.name, active = excluded.active,
    fp = coalesce(p_fp, app_users.fp), salt = coalesce(p_salt, app_users.salt),
    must_change = case when p_fp is not null and excluded.role = 'employee' then true else app_users.must_change end;
  insert into audit_log (user_id, text) values (u.user_id, 'Admin ' || case when existing.user_id is null then 'created' else 'updated' end ||
    ' login ' || t || ' (' || p_role || ')' || case when p_fp is not null and existing.user_id is not null then ' and reset its password' else '' end ||
    case when not coalesce(p_active, true) then ' — deactivated' else '' end);
  return jsonb_build_object('ok', true, 'user', t);
end $$;

create or replace function cw_admin_delete_user(p_user text, p_key text, p_target text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare u app_users; t text := lower(trim(coalesce(p_target, '')));
begin
  u := cw_admin(p_user, p_key);
  if t = u.user_id then raise exception 'you cannot delete your own login' using errcode = '22023'; end if;
  delete from app_users where user_id = t;
  insert into audit_log (user_id, text) values (u.user_id, 'Admin deleted login ' || t);
  return jsonb_build_object('ok', true);
end $$;

-- worker logins in bulk from the Employee Master: rows [{user, empId, name, fp, salt}]
-- contractor and division are taken from the worker record, never from the request
create or replace function cw_admin_create_logins(p_user text, p_key text, p_rows jsonb) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare u app_users; x jsonb; w records; made int := 0; skipped jsonb := '[]'::jsonb; t text;
begin
  u := cw_admin(p_user, p_key);
  for x in select * from jsonb_array_elements(coalesce(p_rows, '[]'::jsonb)) loop
    t := lower(trim(coalesce(x->>'user', '')));
    w := null;
    select * into w from records where collection = 'workers' and id = x->>'empId';
    if t !~ '^[a-z0-9][a-z0-9._-]{1,39}$' or w.id is null or coalesce(x->>'fp', '') !~ '^[0-9a-f]{64}$' or coalesce(x->>'salt', '') !~ '^[0-9a-f]{32}$'
       or exists (select 1 from app_users where user_id = t or emp_id = w.id) then
      skipped := skipped || jsonb_build_array(x->>'empId'); continue;
    end if;
    insert into app_users (user_id, fp, salt, role, contractor, division, name, active, emp_id, must_change)
    values (t, x->>'fp', x->>'salt', 'employee', w.contractor, w.division, coalesce(nullif(trim(x->>'name'), ''), w.data->>'name'), true, w.id, true);
    made := made + 1;
  end loop;
  if made > 0 then insert into audit_log (user_id, text) values (u.user_id, 'Admin created ' || made || ' worker login(s)'); end if;
  return jsonb_build_object('ok', true, 'created', made, 'skipped', skipped);
end $$;

-- anyone changes their own password (workers must at their first sign-in)
create or replace function cw_change_password(p_user text, p_key text, p_fp text, p_salt text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare u app_users;
begin
  u := cw_auth(p_user, p_key);
  if coalesce(p_fp, '') !~ '^[0-9a-f]{64}$' or coalesce(p_salt, '') !~ '^[0-9a-f]{32}$' then raise exception 'bad password data' using errcode = '22023'; end if;
  if p_fp = u.fp then raise exception 'choose a new password, not the current one' using errcode = '22023'; end if;
  update app_users set fp = p_fp, salt = p_salt, must_change = false where user_id = u.user_id;
  insert into audit_log (user_id, text) values (u.user_id, 'Changed their own password');
  return jsonb_build_object('ok', true);
end $$;

-- the contractor list used everywhere in the app: [{name, location, active}]
create or replace function cw_admin_set_contractors(p_user text, p_key text, p_list jsonb) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare u app_users;
begin
  u := cw_admin(p_user, p_key);
  if jsonb_typeof(p_list) <> 'array' then raise exception 'bad list' using errcode = '22023'; end if;
  insert into app_settings (key, value, updated_at, updated_by) values ('contractors', p_list, now(), u.user_id)
  on conflict (key) do update set value = excluded.value, updated_at = now(), updated_by = u.user_id;
  insert into audit_log (user_id, text) values (u.user_id, 'Admin updated the contractor list (' || jsonb_array_length(p_list) || ' contractors)');
  return jsonb_build_object('ok', true);
end $$;

-- rename a contractor across every record, document, login and list
create or replace function cw_admin_rename_contractor(p_user text, p_key text, p_old text, p_new text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare u app_users; n_rec int := 0; n_users int := 0; n int;
begin
  u := cw_admin(p_user, p_key);
  if coalesce(trim(p_new), '') = '' or cw_norm(p_old) = cw_norm(p_new) then raise exception 'enter the new name' using errcode = '22023'; end if;
  update records set data = jsonb_set(data, '{contractor}', to_jsonb(p_new))
    where cw_norm(data->>'contractor') = cw_norm(p_old);
  get diagnostics n_rec = row_count;
  update records set contractor = p_new where cw_norm(contractor) = cw_norm(p_old);
  update records set data = jsonb_set(data, '{assignedContractors}',
      (select coalesce(jsonb_agg(case when cw_norm(a) = cw_norm(p_old) then p_new else a end), '[]'::jsonb)
       from jsonb_array_elements_text(data->'assignedContractors') a))
    where collection = 'requisitions' and jsonb_typeof(data->'assignedContractors') = 'array'
      and exists (select 1 from jsonb_array_elements_text(data->'assignedContractors') a where cw_norm(a) = cw_norm(p_old));
  get diagnostics n = row_count; n_rec := n_rec + n;
  update documents set contractor = p_new where cw_norm(contractor) = cw_norm(p_old);
  update app_users set contractor = p_new where cw_norm(contractor) = cw_norm(p_old);
  get diagnostics n_users = row_count;
  update app_settings set value = (select coalesce(jsonb_agg(case when cw_norm(e->>'name') = cw_norm(p_old) then e || jsonb_build_object('name', p_new) else e end), '[]'::jsonb)
                                   from jsonb_array_elements(value) e), updated_at = now(), updated_by = u.user_id
    where key = 'contractors' and jsonb_typeof(value) = 'array';
  update app_settings set value = (select coalesce(jsonb_agg(distinct case when cw_norm(e) = cw_norm(p_old) then p_new else e end), '[]'::jsonb)
                                   from jsonb_array_elements_text(value) e)
    where key = 'knownContractors' and jsonb_typeof(value) = 'array';
  insert into audit_log (user_id, text) values (u.user_id, 'Admin renamed contractor "' || p_old || '" to "' || p_new || '" (' || n_rec || ' records, ' || n_users || ' logins)');
  return jsonb_build_object('ok', true, 'records', n_rec, 'logins', n_users);
end $$;

revoke all on function cw_admin(text, text), cw_user_json(app_users), cw_sheet(), cw_sheet_send(jsonb), cw_login_row(login_events), cw_event_row(app_events) from public;
revoke execute on function cw_admin(text, text), cw_user_json(app_users), cw_sheet(), cw_sheet_send(jsonb), cw_login_row(login_events), cw_event_row(app_events) from anon, authenticated;
revoke execute on function cw_html(text), cw_mail_to(text[], text, text, text[]), cw_setting_users(text, text), cw_ticket_users(text), cw_worker_email(text),
  cw_mail_enabled(), cw_mail_send(jsonb, text), cw_mail_msg(text[], text, text, jsonb), cw_notify() from public, anon, authenticated;
grant execute on function cw_login_salt(text), cw_login(text, text, text, text), cw_whoami(text, text), cw_event(text, text, text, jsonb),
  cw_admin_overview(text, text), cw_admin_save_user(text, text, text, text, text, text, text, boolean, text, text),
  cw_admin_delete_user(text, text, text), cw_admin_set_contractors(text, text, jsonb), cw_admin_rename_contractor(text, text, text, text),
  cw_admin_set_sheet(text, text, text, text, boolean), cw_admin_sheet_send(text, text, text, jsonb),
  cw_admin_create_logins(text, text, jsonb), cw_change_password(text, text, text, text),
  cw_admin_set_email(text, text, text, text), cw_admin_mail(text, text, text, text), cw_admin_set_access(text, text, text, text)
  to anon, authenticated;

revoke all on function cw_auth(text, text), cw_load(text, text), cw_save(text, text, jsonb, jsonb, jsonb, jsonb) from public;
-- only cw_load and cw_save are meant to be called from outside; Supabase grants new functions to its API roles by default
revoke execute on function cw_auth(text, text), cw_norm(text), cw_in_div(text, text),
  cw_is_hr_head(app_users), cw_ppe_desk(app_users, text), cw_ticket_handler(app_users, text), cw_social_read(app_users, records), cw_social_write(app_users, text, records, jsonb), cw_can_read(app_users, records),
  cw_can_write(app_users, text, records, text, text) from anon, authenticated;
grant execute on function cw_load(text, text) to anon, authenticated;
grant execute on function cw_save(text, text, jsonb, jsonb, jsonb, jsonb) to anon, authenticated;

-- ---------------------------------------------------------------------
-- starting logins. Added only if missing: logins changed in the Admin Portal are never overwritten.
-- ---------------------------------------------------------------------
insert into app_users (user_id, fp, salt, role, contractor, division, name) values
  ('joseph', 'c761c0b819cbd10e6cead2cc2d225bbeee1a838aff67fb7dffc44ff29ebeb1ca', 'fc77088525e6fb937cd46fa5eee0d02d', 'hr_admin', null, null, 'Joseph M T'),
  ('hr.office', '754b123c4e06016d3e6eb97475c572dadae79d7002424aa48a969b2180ad6859', '8714438895426eaa42b8d5c0fb708542', 'hr_admin', null, null, 'HR Office'),
  ('gm', 'e33fc29af57289ac45361e3ddb8210cca2c929b8a3943a398bf5ffa18c5f48f0', 'b661f0229d1f4c00e4db8a54e372f5a4', 'gm_production', null, null, 'GM Production'),
  ('pm.vertical', 'c7a01e7fbd9db4fc7730d38fee7fa9055a6ea754c6c8297a0395bc69ec9462f1', 'c56dc6d9f086e29c2025d17cf943bc09', 'production_manager', null, 'Aristo Vertical Production', 'Production Manager'),
  ('supervisor', '855833a813d133f692d09a1c34cbc4386e06b0d06d6860726e9f4114b9d15454', 'a53b1bc853958ebccd0f678c191dbf5f', 'supervisor', null, 'Aristo Vertical Production', 'Supervisor'),
  ('hrd', '81b1655d694a7d7c54d75e0775bcb8e375b9b25b0a767ec39a26c23217720501', '1091d6222069ab22482262f2c13b88cb', 'contractor', 'M/s. HRD Integrated Manpower Solution', null, null),
  ('nanda', '0839098a302121226bee2f6cb9610c4a49ec0f509805cdef3bf8e0c7b6e2feeb', '225ecc31fffe26f589a0cfabc8de9130', 'contractor', 'M/s.Nanda Enterprises', null, null),
  ('pragathi', '755214d2aa6d1ac317797779296474d737512d33cc8acaf1a858edb66101f6ae', '3f4439b1ab28e6523489f603ef9a918e', 'contractor', 'M/s.Pragathi Enterprises', null, null),
  ('captain', '33d72658096744c5b4fdf8cafeea69c07b2b46d1df5a61567ae0099fce2531b3', '27a550ad5fcb2d66a0c06c2faaed86b8', 'contractor', 'M/s. Captain Security & Investigation Service', null, null),
  ('prasanna', '7dcc4e02eb5744b66ecc1ecc80d9fc7b12314ba6a21da6fd60bea7235f49fd61', '6119a05b28f93b43437bfdef61b8164e', 'contractor', 'M/s.Prasanna Housekeeping Glass Cleaning & Security Services', null, null),
  ('chaitanya', 'c8dfadcb8309885d4bd50bd6a68511b093408fc84fb5169af0d0346587073b53', 'e0ff9f01acc97eff4502a6ac58fdc972', 'contractor', 'Chaitanya Services', null, null),
  ('clearway', '0e8237f765901d59a23194ee4e265bbf959eddec6937f0017302dbb3210b9bde', '98c6cb0601dfa619e029f7fa46b5c8b2', 'contractor', 'Clearway Facility Services', null, null),
  ('divya', 'c4fc42493034b15eaa464a49457c535c1aa1a4be429817523e96f6d4a6b0a369', '4df332b8301de51d65214cb508f0d272', 'contractor', 'M/s. Divya Man Power Resources PVT. LTD,', null, null),
  ('admin', '5713f72de077c9ee34d25309e71af47a86d4a2be2405830aa73cf99c8d1808c6', '2e22230e5e50830b8fac3cf1afdf3bf3', 'admin', null, null, 'System Admin')
on conflict (user_id) do update set salt = coalesce(app_users.salt, excluded.salt);

-- starting contractor list (the Admin Portal edits it from here on)
insert into app_settings (key, value, updated_by) values ('contractors', '[
  {"name": "M/s. HRD Integrated Manpower Solution", "location": "Bangalore", "active": true},
  {"name": "M/s.Nanda Enterprises", "location": "Bangalore", "active": true},
  {"name": "M/s.Pragathi Enterprises", "location": "Bangalore", "active": true},
  {"name": "M/s. Captain Security & Investigation Service", "location": "Faridabad", "active": true},
  {"name": "M/s.Prasanna Housekeeping Glass Cleaning & Security Services", "location": "Hyderabad", "active": true},
  {"name": "Chaitanya Services", "location": "Mumbai", "active": true},
  {"name": "Clearway Facility Services", "location": "Kottayam", "active": true},
  {"name": "M/s. Divya Man Power Resources PVT. LTD,", "location": "Bangalore", "active": true}
]'::jsonb, 'setup') on conflict (key) do nothing;

-- starting ticket departments and who handles each (HR edits this in Team & Approvals → Tickets; HR sees every ticket)
insert into app_settings (key, value, updated_by) values ('ticketDepartments', '[
  {"name": "HR", "handlers": ["joseph", "hr.office"]},
  {"name": "Admin", "handlers": ["hod.admin", "mgr.admin"]},
  {"name": "IT", "handlers": []},
  {"name": "Finance", "handlers": []},
  {"name": "Production - Aristo Vertical", "handlers": ["gm", "pm.vertical"]},
  {"name": "Production - Aristo Cabinetry", "handlers": ["hod.cabinetry", "pm.cabinetry"]},
  {"name": "Production - Art of Lacquering", "handlers": ["hod.cabinetry", "pm.lacquer"]},
  {"name": "Quality and Service", "handlers": ["hod.quality", "asst.quality"]},
  {"name": "Stores", "handlers": []},
  {"name": "Maintenance", "handlers": []},
  {"name": "Safety and Security", "handlers": []}
]'::jsonb, 'setup') on conflict (key) do nothing;

-- HR Head (final candidate approval, salary fixing). Admin-only setting: not sent to browsers, not writable from the app.
insert into app_settings (key, value, updated_by) values ('admin_hr_heads', '["joseph"]'::jsonb, 'setup') on conflict (key) do nothing;
-- PPE desks: Admin confirms the PPE requirement, Store issues it (the 'store' role is always a store desk). HR edits this list.
insert into app_settings (key, value, updated_by) values ('ppeDesk', '{"admin": ["hod.admin", "mgr.admin"], "store": ["store"]}'::jsonb, 'setup') on conflict (key) do nothing;

select 'Setup complete' as result, (select count(*) from app_users) as logins;
