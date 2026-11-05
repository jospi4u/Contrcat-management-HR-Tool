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
alter table app_users drop constraint if exists app_users_role_check;
alter table app_users add constraint app_users_role_check
  check (role in ('admin','hr_admin','gm_production','production_manager','supervisor','contractor'));

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

create or replace function cw_user_json(u app_users) returns jsonb language sql stable as $$
  select jsonb_build_object('user', u.user_id, 'role', u.role, 'contractor', u.contractor, 'division', u.division, 'name', u.name)
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

-- may this person see this row?
create or replace function cw_can_read(u app_users, r records) returns boolean
language sql stable as $$
  select case (case when u.role = 'admin' then 'hr_admin' else u.role end)
    when 'hr_admin' then true
    when 'gm_production' then r.collection in ('requisitions','candidates','workers')
    when 'contractor' then
      (r.collection in ('workers','pendingSubmissions','candidates','resignations','payrollRuns',
                        'wageRegisters','invoices','attendanceRecords','exitClearances')
        and cw_norm(r.contractor) = cw_norm(u.contractor))
      or (r.collection = 'requisitions' and exists (
            select 1 from jsonb_array_elements_text(coalesce(r.data->'assignedContractors', '[]'::jsonb)) a
            where cw_norm(a) = cw_norm(u.contractor)))
    else -- production_manager, supervisor
      r.collection in ('workers','requisitions','resignations','exitClearances','attendanceRecords','candidates')
        and r.division = u.division
  end
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
      )
    when 'gm_production' then p_coll = 'requisitions' and prev.collection is not null
    else -- production_manager, supervisor
      (p_coll in ('requisitions','exitClearances')
        and new_division = u.division
        and (prev is null or prev.collection is null or prev.division = u.division))
      -- interview decision on a candidate HR forwarded to their division
      or (p_coll = 'candidates' and prev.collection is not null and prev.division = u.division)
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
    'me', jsonb_build_object('user', u.user_id, 'role', u.role, 'contractor', u.contractor, 'division', u.division, 'name', u.name),
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
begin
  u := cw_auth(p_user, p_key);

  for x in select * from jsonb_array_elements(coalesce(p_upserts, '[]'::jsonb)) loop
    prev := null;
    select * into prev from records where collection = x->>'c' and id = x->>'id';
    if not cw_can_write(u, x->>'c', prev, x->>'contractor', x->>'division') then
      rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
    end if;
    d := x->'d';
    if u.role = 'contractor' and x->>'c' = 'payrollRuns' then
      -- contractors may only change the status (confirm / query) and their query note, never amounts
      if coalesce(d->>'status', '') not in ('Contractor Confirmed', 'Query Raised') then
        rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
      end if;
      d := prev.data || jsonb_build_object('status', d->'status', 'queryRemarks', coalesce(d->'queryRemarks', prev.data->'queryRemarks', 'null'::jsonb));
    end if;
    if x->>'c' = 'candidates' and u.role = 'contractor' then
      -- contractors submit or resubmit; they can't move a candidate further along
      if coalesce(d->>'status', '') <> 'Submitted'
         or (prev.collection is not null and coalesce(prev.data->>'status', '') not in ('Submitted', 'Returned to Contractor')) then
        rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
      end if;
    end if;
    if x->>'c' = 'candidates' and u.role in ('production_manager', 'supervisor') then
      -- the interview panel records only its decision; candidate details stay as submitted
      if coalesce(prev.data->>'status', '') not in ('Forwarded to Production', 'On Hold')
         or coalesce(d->>'status', '') not in ('Selected', 'Rejected by Production', 'On Hold') then
        rejected := rejected || jsonb_build_array(jsonb_build_object('c', x->>'c', 'id', x->>'id')); continue;
      end if;
      d := prev.data || jsonb_build_object('status', d->'status', 'interview', d->'interview',
                                           'decisionBy', d->'decisionBy', 'history', d->'history');
    end if;
    insert into records (collection, id, data, contractor, division, updated_at, updated_by)
    values (x->>'c', x->>'id', d, x->>'contractor', x->>'division', now(), u.user_id)
    on conflict (collection, id) do update
      set data = excluded.data,
          contractor = case when u.role in ('hr_admin', 'admin') then excluded.contractor else records.contractor end,
          division   = case when u.role in ('hr_admin', 'admin') then excluded.division   else records.division end,
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
  if u.role not in ('hr_admin', 'admin', 'contractor') then raise exception 'not allowed' using errcode = '42501'; end if;
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
          or (u.role in ('production_manager', 'supervisor') and dd.division = u.division)) then
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
                          'name', name, 'active', active, 'created_at', created_at, 'last_login', last_login, 'has_password', fp is not null)
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
    'workers', coalesce((select jsonb_agg(jsonb_build_object('empId', id, 'status', data->>'status', 'candidateId', data->>'candidateId'))
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

-- add or change a login. p_fp / p_salt are null to keep the current password.
create or replace function cw_admin_save_user(p_user text, p_key text, p_target text, p_role text, p_contractor text,
                                              p_division text, p_name text, p_active boolean, p_fp text, p_salt text)
returns jsonb language plpgsql volatile security definer set search_path = public as $$
declare u app_users; t text := lower(trim(coalesce(p_target, ''))); existing app_users;
begin
  u := cw_admin(p_user, p_key);
  if t !~ '^[a-z0-9][a-z0-9._-]{1,39}$' then raise exception 'User ID: 2-40 letters, numbers, dot, dash or underscore' using errcode = '22023'; end if;
  if p_role not in ('admin','hr_admin','gm_production','production_manager','supervisor','contractor') then raise exception 'unknown role' using errcode = '22023'; end if;
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
          case when p_role in ('production_manager','supervisor') then nullif(trim(p_division), '') end,
          nullif(trim(p_name), ''), coalesce(p_active, true))
  on conflict (user_id) do update set
    role = excluded.role, contractor = excluded.contractor, division = excluded.division, name = excluded.name, active = excluded.active,
    fp = coalesce(p_fp, app_users.fp), salt = coalesce(p_salt, app_users.salt);
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
grant execute on function cw_login_salt(text), cw_login(text, text, text, text), cw_whoami(text, text), cw_event(text, text, text, jsonb),
  cw_admin_overview(text, text), cw_admin_save_user(text, text, text, text, text, text, text, boolean, text, text),
  cw_admin_delete_user(text, text, text), cw_admin_set_contractors(text, text, jsonb), cw_admin_rename_contractor(text, text, text, text),
  cw_admin_set_sheet(text, text, text, text, boolean), cw_admin_sheet_send(text, text, text, jsonb)
  to anon, authenticated;

revoke all on function cw_auth(text, text), cw_load(text, text), cw_save(text, text, jsonb, jsonb, jsonb, jsonb) from public;
-- only cw_load and cw_save are meant to be called from outside; Supabase grants new functions to its API roles by default
revoke execute on function cw_auth(text, text), cw_norm(text), cw_can_read(app_users, records),
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

select 'Setup complete' as result, (select count(*) from app_users) as logins;
