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

alter table app_users    enable row level security;
alter table records      enable row level security;
alter table app_settings enable row level security;
alter table audit_log    enable row level security;
revoke all on app_users, records, app_settings, audit_log from anon, authenticated;

-- ---------------------------------------------------------------------
-- helpers
-- ---------------------------------------------------------------------
create or replace function cw_norm(t text) returns text language sql immutable as $$ select lower(trim(coalesce(t, ''))) $$;

create or replace function cw_auth(p_user text, p_key text) returns app_users
language plpgsql stable security definer set search_path = public as $$
declare u app_users;
begin
  select * into u from app_users where user_id = lower(trim(p_user));
  if not found or p_key is null or p_key !~ '^[0-9a-f]{64}$'
     or encode(sha256(convert_to(p_key, 'UTF8')), 'hex') <> u.fp then
    raise exception 'not signed in' using errcode = '28000';
  end if;
  return u;
end $$;

-- may this person see this row?
create or replace function cw_can_read(u app_users, r records) returns boolean
language sql stable as $$
  select case u.role
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
  select case u.role
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
    'settings', coalesce((select jsonb_object_agg(key, value) from app_settings), '{}'::jsonb),
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
          contractor = case when u.role = 'hr_admin' then excluded.contractor else records.contractor end,
          division   = case when u.role = 'hr_admin' then excluded.division   else records.division end,
          updated_at = now(), updated_by = u.user_id;
    saved := saved + 1;
  end loop;

  for x in select * from jsonb_array_elements(coalesce(p_deletes, '[]'::jsonb)) loop
    if u.role = 'hr_admin' then
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
    elsif u.role <> 'hr_admin' then
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
  if u.role not in ('hr_admin', 'contractor') then raise exception 'not allowed' using errcode = '42501'; end if;
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
  if not (u.role = 'hr_admin'
          or (u.role = 'contractor' and cw_norm(dd.contractor) = cw_norm(u.contractor))
          or (u.role in ('production_manager', 'supervisor') and dd.division = u.division)) then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  return jsonb_build_object('id', dd.id, 'name', dd.name, 'mime', dd.mime, 'kind', dd.kind, 'data', dd.data);
end $$;

revoke all on function cw_doc_put(text, text, text, text, text, text, text, text, text, text), cw_doc_get(text, text, text) from public;
grant execute on function cw_doc_put(text, text, text, text, text, text, text, text, text, text) to anon, authenticated;
grant execute on function cw_doc_get(text, text, text) to anon, authenticated;

revoke all on function cw_auth(text, text), cw_load(text, text), cw_save(text, text, jsonb, jsonb, jsonb, jsonb) from public;
-- only cw_load and cw_save are meant to be called from outside; Supabase grants new functions to its API roles by default
revoke execute on function cw_auth(text, text), cw_norm(text), cw_can_read(app_users, records),
  cw_can_write(app_users, text, records, text, text) from anon, authenticated;
grant execute on function cw_load(text, text) to anon, authenticated;
grant execute on function cw_save(text, text, jsonb, jsonb, jsonb, jsonb) to anon, authenticated;

-- ---------------------------------------------------------------------
-- logins (must match middleware.js). Re-running updates them.
-- ---------------------------------------------------------------------
insert into app_users (user_id, fp, role, contractor, division, name) values
  ('joseph', 'c761c0b819cbd10e6cead2cc2d225bbeee1a838aff67fb7dffc44ff29ebeb1ca', 'hr_admin', null, null, 'Joseph M T'),
  ('hr.office', '754b123c4e06016d3e6eb97475c572dadae79d7002424aa48a969b2180ad6859', 'hr_admin', null, null, 'HR Office'),
  ('gm', 'e33fc29af57289ac45361e3ddb8210cca2c929b8a3943a398bf5ffa18c5f48f0', 'gm_production', null, null, 'GM Production'),
  ('pm.vertical', 'c7a01e7fbd9db4fc7730d38fee7fa9055a6ea754c6c8297a0395bc69ec9462f1', 'production_manager', null, 'Aristo Vertical Production', 'Production Manager'),
  ('supervisor', '855833a813d133f692d09a1c34cbc4386e06b0d06d6860726e9f4114b9d15454', 'supervisor', null, 'Aristo Vertical Production', 'Supervisor'),
  ('hrd', '81b1655d694a7d7c54d75e0775bcb8e375b9b25b0a767ec39a26c23217720501', 'contractor', 'M/s. HRD Integrated Manpower Solution', null, null),
  ('nanda', '0839098a302121226bee2f6cb9610c4a49ec0f509805cdef3bf8e0c7b6e2feeb', 'contractor', 'M/s.Nanda Enterprises', null, null),
  ('pragathi', '755214d2aa6d1ac317797779296474d737512d33cc8acaf1a858edb66101f6ae', 'contractor', 'M/s.Pragathi Enterprises', null, null),
  ('captain', '33d72658096744c5b4fdf8cafeea69c07b2b46d1df5a61567ae0099fce2531b3', 'contractor', 'M/s. Captain Security & Investigation Service', null, null),
  ('prasanna', '7dcc4e02eb5744b66ecc1ecc80d9fc7b12314ba6a21da6fd60bea7235f49fd61', 'contractor', 'M/s.Prasanna Housekeeping Glass Cleaning & Security Services', null, null),
  ('chaitanya', 'c8dfadcb8309885d4bd50bd6a68511b093408fc84fb5169af0d0346587073b53', 'contractor', 'Chaitanya Services', null, null),
  ('clearway', '0e8237f765901d59a23194ee4e265bbf959eddec6937f0017302dbb3210b9bde', 'contractor', 'Clearway Facility Services', null, null),
  ('divya', 'c4fc42493034b15eaa464a49457c535c1aa1a4be429817523e96f6d4a6b0a369', 'contractor', 'M/s. Divya Man Power Resources PVT. LTD,', null, null)
on conflict (user_id) do update
  set fp = excluded.fp, role = excluded.role, contractor = excluded.contractor,
      division = excluded.division, name = excluded.name;

-- remove logins that are no longer in middleware.js
delete from app_users where user_id not in ('joseph', 'hr.office', 'gm', 'pm.vertical', 'supervisor', 'hrd', 'nanda', 'pragathi', 'captain', 'prasanna', 'chaitanya', 'clearway', 'divya');

select 'Setup complete' as result, (select count(*) from app_users) as logins;
