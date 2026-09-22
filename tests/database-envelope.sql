-- Focused additive envelope foundation checks. Run after all current migrations
-- and 20260922020000_envelope_foundation.sql.
begin;

do $$
declare
  member_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  admin_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  other_id uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  generation uuid;
  request_id uuid;
  device_id uuid;
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  token_digest text := encode(sha256(decode(token || '=', 'base64')), 'hex');
  public_jwk jsonb := jsonb_build_object('kty', 'RSA', 'n', repeat('A', 512), 'e', 'AQAB');
  protection jsonb := '{"version":1,"mode":"remembered"}'::jsonb;
  fingerprint text := 'fp-abcdef';
  response jsonb;
begin
  select vs.generation into generation from public.vault_state vs where singleton;
  insert into public.allowlist(id, email, created_at)
  values (member_id, 'member@example.invalid', now()), (admin_id, 'darkmgdevelopment@gmail.com', now()), (other_id, 'other@example.invalid', now())
  on conflict (id) do nothing;
  insert into auth.users(instance_id, id, aud, role, email, encrypted_password, email_confirmed_at)
  values (gen_random_uuid(), member_id, 'authenticated', 'authenticated', 'member@example.invalid', 'x', now()),
         (gen_random_uuid(), admin_id, 'authenticated', 'authenticated', 'darkmgdevelopment@gmail.com', 'x', now())
         ,(gen_random_uuid(), other_id, 'authenticated', 'authenticated', 'other@example.invalid', 'x', now())
  on conflict (id) do nothing;

  perform set_config('request.jwt.claim.sub', member_id::text, true);
  if public.qv_authorize_device('00000000-0000-4000-8000-000000000000', token, generation, 'sync') is not null then
    raise exception 'missing device authorized';
  end if;

  response := public.request_device(
    member_id, 'new-device', public_jwk, fingerprint, token_digest, 'remembered', protection, 'first');
  request_id := (response->>'request_id')::uuid;
  device_id := (response->>'device_id')::uuid;
  if response ? 'wrapped_key' then raise exception 'pending request exposed wrapper'; end if;
  if not exists (select 1 from public.vault_devices where id = device_id and status = 'pending') then
    raise exception 'pending device was not stored';
  end if;

  perform set_config('request.jwt.claim.sub', admin_id::text, true);
  response := public.approve_device(request_id, member_id, fingerprint, 'wrapped', null);
  if response->>'status' <> 'approved' then raise exception 'approval did not succeed'; end if;
  if (select count(*) from public.vault_device_wrappers w where w.device_id = (response->>'device_id')::uuid) <> 1 then
    raise exception 'approval did not store exactly one wrapper';
  end if;
  begin
    perform public.approve_device(request_id, member_id, fingerprint, 'wrapped-again', null);
    raise exception 'approval replay succeeded';
  exception when sqlstate '40001' then null;
  end;

  perform set_config('request.jwt.claim.sub', member_id::text, true);
  if (public.complete_device(device_id, token, generation)->>'device_id')::uuid <> device_id then
    raise exception 'device completion failed';
  end if;
  if public.complete_device(device_id, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', generation) is not null then
    raise exception 'wrong token completed device';
  end if;
  if public.complete_device(device_id, token, gen_random_uuid()) is not null then
    raise exception 'wrong generation completed device';
  end if;
  perform set_config('request.jwt.claim.sub', other_id::text, true);
  if public.complete_device(device_id, token, generation) is not null then
    raise exception 'cross-account completed device';
  end if;
  perform set_config('request.jwt.claim.sub', member_id::text, true);
  perform public.revoke_own_device(device_id, token);
  if public.qv_authorize_device(device_id, token, generation, 'sync') is not null then
    raise exception 'revoked device authorized';
  end if;
end $$;

-- Direct quote reads remain available in legacy mode and are hidden once active.
set local role authenticated;
select set_config('request.jwt.claim.sub', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', true);
do $$
begin
  perform * from public.quotes;
end $$;

reset role;
update public.vault_state set envelope_status = 'active' where singleton;
set local role authenticated;
do $$
declare
  visible_count integer;
begin
  select count(*) into visible_count from public.quotes;
  if visible_count <> 0 then raise exception 'direct quote select bypassed device authorization'; end if;
end $$;

rollback;
