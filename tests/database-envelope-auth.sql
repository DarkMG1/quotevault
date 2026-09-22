-- Device-bound vault RPCs. Run after the envelope/bootstrap migrations.
begin;

do $test$
declare
  admin_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  member_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  other_id uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  admin_device uuid := '11111111-1111-4111-8111-111111111111';
  member_device uuid := '22222222-2222-4222-8222-222222222222';
  other_device uuid := '33333333-3333-4333-8333-333333333333';
  other_pending_device uuid := '55555555-5555-4555-8555-555555555555';
  other_recovery_id uuid := '66666666-6666-4666-8666-666666666666';
  generation uuid := (select generation from public.vault_state where singleton);
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  wrong_token text := 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
  digest text := rtrim(replace(replace(replace(encode(sha256(decode(token || '=', 'base64')), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  jwk jsonb := jsonb_build_object('kty', 'RSA', 'n', rtrim(replace(replace(replace(encode(decode('80' || repeat('00', 383), 'hex'), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '='), 'e', 'AQAB');
  bundle jsonb := jsonb_build_object('version', 2, 'iv', 'AAAAAAAAAAAAAAAA', 'data', 'AAAAAAAAAAAAAAAAAAAAAA==');
  quote_id uuid := '44444444-4444-4444-8444-444444444444';
  response jsonb;
  operation jsonb;
  envelope_mode text;
begin
  insert into public.allowlist(id, email, created_at) values
    (admin_id, 'darkmgdevelopment@gmail.com', now()),
    (member_id, 'member@example.invalid', now()),
    (other_id, 'other@example.invalid', now());
  insert into auth.users(instance_id, id, aud, role, email, encrypted_password, email_confirmed_at)
  values (gen_random_uuid(), admin_id, 'authenticated', 'authenticated', 'darkmgdevelopment@gmail.com', 'x', now()),
         (gen_random_uuid(), member_id, 'authenticated', 'authenticated', 'member@example.invalid', 'x', now()),
         (gen_random_uuid(), other_id, 'authenticated', 'authenticated', 'other@example.invalid', 'x', now());
  insert into public.vault_devices(id, owner_id, status, request_kind, enrollment_fingerprint, public_jwk,
    public_key_fingerprint, authorization_token_digest, label, protection_mode, protection, encrypted_private_bundle, lease_expires_at)
  select d.id, d.owner_id, 'active', 'first', digest, jwk, public.qv_public_key_fingerprint(jwk), digest,
    'auth test', 'remembered', '{"version":1,"mode":"remembered"}'::jsonb, bundle, now() + interval '1 day'
  from (values (admin_device, admin_id), (member_device, member_id), (other_device, other_id)) as d(id, owner_id);
  insert into public.vault_devices(id, owner_id, status, request_kind, expires_at, enrollment_fingerprint, public_jwk,
    public_key_fingerprint, authorization_token_digest, label, protection_mode, protection, encrypted_private_bundle)
  values (other_pending_device, other_id, 'pending', 'additional', now() + interval '1 day', digest, jwk,
    public.qv_public_key_fingerprint(jwk), digest, 'pending auth test', 'remembered', '{"version":1,"mode":"remembered"}'::jsonb, bundle);
  insert into public.vault_device_wrappers(device_id, generation, purpose, wrapped_key)
  values (other_device, generation, 'active', repeat('A', 512));
  insert into public.vault_recovery_keys(id, owner_id, status, public_jwk, public_key_fingerprint, encrypted_private_key, kdf, confirmed_at)
  values (other_recovery_id, other_id, 'active', jwk, public.qv_public_key_fingerprint(jwk), bundle,
    '{"version":1,"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}'::jsonb, now());
  insert into public.vault_recovery_wrappers(recovery_key_id, generation, wrapped_key)
  values (other_recovery_id, generation, repeat('A', 512));
  insert into public.quotes(id, text, author, context, quote_date, created_at, user_id, vault_generation)
  values (quote_id, '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}',
    'ENCRYPTED', 'ENCRYPTED', current_date, now(), member_id, generation);
  operation := jsonb_build_object('operation_id', gen_random_uuid(), 'action', 'INSERT', 'quote_id', gen_random_uuid(),
    'actor_id', member_id, 'vault_generation', generation, 'payload', jsonb_build_object('id', gen_random_uuid(),
    'text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', 'author', 'ENCRYPTED',
    'context', 'ENCRYPTED', 'quote_date', null, 'created_at', to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'user_id', member_id, 'vault_generation', generation));
  operation := jsonb_set(operation, '{payload,id}', operation->'quote_id');

  perform set_config('request.jwt.claim.sub', member_id::text, true);
  -- Legacy and preparing preserve the existing null-device contracts.
  if public.get_vault_state() is null or public.sync_quotes(generation, null, '[]') is null then
    raise exception 'legacy null-device RPC compatibility regressed';
  end if;
  update public.vault_state set envelope_status = 'preparing' where singleton;
  if public.get_vault_state() is null or public.sync_quotes(generation, null, '[]') is null then
    raise exception 'preparing null-device RPC compatibility regressed';
  end if;
  update public.vault_state set envelope_status = 'active' where singleton;

  foreach envelope_mode in array array['staging', 'active', 'maintenance'] loop
    update public.vault_state set envelope_status = envelope_mode where singleton;
    if public.get_vault_state(member_device, wrong_token) is not null
       or public.get_vault_state(member_device, token) is null
       or public.sync_quotes(generation, null, '[]', member_device, wrong_token) is not null then
      raise exception 'device authorization was not enforced in % mode', envelope_mode;
    end if;
  end loop;
  update public.vault_state set envelope_status = 'active' where singleton;

  -- No protected RPC returns a snapshot, quote, or result before device authorization.
  if public.get_vault_state(null, null) is not null
     or public.get_vault_state(member_device, wrong_token) is not null
     or public.get_vault_state(other_device, token) is not null
     or public.sync_quotes(generation, null, '[]', null, null) is not null
     or public.sync_quotes(generation, null, '[]', member_device, wrong_token) is not null
     or public.sync_quotes(generation, null, '[]', other_device, token) is not null
     or public.checked_import(generation, 0, jsonb_build_array(operation), null, null) is not null then
    raise exception 'unauthorized device received protected vault data';
  end if;
  if public.get_vault_state(member_device, token) is null
     or public.sync_quotes(generation, null, '[]', member_device, token)->'quotes' is null then
    raise exception 'authorized member device did not receive vault state/snapshot';
  end if;
  update public.vault_devices set lease_expires_at = now() - interval '1 second' where id = member_device;
  if public.get_vault_state(member_device, token) is not null
     or public.sync_quotes(generation, null, '[]', member_device, token) is not null then
    raise exception 'expired lease received vault data';
  end if;
  update public.vault_devices set lease_expires_at = now() + interval '1 day' where id = member_device;
  if public.sync_quotes(gen_random_uuid(), null, '[]', member_device, token) is not null then
    raise exception 'stale generation returned a snapshot';
  end if;
  update public.vault_devices set status = 'revoked', revoked_at = now(), lease_expires_at = null where id = member_device;
  if public.get_vault_state(member_device, token) is not null then
    raise exception 'revoked device received vault state';
  end if;
  update public.vault_devices set status = 'active', revoked_at = null, lease_expires_at = now() + interval '1 day' where id = member_device;

  perform set_config('request.jwt.claim.sub', admin_id::text, true);
  if public.edit_quote(generation, quote_id, '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', current_date, null, null) is not null
     or public.edit_quotes(generation, '[]', null, null) is not null then
    raise exception 'unauthorized admin device received edit result';
  end if;
  if public.edit_quote(generation, quote_id, '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', current_date, admin_device, token) is null
     or public.edit_quotes(generation, jsonb_build_array(jsonb_build_object('quote_id', quote_id, 'expected_text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', 'text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', 'quote_date', current_date)), admin_device, token) is null then
    raise exception 'authorized admin device could not edit';
  end if;
  if jsonb_array_length(public.list_members(admin_device, token)) <> 3 then
    raise exception 'admin member listing failed';
  end if;
  response := public.add_member('added@example.invalid', admin_device, token);
  if response->>'email' <> 'added@example.invalid' or jsonb_array_length(public.list_members(admin_device, token)) <> 4
     or public.remove_member_access((response->>'id')::uuid, admin_device, token)->>'status' <> 'removed' then
    raise exception 'admin member addition/removal failed';
  end if;
  response := public.remove_member_access(other_id, admin_device, token);
  if response->>'status' <> 'removed'
     or exists (select 1 from public.allowlist where id = other_id)
     or exists (select 1 from public.vault_devices where owner_id = other_id and status <> 'revoked')
     or exists (select 1 from public.vault_device_wrappers w join public.vault_devices d on d.id = w.device_id where d.owner_id = other_id)
     or exists (select 1 from public.vault_recovery_wrappers w join public.vault_recovery_keys k on k.id = w.recovery_key_id where k.owner_id = other_id)
     or exists (select 1 from public.vault_recovery_keys where id = other_recovery_id and status <> 'revoked') then
    raise exception 'member removal did not revoke access, devices, or wrappers: %, %, %', response,
      exists (select 1 from public.allowlist where id = other_id),
      exists (select 1 from public.vault_devices where owner_id = other_id and status <> 'revoked');
  end if;
end;
$test$;

-- Active envelope mode keeps tables RPC-only; legacy policy remains needed before cutover.
set local role authenticated;
select set_config('request.jwt.claim.sub', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', true);
do $$ begin
  if exists (select 1 from public.quotes) then raise exception 'active direct quote read bypassed RPCs'; end if;
  if exists (select 1 from public.allowlist) then raise exception 'active direct allowlist read bypassed RPCs'; end if;
end $$;
reset role;

rollback;
