-- Regression checks for device authorization fixes. Allowlist IDs deliberately
-- differ from auth IDs: allowlist membership is email-based.
begin;

do $setup$
declare
  admin_allowlist_id uuid := '10101010-1010-4010-8010-101010101010';
  member_allowlist_id uuid := '20202020-2020-4020-8020-202020202020';
  other_allowlist_id uuid := '30303030-3030-4030-8030-303030303030';
  admin_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  member_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  other_id uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  admin_device uuid := '11111111-1111-4111-8111-111111111111';
  member_device uuid := '22222222-2222-4222-8222-222222222222';
  other_device uuid := '33333333-3333-4333-8333-333333333333';
  other_pending_device uuid := '44444444-4444-4444-8444-444444444444';
  recovery_id uuid := '55555555-5555-4555-8555-555555555555';
  generation uuid := (select generation from public.vault_state where singleton);
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  digest text := rtrim(replace(replace(replace(encode(sha256(decode(token || '=', 'base64')), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  jwk jsonb := jsonb_build_object('kty', 'RSA', 'n', rtrim(replace(replace(replace(encode(decode('80' || repeat('00', 383), 'hex'), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '='), 'e', 'AQAB');
  bundle jsonb := jsonb_build_object('version', 2, 'iv', 'AAAAAAAAAAAAAAAA', 'data', 'AAAAAAAAAAAAAAAAAAAAAA==');
  quote_id uuid := '66666666-6666-4666-8666-666666666666';
  members jsonb;
  response jsonb;
  operation jsonb;
begin
  insert into public.allowlist(id, email, created_at) values
    (admin_allowlist_id, 'darkmgdevelopment@gmail.com', now()),
    (member_allowlist_id, 'member@example.invalid', now()),
    (other_allowlist_id, 'other@example.invalid', now());
  insert into auth.users(instance_id, id, aud, role, email, encrypted_password, email_confirmed_at, raw_user_meta_data)
  values (gen_random_uuid(), admin_id, 'authenticated', 'authenticated', 'darkmgdevelopment@gmail.com', 'x', now(), '{"first_name":"Admin","last_name":"User"}'),
         (gen_random_uuid(), member_id, 'authenticated', 'authenticated', 'member@example.invalid', 'x', now(), '{"first_name":"Member","last_name":"User"}'),
         (gen_random_uuid(), other_id, 'authenticated', 'authenticated', 'other@example.invalid', 'x', now(), '{"first_name":"Other","last_name":"User"}');
  insert into public.vault_devices(id, owner_id, status, request_kind, enrollment_fingerprint, public_jwk, public_key_fingerprint, authorization_token_digest, label, protection_mode, protection, encrypted_private_bundle, lease_expires_at)
  select d.id, d.owner_id, 'active', 'first', digest, jwk, public.qv_public_key_fingerprint(jwk), digest, 'regression test', 'remembered', '{"version":1,"mode":"remembered"}', bundle, now() + interval '1 day'
  from (values (admin_device, admin_id), (member_device, member_id), (other_device, other_id)) d(id, owner_id);
  insert into public.vault_devices(id, owner_id, status, request_kind, expires_at, enrollment_fingerprint, public_jwk, public_key_fingerprint, authorization_token_digest, label, protection_mode, protection, encrypted_private_bundle)
  values (other_pending_device, other_id, 'pending', 'additional', now() + interval '1 day', digest, jwk, public.qv_public_key_fingerprint(jwk), digest, 'pending regression test', 'remembered', '{"version":1,"mode":"remembered"}', bundle);
  insert into public.vault_device_wrappers(device_id, generation, purpose, wrapped_key) values (other_device, generation, 'active', repeat('A', 512));
  insert into public.vault_recovery_keys(id, owner_id, status, public_jwk, public_key_fingerprint, encrypted_private_key, kdf, confirmed_at)
  values (recovery_id, other_id, 'active', jwk, public.qv_public_key_fingerprint(jwk), bundle, '{"version":1,"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}', now());
  insert into public.vault_recovery_wrappers(recovery_key_id, generation, wrapped_key) values (recovery_id, generation, repeat('A', 512));
  insert into public.vault_recovery_challenges(recovery_key_id, expected_digest, expires_at) values (recovery_id, digest, now() + interval '1 day');
  insert into public.quotes(id, text, author, context, quote_date, created_at, user_id, vault_generation)
  values (quote_id, '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', 'ENCRYPTED', 'ENCRYPTED', current_date, now(), member_id, generation);
  operation := jsonb_build_object('operation_id', gen_random_uuid(), 'action', 'INSERT', 'quote_id', gen_random_uuid(), 'actor_id', admin_id, 'vault_generation', generation,
    'payload', jsonb_build_object('id', gen_random_uuid(), 'text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', 'author', 'ENCRYPTED', 'context', 'ENCRYPTED', 'quote_date', null, 'created_at', to_char(now(), 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'user_id', admin_id, 'vault_generation', generation));
  operation := jsonb_set(operation, '{payload,id}', operation->'quote_id');

  perform set_config('request.jwt.claim.sub', admin_id::text, true);
  members := public.list_members(admin_device, token);
  if members->1->>'id' <> member_allowlist_id::text or members->1->>'first_name' <> 'Member' then raise exception 'member listing did not resolve profile through auth email'; end if;
  response := public.remove_member_access(other_allowlist_id, admin_device, token);
  if response->>'status' <> 'removed' or exists(select 1 from public.allowlist where id = other_allowlist_id)
     or exists(select 1 from public.vault_devices where owner_id = other_id and status <> 'revoked')
     or exists(select 1 from public.vault_device_wrappers w join public.vault_devices d on d.id = w.device_id where d.owner_id = other_id)
     or exists(select 1 from public.vault_recovery_wrappers w join public.vault_recovery_keys k on k.id = w.recovery_key_id where k.owner_id = other_id)
     or exists(select 1 from public.vault_recovery_challenges c join public.vault_recovery_keys k on k.id = c.recovery_key_id where k.owner_id = other_id)
     or exists(select 1 from public.vault_devices where id = other_pending_device and status = 'pending')
     or exists(select 1 from public.vault_recovery_keys where id = recovery_id and status <> 'revoked') then
    raise exception 'removal did not map allowlist identity to auth-owned records';
  end if;

  update public.vault_state set envelope_status = 'active' where singleton;
  if public.sync_quotes(generation, null, '[]', null, null) is not null
     or public.checked_import(generation, 0, jsonb_build_array(operation), null, null) is not null
     or public.edit_quote(generation, quote_id, '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', current_date, null, null) is not null
     or public.edit_quotes(generation, jsonb_build_array(jsonb_build_object('quote_id', quote_id, 'expected_text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', 'text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', 'quote_date', current_date)), null, null) is not null then
    raise exception 'missing device token returned protected data';
  end if;
  update public.vault_devices set lease_expires_at = now() - interval '1 second' where id = admin_device;
  if public.checked_import(generation, 0, jsonb_build_array(operation), admin_device, token) is not null
     or public.edit_quote(generation, quote_id, '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', current_date, admin_device, token) is not null then
    raise exception 'expired device returned import or edit data';
  end if;
  update public.vault_devices set lease_expires_at = now() + interval '1 day' where id = admin_device;
  if public.checked_import(gen_random_uuid(), 0, jsonb_build_array(operation), admin_device, token) is not null
     or public.edit_quote(gen_random_uuid(), quote_id, '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', current_date, admin_device, token) is not null then
    raise exception 'stale generation returned import or edit data';
  end if;
  update public.vault_devices set status = 'revoked', revoked_at = now(), lease_expires_at = null where id = admin_device;
  if public.checked_import(generation, 0, jsonb_build_array(operation), admin_device, token) is not null
     or public.edit_quotes(generation, jsonb_build_array(jsonb_build_object('quote_id', quote_id, 'expected_text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', 'text', '$$E2E$${"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}', 'quote_date', current_date)), admin_device, token) is not null then
    raise exception 'revoked device returned import or edit data';
  end if;
  update public.vault_devices set status = 'active', revoked_at = null, lease_expires_at = now() + interval '1 day' where id = admin_device;

  update public.vault_state set envelope_status = 'legacy' where singleton;
end;
$setup$;

-- This remains in the same transaction as the fixtures: legacy reads work,
-- then active mode hides the exact same ciphertext from direct table access.
set local role authenticated;
select set_config('request.jwt.claim.sub', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', true);
do $$ begin
  if not exists(select 1 from public.quotes) then raise exception 'legacy direct quote policy regressed'; end if;
end $$;
reset role;
update public.vault_state set envelope_status = 'active' where singleton;
set local role authenticated;
select set_config('request.jwt.claim.sub', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', true);
do $$ begin
  if exists(select 1 from public.quotes) then raise exception 'active direct quote policy leaked ciphertext'; end if;
end $$;
reset role;

do $rotation$
declare current_generation uuid := (select v.generation from public.vault_state v where v.singleton); rotated jsonb;
begin
  perform set_config('request.jwt.claim.sub', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', true);
  begin
    perform public.rotate_vault(current_generation, '{"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}', '{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}');
    raise exception 'active vault rotation was accepted';
  exception when insufficient_privilege then null;
  end;
  if (select v.generation from public.vault_state v where v.singleton) <> current_generation then raise exception 'denied active rotation changed vault state'; end if;
  update public.vault_state set envelope_status = 'legacy' where singleton;
  rotated := public.rotate_vault(current_generation, '{"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}', '{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}');
  if (rotated->>'generation')::uuid = current_generation then raise exception 'legacy rotation compatibility regressed'; end if;
end;
$rotation$;

rollback;
