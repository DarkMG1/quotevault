-- Task 5 bootstrap contracts. Run after the envelope migrations.
begin;

do $$
declare
  member_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  admin_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  other_id uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  passkey_id uuid := '22222222-2222-4222-8222-222222222222';
  remembered_id uuid := '33333333-3333-4333-8333-333333333333';
  malformed_active_id uuid := '44444444-4444-4444-8444-444444444444';
  malformed_pending_id uuid := '55555555-5555-4555-8555-555555555555';
  token_digest text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  public_jwk jsonb := jsonb_build_object('kty', 'RSA', 'n', rtrim(replace(replace(replace(encode(decode('80' || repeat('00', 383), 'hex'), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '='), 'e', 'AQAB');
  fingerprint text;
  bundle jsonb := jsonb_build_object('version', 2, 'iv', 'AAAAAAAAAAAAAAAA', 'data', 'AAAAAAAAAAAAAAAAAAAAAA==');
  passkey_protection jsonb := jsonb_build_object('version', 1, 'rpId', 'quotes.darkmg1.dev', 'credentialId', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'prfSalt', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
  remembered_protection jsonb := jsonb_build_object('version', 1, 'mode', 'remembered');
  state jsonb;
  restored jsonb;
begin
  fingerprint := public.qv_public_key_fingerprint(public_jwk);
  insert into public.allowlist(id, email, created_at)
  values (member_id, 'member@example.invalid', now()), (admin_id, 'darkmgdevelopment@gmail.com', now()), (other_id, 'other@example.invalid', now())
  on conflict (id) do nothing;
  insert into auth.users(instance_id, id, aud, role, email, encrypted_password, email_confirmed_at)
  values (gen_random_uuid(), member_id, 'authenticated', 'authenticated', 'member@example.invalid', 'x', now()),
         (gen_random_uuid(), admin_id, 'authenticated', 'authenticated', 'darkmgdevelopment@gmail.com', 'x', now()),
         (gen_random_uuid(), other_id, 'authenticated', 'authenticated', 'other@example.invalid', 'x', now())
  on conflict (id) do nothing;

  if public.qv_valid_device_protection('remembered', remembered_protection) is not true
     or public.qv_valid_device_protection('remembered', '{"version":1}'::jsonb) is not false
     or public.qv_valid_device_protection('remembered', '{"version":1,"mode":"remembered","extra":true}'::jsonb) is not false
     or public.qv_valid_device_protection('passkey-prf', passkey_protection) is not true
     or public.qv_valid_device_protection('passkey-prf', jsonb_set(passkey_protection, '{credentialId}', 'true'::jsonb)) is not false
     or public.qv_valid_device_protection('passkey-prf', jsonb_set(passkey_protection, '{prfSalt}', '"bad"')) is not false
     or public.qv_valid_device_protection('passkey-prf', passkey_protection || '{"extra":true}'::jsonb) is not false then
    raise exception 'device protection validation was not exact';
  end if;

  if has_function_privilege('anon', 'public.get_passkey_restore_devices()', 'EXECUTE')
     or not has_function_privilege('authenticated', 'public.get_passkey_restore_devices()', 'EXECUTE') then
    raise exception 'passkey restoration grants were unsafe';
  end if;

  perform set_config('request.jwt.claim.sub', member_id::text, true);
  begin
    perform public.request_device('44444444-4444-4444-8444-444444444444', member_id, 'invalid protection', public_jwk,
      token_digest, fingerprint, token_digest, 'remembered', '{"version":1}'::jsonb, bundle, 'first');
    raise exception 'request accepted malformed remembered protection';
  exception when sqlstate '22023' then null;
  end;
  state := public.get_vault_state();
  if state->>'envelope_status' <> 'legacy' or state->>'generation' is null
     or state->'kdf' is null or state->'verifier' is null or not state ? 'prepared_generation' then
    raise exception 'legacy bootstrap response changed';
  end if;

  insert into public.vault_devices(id, owner_id, status, request_kind, expires_at, enrollment_fingerprint, public_jwk, public_key_fingerprint, authorization_token_digest, label, protection_mode, protection, encrypted_private_bundle, lease_expires_at)
  values
    (passkey_id, member_id, 'active', 'first', null, token_digest, public_jwk, fingerprint, token_digest, 'passkey restore', 'passkey-prf', passkey_protection, bundle, now() + interval '1 day'),
    (remembered_id, member_id, 'active', 'first', null, token_digest, public_jwk, fingerprint, token_digest, 'remembered restore', 'remembered', remembered_protection, bundle, now() + interval '1 day'),
    (malformed_active_id, member_id, 'active', 'first', null, token_digest, public_jwk, fingerprint, token_digest, 'malformed passkey', 'passkey-prf', '{"version":1}'::jsonb, bundle, now() + interval '1 day'),
    (malformed_pending_id, member_id, 'pending', 'first', now() + interval '1 day', token_digest, public_jwk, fingerprint, token_digest, 'malformed pending', 'remembered', '{"version":1}'::jsonb, bundle, null);
  restored := public.get_passkey_restore_devices();
  if restored->>'generation' is null or jsonb_array_length(restored->'devices') <> 1
     or restored->'devices'->0->>'device_id' <> passkey_id::text
     or restored->'devices'->0->>'public_key_fingerprint' <> fingerprint
     or restored->'devices'->0->'encrypted_private_bundle' <> bundle
     or restored->'devices'->0 ? 'wrapped_key' or restored->'devices'->0 ? 'authorization_token_digest'
     or restored->'devices'->0 ? 'lease_expires_at' then
    raise exception 'passkey restoration response was unsafe or incomplete';
  end if;
  perform set_config('request.jwt.claim.sub', other_id::text, true);
  if jsonb_array_length(public.get_passkey_restore_devices()->'devices') <> 0 then
    raise exception 'passkey restoration crossed account boundary';
  end if;
  perform set_config('request.jwt.claim.sub', admin_id::text, true);
  begin
    perform public.approve_device(malformed_pending_id, member_id, fingerprint, token_digest, repeat('A', 512),
      (select generation from public.vault_state where singleton), null, null);
    raise exception 'malformed pending device was approved';
  exception when sqlstate '40001' then null;
  end;
  if (select status from public.vault_devices where id = malformed_pending_id) <> 'pending'
     or exists (select 1 from public.vault_device_wrappers where device_id = malformed_pending_id) then
    raise exception 'malformed pending device changed state';
  end if;

  update public.vault_state set envelope_status = 'active', prepared_generation = gen_random_uuid() where singleton;
  perform set_config('request.jwt.claim.sub', member_id::text, true);
  state := public.get_vault_state();
  if state->>'envelope_status' <> 'active' or state->>'generation' is null or not state ? 'prepared_generation'
     or state ? 'kdf' or state ? 'verifier' or state ? 'legacy_generation' then
    raise exception 'active bootstrap leaked legacy verifier material';
  end if;
end $$;

rollback;
