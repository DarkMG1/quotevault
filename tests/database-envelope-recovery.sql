-- Focused recovery and lease checks. Run after the envelope-foundation migration.
begin;

do $$
declare
  member_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  other_id uuid := 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  device_id uuid := 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
  recovery_id uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  replacement_id uuid := 'ffffffff-ffff-4fff-8fff-ffffffffffff';
  generation uuid;
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  token_digest text := rtrim(replace(replace(replace(encode(sha256(decode(token || '=', 'base64')), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  public_jwk jsonb := jsonb_build_object('kty', 'RSA', 'n', rtrim(replace(replace(replace(encode(decode('80' || repeat('00', 383), 'hex'), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '='), 'e', 'AQAB');
  fingerprint text;
  bundle jsonb := jsonb_build_object('version', 2, 'iv', 'AAAAAAAAAAAAAAAA', 'data', 'AAAAAAAAAAAAAAAAAAAAAA==');
  kdf jsonb := jsonb_build_object('version', 1, 'salt', 'AAAAAAAAAAAAAAAAAAAAAA==', 'iterations', 600000);
  wrapped_key text := repeat('A', 512);
  issued jsonb;
  recovered jsonb;
  expired jsonb;
begin
  select vs.generation into generation from public.vault_state vs where singleton;
  fingerprint := public.qv_public_key_fingerprint(public_jwk);
  insert into public.allowlist(id, email, created_at)
  values (member_id, 'member@example.invalid', now()), (other_id, 'other@example.invalid', now())
  on conflict (id) do nothing;
  insert into auth.users(instance_id, id, aud, role, email, encrypted_password, email_confirmed_at)
  values (gen_random_uuid(), member_id, 'authenticated', 'authenticated', 'member@example.invalid', 'x', now()),
         (gen_random_uuid(), other_id, 'authenticated', 'authenticated', 'other@example.invalid', 'x', now())
  on conflict (id) do nothing;
  insert into public.vault_devices(id, owner_id, status, request_kind, enrollment_fingerprint, public_jwk, public_key_fingerprint, authorization_token_digest, label, protection_mode, protection, encrypted_private_bundle, lease_expires_at)
  values (device_id, member_id, 'active', 'first', token_digest, public_jwk, fingerprint, token_digest, 'recovery-test', 'remembered', '{"version":1}'::jsonb, bundle, now() + interval '1 day');
  perform set_config('request.jwt.claim.sub', member_id::text, true);
  issued := public.renew_device_lease(device_id, token);
  if issued->>0 <> '1' or issued->>1 <> device_id::text or issued->>2 <> member_id::text
     or issued->>3 <> generation::text or issued->>6 <> fingerprint
     or (issued->>5)::bigint - (issued->>4)::bigint <> 30::bigint * 24 * 60 * 60 * 1000 then
    raise exception 'lease renewal claims were not canonical';
  end if;
  if public.create_recovery_key(recovery_id, public_jwk, fingerprint, bundle, kdf, generation, wrapped_key, device_id, token)->>'recovery_key_id' <> recovery_id::text then
    raise exception 'recovery key creation failed';
  end if;
  if has_function_privilege('authenticated', 'public.begin_recovery(uuid)', 'EXECUTE') then
    raise exception 'authenticated callers can invoke internal recovery challenge RPC';
  end if;
  issued := public.begin_recovery(member_id);
  if issued is null or issued ? 'wrapped_key' or public.qv_base64url_bytes(issued->>'challenge', 32) is null then
    raise exception 'challenge did not contain exactly one opaque 256-bit proof';
  end if;
  if public.complete_recovery((issued->>'challenge_id')::uuid, repeat('B', 43)) is not null then
    raise exception 'wrong recovery challenge returned a wrapper';
  end if;
  recovered := public.complete_recovery((issued->>'challenge_id')::uuid, issued->>'challenge');
  if recovered->>'wrapped_key' <> wrapped_key or recovered->>'generation' <> generation::text then
    raise exception 'exact recovery challenge did not release the active wrapper';
  end if;
  if public.complete_recovery((issued->>'challenge_id')::uuid, issued->>'challenge') is not null then
    raise exception 'recovery challenge was reusable';
  end if;
  expired := public.begin_recovery(member_id);
  update public.vault_recovery_challenges set expires_at = now() - interval '1 second' where id = (expired->>'challenge_id')::uuid;
  if public.complete_recovery((expired->>'challenge_id')::uuid, expired->>'challenge') is not null then
    raise exception 'expired recovery challenge returned a wrapper';
  end if;
  perform set_config('request.jwt.claim.sub', other_id::text, true);
  if public.complete_recovery((public.begin_recovery(member_id)->>'challenge_id')::uuid, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') is not null then
    raise exception 'another account completed recovery';
  end if;
  perform set_config('request.jwt.claim.sub', member_id::text, true);
  if public.replace_recovery_key(replacement_id, public_jwk, fingerprint, bundle, kdf, generation, wrapped_key, device_id, repeat('B', 43)) is not null then
    raise exception 'recovery key replacement bypassed device authorization';
  end if;
  if (select count(*) from public.vault_recovery_keys where owner_id = member_id and status = 'active') <> 1 then
    raise exception 'failed replacement changed active recovery state';
  end if;
end $$;

rollback;
