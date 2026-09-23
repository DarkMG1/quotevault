-- Legacy reversion preserves every quote and refuses every unsafe request.
begin;
do $test$
declare
  admin_id uuid := 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  member_id uuid := 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  admin_device uuid := '11111111-1111-4111-8111-111111111111';
  g uuid := (select generation from public.vault_state where singleton);
  token text := 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  digest text := rtrim(replace(replace(replace(encode(sha256(decode(token || '=', 'base64')), 'base64'), E'\n', ''), '+', '-'), '/', '_'), '=');
  jwk jsonb := jsonb_build_object('kty','RSA','n',rtrim(replace(replace(replace(encode(decode('80'||repeat('00',383),'hex'),'base64'),E'\n',''),'+','-'),'/','_'),'='),'e','AQAB');
  v1 text := '$$E2E$${"iv":"CCCCCCCCCCCCCCCC","data":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  q1 uuid := '44444444-4444-4444-8444-444444444444';
  q2 uuid := '55555555-5555-4555-8555-555555555555';
  begun jsonb; committed jsonb; r uuid; before_meta text; rev bigint;
begin
  insert into public.allowlist(id,email,created_at) values (admin_id,'darkmgdevelopment@gmail.com',now()),(member_id,'member@example.invalid',now());
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at) values
    (gen_random_uuid(),admin_id,'authenticated','authenticated','darkmgdevelopment@gmail.com','x',now()),
    (gen_random_uuid(),member_id,'authenticated','authenticated','member@example.invalid','x',now());
  insert into public.vault_devices(id,owner_id,status,request_kind,enrollment_fingerprint,public_jwk,public_key_fingerprint,authorization_token_digest,label,protection_mode,protection,encrypted_private_bundle,lease_expires_at)
    values(admin_device,admin_id,'active','first',digest,jwk,public.qv_public_key_fingerprint(jwk),digest,'t','remembered','{"version":1,"mode":"remembered"}'::jsonb,'{"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb,now()+interval '1 day');
  insert into public.quotes(id,text,author,context,quote_date,created_at,user_id,vault_generation) values
    (q1,'$$E2E$${"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}','ENCRYPTED','ENCRYPTED',date '2026-09-20','2026-09-20T12:00:00.123456Z',member_id,g),
    (q2,'$$E2E$${"version":2,"iv":"BBBBBBBBBBBBBBBB","data":"AAAAAAAAAAAAAAAAAAAAAA=="}','ENCRYPTED','ENCRYPTED',null,'2026-09-21T12:00:00Z',admin_id,g);
  update public.vault_state set envelope_status='active' where singleton;
  before_meta := (select string_agg(id::text||user_id::text||created_at::text||coalesce(quote_date::text,''),',' order by id) from public.quotes);
  rev := (select revision from public.vault_state);

  -- Members cannot start a reversion; active vaults require the admin's device.
  perform set_config('request.jwt.claim.sub',member_id::text,true);
  begin perform public.begin_legacy_reversion(g,rev,null,null); raise exception 'member began a reversion'; exception when sqlstate '42501' then null; end;
  perform set_config('request.jwt.claim.sub',admin_id::text,true);
  begin perform public.begin_legacy_reversion(g,rev,null,null); raise exception 'active vault reverted without device authorization'; exception when sqlstate '42501' then null; end;
  begin perform public.begin_legacy_reversion(g,rev+1,admin_device,token); raise exception 'stale revision accepted'; exception when sqlstate '40001' then null; end;

  begun := public.begin_legacy_reversion(g,rev,admin_device,token); r := (begun->>'reversion_id')::uuid;
  if (begun->>'expected_quote_count')::int <> 2 then raise exception 'wrong expected count %', begun; end if;

  -- Staged text must be v1 legacy ciphertext for a quote in the source generation.
  begin perform public.stage_legacy_reversion(r,jsonb_build_array(jsonb_build_object('quote_id',q1,'text','$$E2E$${"version":2,"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}')),admin_device,token); raise exception 'v2 text staged'; exception when sqlstate '22023' then null; end;
  begin perform public.stage_legacy_reversion(r,jsonb_build_array(jsonb_build_object('quote_id',gen_random_uuid(),'text',v1)),admin_device,token); raise exception 'foreign quote staged'; exception when sqlstate '22023' then null; end;
  begin perform public.stage_legacy_reversion(r,jsonb_build_array(jsonb_build_object('quote_id',q1,'text','plaintext')),admin_device,token); raise exception 'unencrypted text staged'; exception when sqlstate '22023' then null; end;
  perform public.stage_legacy_reversion(r,jsonb_build_array(jsonb_build_object('quote_id',q1,'text',v1)),admin_device,token);

  -- Commit refuses an incomplete set; nothing changes.
  begin perform public.commit_legacy_reversion(r,'{"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}'::jsonb,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb,admin_device,token); raise exception 'incomplete reversion committed'; exception when sqlstate '40001' then null; end;
  if (select envelope_status from public.vault_state)<>'active' or exists(select 1 from public.quotes where text=v1) then raise exception 'failed commit changed state'; end if;

  perform public.stage_legacy_reversion(r,jsonb_build_array(jsonb_build_object('quote_id',q2,'text',v1)),admin_device,token);

  -- A write after begin invalidates the snapshot.
  update public.vault_state set revision=revision+1 where singleton;
  begin perform public.commit_legacy_reversion(r,'{"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}'::jsonb,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb,admin_device,token); raise exception 'revision changed after begin but commit succeeded'; exception when sqlstate '40001' then null; end;
  update public.vault_state set revision=rev where singleton;

  committed := public.commit_legacy_reversion(r,'{"salt":"MDEyMzQ1Njc4OWFiY2RlZg==","iterations":600000}'::jsonb,'{"iv":"AAAAAAAAAAAAAAAA","data":"AAAAAAAAAAAAAAAAAAAAAA=="}'::jsonb,admin_device,token);
  if committed->>'envelope_status'<>'legacy' or (select envelope_status from public.vault_state)<>'legacy'
     or (select generation from public.vault_state)<>(begun->>'target_generation')::uuid
     or (select revision from public.vault_state)<=rev then raise exception 'state not legacy after commit: %', committed; end if;
  if (select count(*) from public.quotes)<>2 or exists(select 1 from public.quotes where text<>v1 or vault_generation<>(begun->>'target_generation')::uuid) then raise exception 'quotes not rewritten exactly'; end if;
  if (select string_agg(id::text||user_id::text||created_at::text||coalesce(quote_date::text,''),',' order by id) from public.quotes) is distinct from before_meta then raise exception 'quote metadata changed'; end if;
  if (select count(*) from public.vault_legacy_reversion_rows where reversion_id=r and row_kind='source')<>2 then raise exception 'source ciphertext not retained'; end if;
  if public.qv_envelope_legacy_mode() is not true then raise exception 'legacy RPCs not reopened'; end if;
end $test$;
rollback;
