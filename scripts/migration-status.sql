-- Read-only rollout status: quote fingerprint plus envelope migration and enrollment progress.
-- Safe on production; the transaction is read-only and rolled back.
\x on
begin transaction read only;
select count(q.id) as quote_count,
       md5(coalesce(string_agg(q.id::text, ',' order by q.id), '')) as id_digest,
       md5(coalesce(string_agg(q.id::text || ':' || q.text || ':' || q.user_id::text || ':' || q.created_at::text || ':' || coalesce(q.quote_date::text, ''), ',' order by q.id), '')) as ciphertext_digest,
       count(q.id) filter (where q.text like '%"version"%') as v2_count,
       s.generation, s.envelope_status, s.revision
from public.vault_state s left join public.quotes q on true
where s.singleton
group by s.generation, s.envelope_status, s.revision;
select m.status as migration_status, m.source_generation, m.target_generation, m.expected_quote_count,
       (select count(*) from public.vault_devices where status = 'pending') as pending_device_requests,
       (select count(*) from public.vault_devices where status = 'active') as active_devices,
       (select count(*) from public.vault_device_wrappers w where w.generation = m.target_generation) as target_device_wrappers,
       (select count(*) from public.vault_recovery_keys where status = 'active') as active_recovery_keys,
       (select count(*) from public.vault_recovery_wrappers w where w.generation = m.target_generation) as target_recovery_wrappers,
       public.qv_envelope_legacy_mode() as legacy_mode_open,
       current_setting('transaction_read_only') as transaction_read_only
from public.vault_state s left join public.vault_migrations m on m.id = s.active_migration_id
where s.singleton;
rollback;
