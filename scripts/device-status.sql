-- Read-only: enrolled devices and recovery keys (no keys, tokens, or ciphertext).
begin transaction read only;
select d.id, u.email, d.status, d.request_kind, d.protection_mode, d.created_at, d.lease_expires_at,
       array(select w.purpose || '@' || left(w.generation::text, 8) from public.vault_device_wrappers w where w.device_id = d.id order by w.generation) as wrappers
from public.vault_devices d left join auth.users u on u.id = d.owner_id
order by d.created_at;
select k.id, u.email, k.status, k.created_at, k.confirmed_at,
       array(select left(w.generation::text, 8) from public.vault_recovery_wrappers w where w.recovery_key_id = k.id order by w.generation) as wrapper_generations
from public.vault_recovery_keys k left join auth.users u on u.id = k.owner_id
order by k.created_at;
select left(target_generation::text, 8) as current_target, status, prepared_at from public.vault_migrations where id = (select active_migration_id from public.vault_state);
rollback;
