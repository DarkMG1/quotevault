-- Read-only. Safe on production. Prints no plaintext (quotes are ciphertext).
select count(q.id) as quote_count,
       md5(coalesce(string_agg(q.id::text, ',' order by q.id), '')) as id_digest,
       md5(coalesce(string_agg(q.id::text || ':' || q.text || ':' || q.user_id::text || ':' || q.created_at::text || ':' || coalesce(q.quote_date::text, ''), ',' order by q.id), '')) as ciphertext_digest,
       s.generation, s.envelope_status, s.revision
from public.vault_state s left join public.quotes q on true
where s.singleton
group by s.generation, s.envelope_status, s.revision;
