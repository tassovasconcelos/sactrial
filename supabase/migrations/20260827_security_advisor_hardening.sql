-- Fecha execução direta de gatilhos SECURITY DEFINER e RPCs anônimos.
revoke execute on function public.alert_missing_ticket_traceability() from authenticated;
revoke execute on function public.audit_sensitive_change() from authenticated;
revoke execute on function public.enforce_profile_seats() from public,anon,authenticated;
revoke execute on function public.guard_profile_privilege() from public,anon,authenticated;
revoke execute on function public.record_saas_usage() from public,anon,authenticated;

revoke execute on function public.generate_technical_subprotocol(uuid) from public,anon;
revoke execute on function public.module_enabled(uuid,text) from public,anon;
revoke execute on function public.open_integrated_risk_case(uuid,text,text,text,smallint,smallint,smallint,text,uuid,boolean,text,integer) from public,anon;

-- Os gatilhos continuam executando internamente; as RPCs operacionais permanecem
-- disponíveis somente para usuários autenticados e continuam validando tenant/perfil.
