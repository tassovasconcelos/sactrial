-- SAC 4.0: governança executiva, supervisão regulatória e rastreabilidade administrativa.

create or replace function public.is_platform_superadmin() returns boolean
language sql stable security definer set search_path=pg_catalog,public set row_security=off as $$
  select exists(select 1 from public.profiles where id=auth.uid() and is_active=true and role_code='SUPERADMIN')
$$;
revoke all on function public.is_platform_superadmin() from public,anon;
grant execute on function public.is_platform_superadmin() to authenticated;

-- A RT continua sendo a responsável pelo conteúdo técnico; o SUPERADMIN pode auditar
-- e corrigir a operação, sempre deixando evidência no audit_logs.
drop policy if exists regulatory_compliance_rt_only on public.product_regulatory_compliance;
create policy regulatory_compliance_rt_or_superadmin on public.product_regulatory_compliance
for all to authenticated
using ((tenant_id=public.user_tenant_id() and public.user_role_code()='RESPONSAVEL_TECNICA') or public.is_platform_superadmin())
with check ((tenant_id=public.user_tenant_id() and public.user_role_code()='RESPONSAVEL_TECNICA' and updated_by=auth.uid()) or public.is_platform_superadmin());

drop policy if exists regulatory_reports_rt_only on public.regulatory_report_snapshots;
create policy regulatory_reports_rt_or_superadmin on public.regulatory_report_snapshots
for all to authenticated
using ((tenant_id=public.user_tenant_id() and public.user_role_code()='RESPONSAVEL_TECNICA') or public.is_platform_superadmin())
with check ((tenant_id=public.user_tenant_id() and public.user_role_code()='RESPONSAVEL_TECNICA' and created_by=auth.uid()) or public.is_platform_superadmin());

drop policy if exists audit_logs_tenant_read on public.audit_logs;
create policy audit_logs_tenant_or_superadmin_read on public.audit_logs for select to authenticated
using ((tenant_id=public.user_tenant_id() and public.user_role_code() in ('SUPERADMIN','DIRETORIA','ADMIN_EMPRESA','RESPONSAVEL_TECNICA')) or public.is_platform_superadmin());
drop policy if exists audit_logs_tenant_insert on public.audit_logs;
create policy audit_logs_actor_insert on public.audit_logs for insert to authenticated
with check (user_id=auth.uid() and (tenant_id=public.user_tenant_id() or public.is_platform_superadmin()));

-- Logs são evidências imutáveis para auditoria. Correções geram novo evento.
revoke update,delete on public.audit_logs from authenticated;

create or replace function public.audit_sensitive_change() returns trigger
language plpgsql security definer set search_path=pg_catalog,public set row_security=off as $$
declare v_tenant uuid; v_id uuid; v_before jsonb; v_after jsonb;
begin
  v_before:=case when tg_op='INSERT' then null else to_jsonb(old) end;
  v_after:=case when tg_op='DELETE' then null else to_jsonb(new) end;
  v_tenant:=coalesce((v_after->>'tenant_id')::uuid,(v_before->>'tenant_id')::uuid,public.user_tenant_id());
  if tg_table_name='ticket_items' then
    select tenant_id into v_tenant from public.tickets where id=coalesce((v_after->>'ticket_id')::uuid,(v_before->>'ticket_id')::uuid);
  end if;
  v_id:=coalesce((v_after->>'id')::uuid,(v_before->>'id')::uuid);
  insert into public.audit_logs(tenant_id,user_id,user_email,action,entity,entity_id,details)
  values(v_tenant,auth.uid(),auth.jwt()->>'email','ADMIN_'||tg_op,tg_table_name,v_id,
    jsonb_build_object('before',v_before,'after',v_after,'actor_role',public.user_role_code(),'occurred_at',now()));
  return case when tg_op='DELETE' then old else new end;
end $$;
revoke all on function public.audit_sensitive_change() from public,anon;
revoke execute on function public.audit_sensitive_change() from authenticated;

do $$
declare t text;
begin
  foreach t in array array['tickets','ticket_items','service_orders','risk_cases','product_regulatory_compliance','regulatory_report_snapshots','compliance_audits','audit_documents','tenant_modules'] loop
    if to_regclass('public.'||t) is not null then
      execute format('drop trigger if exists %I on public.%I','trg_'||t||'_admin_audit',t);
      execute format('create trigger %I after insert or update or delete on public.%I for each row execute function public.audit_sensitive_change()','trg_'||t||'_admin_audit',t);
    end if;
  end loop;
end $$;

-- Gera pendência automática para a RT sempre que um item é salvo sem lote e sem série.
create or replace function public.alert_missing_ticket_traceability() returns trigger
language plpgsql security definer set search_path=pg_catalog,public set row_security=off as $$
declare v_ticket public.tickets%rowtype; v_rt public.profiles%rowtype;
begin
  if nullif(trim(coalesce(new.lot_number,'')),'') is not null or nullif(trim(coalesce(new.serial_number,'')),'') is not null then return new; end if;
  select * into v_ticket from public.tickets where id=new.ticket_id;
  select * into v_rt from public.profiles where tenant_id=v_ticket.tenant_id and role_code='RESPONSAVEL_TECNICA' and is_active=true order by created_at limit 1;
  insert into public.operational_alerts(tenant_id,module_code,entity_type,entity_id,severity,title,message,recipient_profile_id,recipient_name,recipient_email,due_at,delivery_status)
  values(v_ticket.tenant_id,'REGULATORY','TICKET',v_ticket.id,'HIGH','Rastreabilidade obrigatória pendente',
    'O SAC '||v_ticket.protocol||' possui o produto '||coalesce(new.product_name,'não identificado')||' sem lote e sem número de série. A RT deve completar ou justificar a inaplicabilidade.',
    v_rt.id,v_rt.full_name,v_rt.email,now()+interval '1 day',case when v_rt.email is null then 'NOT_APPLICABLE' else 'QUEUED' end)
  on conflict do nothing;
  return new;
end $$;
revoke all on function public.alert_missing_ticket_traceability() from public,anon;
revoke execute on function public.alert_missing_ticket_traceability() from authenticated;
drop trigger if exists trg_ticket_item_traceability_alert on public.ticket_items;
create trigger trg_ticket_item_traceability_alert after insert or update of lot_number,serial_number on public.ticket_items
for each row execute function public.alert_missing_ticket_traceability();

insert into public.product_releases(version,title,summary,improvements)
values('4.2.0','Governança executiva e regulatória','Painel executivo, supervisão ANVISA/Inmetro, rastreabilidade obrigatória e LOG administrativo imutável.',
'["Sala de situação da diretoria","Indicadores de resolução, backlog, risco, reincidência e rastreabilidade","Acesso regulatório auditável para SUPERADMIN","Alerta automático à RT por ausência de lote ou série","Auditoria de alterações em SAC, OS, risco, módulos e documentos","Modularização por contrato preservada"]'::jsonb)
on conflict(version) do update set title=excluded.title,summary=excluded.summary,improvements=excluded.improvements,published_at=now();
