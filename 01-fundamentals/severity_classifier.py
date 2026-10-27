

def main():
    print("=== SOC Alert Triage System ===")
    
    # 1. Entrada de dados
    incident_name = input("Name of incident / alert: ").strip()
    target_ip = input("Destination IP Address: ").strip()
    port = int(input("Affected Port (ex: 22, 80, 443, 3389): "))
    cvss_score = float(input("CVSS score (0.0 a 10.0): "))

    # 2. Definição de portas administrativas sensíveis
    is_sensitive_port = (port == 22) or (port == 3389) or (port == 445)
    
    # 3. Classificação padrão baseada no padrão CVSS v3
    if cvss_score >= 9.0:
        base_severity = "CRITICAL"
    elif cvss_score >= 7.0:
        base_severity = "HIGHT"
    elif cvss_score >= 4.0:
        base_severity = "MEDIUM"
    else:
        base_severity = "LOW"

    # 4. Lógica de escalonamento prioritário
    # Se atingir uma porta crítica com severidade média ou superior, requer escalonamento
    escalation_required = is_sensitive_port and (cvss_score >= 4.0)

    # 5. Apresentação do relatório com f-strings
    print("\n" + "=" * 40)
    print("       RELATÓRIO DE TRIAGEM")
    print("=" * 40)
    print(f"Alerta:         {incident_name}")
    print(f"Destino:        {target_ip}:{port}")
    print(f"Score CVSS:     {cvss_score:.1f}")
    print(f"Severidade:     {base_severity}")
    print(f"Porta Crítica:  {'SIM' if is_sensitive_port else 'NÃO'}")
    print(f"Escalar p/ L2:  {'URGENTE (Imediato)' if escalation_required else 'Não (Fila Padrão)'}")
    print("=" * 40)


if __name__ == "__main__":
    main()