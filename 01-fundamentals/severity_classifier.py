"""
Module: 01-fundamentals
Script: severity_classifier.py
Description: Evaluates security incident severity using CVSS v3 scoring and triggers escalation logic for critical infrastructure ports.
"""

def main():
    print("=== SOC Alert Triage System ===")
    
    # 1. User Input Collection
    incident_name = input("Enter incident / alert name: ").strip()
    target_ip = input("Enter target IP address: ").strip()
    port = int(input("Enter affected port (e.g., 22, 80, 443, 3389): "))
    cvss_score = float(input("Enter CVSS score (0.0 - 10.0): "))

    # 2. Critical Management / Lateral Movement Ports (SSH, RDP, SMB)
    is_sensitive_port = (port == 22) or (port == 3389) or (port == 445)
    
    # 3. Standard CVSS v3 Severity Mapping
    if cvss_score >= 9.0:
        base_severity = "CRITICAL"
    elif cvss_score >= 7.0:
        base_severity = "HIGH"
    elif cvss_score >= 4.0:
        base_severity = "MEDIUM"
    else:
        base_severity = "LOW"

    # 4. Escalation Logic
    # Alerts targeting critical ports with at least Medium severity require immediate L2 escalation
    escalation_required = is_sensitive_port and (cvss_score >= 4.0)

    # 5. Formatted Incident Summary Report
    print("\n" + "=" * 45)
    print("           INCIDENT TRIAGE REPORT")
    print("=" * 45)
    print(f"Alert Name:       {incident_name}")
    print(f"Target Endpoint:  {target_ip}:{port}")
    print(f"CVSS Score:       {cvss_score:.1f}")
    print(f"Base Severity:    {base_severity}")
    print(f"Critical Port:    {'YES' if is_sensitive_port else 'NO'}")
    print(f"Tier 2 Escalation:{' URGENT (Immediate Action Required)' if escalation_required else ' Standard Queue'}")
    print("=" * 45)


if __name__ == "__main__":
    main()