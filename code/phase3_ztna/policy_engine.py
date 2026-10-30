# policy_engine.py

def check_policy(source_role, destination_role, risk_level):
    """
    Decide whether traffic should be ALLOW, DENY, or QUARANTINE
    based on the source role, destination role, and current risk level.

    Priority order:
      1. HIGH risk   -> always QUARANTINE regardless of roles
      2. MEDIUM risk -> always DENY until risk drops back to LOW
      3. UNKNOWN src -> always DENY (untrusted by default)
      4. Role-based  -> explicit rules for each trusted role pair
      5. Default     -> DENY anything not explicitly allowed
    """

    # --- Priority 1: High risk — full isolation ---
    if risk_level == "HIGH":
        return "QUARANTINE"

    # --- Priority 2: Medium risk — deny access until risk clears ---
    # A host with suspicious activity is blocked even if its role would
    # normally be allowed, until its risk score decays back to LOW.
    if risk_level == "MEDIUM":
        return "DENY"

    # --- Priority 3: Unknown sources are never trusted ---
    if source_role == "UNKNOWN":
        return "DENY"

    # --- Priority 4: Role-based rules for trusted sources ---

    # Users may access the application server
    if source_role == "USER" and destination_role == "APP_SERVER":
        return "ALLOW"

    # Users may not directly reach the database
    if source_role == "USER" and destination_role == "DATABASE":
        return "DENY"

    # The application server may reach the database
    if source_role == "APP_SERVER" and destination_role == "DATABASE":
        return "ALLOW"

    # The application server does not initiate connections to users
    if source_role == "APP_SERVER" and destination_role == "USER":
        return "DENY"

    # --- Priority 5: Default deny — anything not explicitly allowed ---
    return "DENY"
