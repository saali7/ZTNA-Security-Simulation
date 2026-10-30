# Design, Implementation, and Experimental Evaluation of a Zero Trust Network Access Defense System

**An experimental cybersecurity framework integrating context-aware access control, behavioral threat detection, risk-based policy enforcement, automated containment, and privacy-aware security analysis.**

## 1. Project Overview

This project presents the design, implementation, and experimental evaluation of a **Zero Trust Network Access (ZTNA) defense system** using a controlled Mininet-based network environment.

The research investigates how different security architectures respond to legitimate traffic, unauthorized access, network reconnaissance, lateral movement, and SYN flood attacks.

Three security models are implemented and compared:

- **Phase 1 — Baseline:** An unrestricted network without additional security controls.
- **Phase 2 — Traditional Firewall:** Rule-based traffic filtering, logging, and rate limiting.
- **Phase 3 — Zero Trust:** Context-aware access control integrating behavioral detection, cumulative risk scoring, policy decisions, and automated enforcement.

The objective is to evaluate how Zero Trust principles strengthen access control, restrict unauthorized internal communication, and improve threat containment compared with traditional approaches.

## 2. Key Security Features

- **Context-Aware Access Control:** Evaluates predefined network roles, destinations, observed behavior, and security policies.
- **Behavioral Threat Detection:** Identifies selected port scanning, subnet scanning, SYN flood, and lateral movement activities.
- **Risk-Based Decision Engine:** Uses weighted event scoring to classify threats into LOW, MEDIUM, and HIGH risk levels.
- **Automated Policy Enforcement:** Applies **ALLOW, DENY, and QUARANTINE** decisions using Linux networking rules.
- **Least-Privilege Access:** Restricts unauthorized communication with protected application and database resources.
- **Privacy-Aware Logging:** Anonymizes selected network identifiers while retaining experimental evidence.
- **Security Analytics Dashboard:** Presents security decisions, risk classifications, attack scenarios, and experimental outcomes.

## 3. Experimental Architecture & Methodology

The project follows a three-phase comparative experimental methodology, using Mininet to simulate legitimate users, unknown hosts, and protected resources.

![ZTNA Simulation Architecture](docs/images/ztna-architecture.png)

*Figure 1. High-level architecture of the three-phase security simulation.*

| Phase | Security Model | Evaluation Focus |
|---|---|---|
| 1 | Baseline | Unrestricted network behavior |
| 2 | Traditional Firewall | Filtering, logging, and rate limiting |
| 3 | Zero Trust | Policy-based decisions and risk-based containment |

The Zero Trust topology includes four principal network roles: **USER, UNKNOWN, APP_SERVER, and DATABASE**. Legitimate communication is permitted according to predefined policies, while unauthorized requests and suspicious behavior are restricted.

### Zero Trust Decision Pipeline

**Identity → Behavior → Risk → Policy → Enforcement → Evidence**

Each access request is evaluated using network role mappings, behavioral indicators, and risk classification before a policy decision is enforced and recorded.

## 4. Experimental Results & Key Findings

The evaluation demonstrated how security behavior changed across the three experimental phases.

| Security Scenario | Baseline | Firewall | Zero Trust |
|---|---|---|---|
| Legitimate HTTP access | Allowed | Allowed | Allowed |
| Unauthorized HTTP access | Allowed | Allowed | Denied |
| Port scanning | Successful | Slowed | Quarantined |
| Subnet scanning | Successful | Discovery remained possible | Quarantined |
| Unauthorized lateral movement | Allowed | Allowed | Denied |
| SYN flood | Unrestricted | Rate-limited | Quarantined |

### Phase 3 — Policy Validation

All **11 predefined Zero Trust test scenarios passed**, with actual decisions matching their expected outcomes.

| Metric | Result |
|---|---:|
| Total Tests | 11 |
| Passed / Failed | 11 / 0 |
| ALLOW Decisions | 2 |
| DENY Decisions | 5 |
| QUARANTINE Decisions | 4 |

**Key findings:**

- Legitimate USER → APP_SERVER and APP_SERVER → DATABASE communication was permitted.
- Unauthorized access to protected resources and unnecessary internal communication was denied.
- Scanning and SYN flood scenarios triggered QUARANTINE decisions.
- A normally trusted user performing port scanning was quarantined, demonstrating that predefined trust does not override suspicious behavior.

These results demonstrate the effectiveness of the implemented policies within the tested simulation scenarios, rather than universal protection against cyberattacks.

## 5. Security Analytics Dashboard

A Flask-based dashboard provides visual analysis of the three experimental phases, including access decisions, risk scores, expected versus actual outcomes, attack narratives, and supporting logs.

![ZTNA Security Dashboard](docs/images/ztna-dashboard-overview.png)

*Figure 2. Security dashboard showing phase comparison and Zero Trust validation results: 11 PASS, 0 FAIL, 2 ALLOW, 5 DENY, and 4 QUARANTINE.*

**Note:** The dashboard's security effectiveness bars are illustrative comparisons, not experimentally calculated effectiveness percentages.

## 6. Technologies & Implementation

**Technologies:** Python 3, Mininet, Ubuntu/Linux, iptables, Flask, HTML/CSS, Nmap, hping3, tcpdump, and CSV-based logging.

### Project Structure

```text
ZTNA-Security-Simulation/
├── code/
│   ├── phase1_baseline/
│   ├── phase2_firewall/
│   └── phase3_ztna/
├── dashboard/
│   ├── app.py
│   ├── static/
│   └── templates/
├── logs/
│   ├── anonymized/
│   └── phase3_summary.csv
├── docs/
│   └── images/
├── README.md
└── .gitignore
```

### How to Run

A Linux environment with Python 3, Mininet, iptables, Nmap, hping3, tcpdump, curl, and Flask is required.

**Phase 1 — Baseline**

```bash
cd code/phase1_baseline
sudo python3 baseline_phase.py
```

**Phase 2 — Traditional Firewall**

```bash
cd code/phase2_firewall
sudo python3 run_firewall_phase.py
```

**Phase 3 — Zero Trust**

```bash
cd code/phase3_ztna
sudo bash run_phase3.sh
```

**Security Dashboard**

From the repository root:

```bash
python3 -m pip install flask
cd dashboard
python3 app.py
```

Open the local address provided by Flask.

*The project was developed in a controlled Linux simulation environment. Reproduction on a fresh installation may require additional dependency configuration and network setup and has not yet been fully revalidated.*

## 7. Research Contribution

The project provides a practical experimental framework for comparing baseline, firewall, and Zero Trust security architectures.

Its main contribution is the integration of **role-aware access control, behavioral detection, cumulative risk scoring, explainable policy decisions, automated threat containment, and privacy-aware evidence collection** within a comparative network security experiment.

The work emphasizes how access decisions are determined and enforced, supported by observed experimental outcomes.

## 8. Limitations & Future Research

This implementation is an academic prototype rather than a production-ready enterprise security platform. Identity evaluation relies on predefined network role mappings, and risk classification uses rule-based scoring rather than machine learning.

The evaluation is limited to a small simulated topology and selected attack scenarios.

Future research could extend the framework through authenticated identity providers, device posture assessment, adaptive security policies, machine-learning-assisted anomaly detection, larger topologies, and quantitative performance benchmarking.

## 9. Academic Context

**Project:** Design, Simulation, and Analysis of a Zero Trust Network Access (ZTNA) Architecture

**Author:** Sahar Effat Mahmoud Ali

**Institution:** Arab Open University — Egypt

**Degree:** BSc in Information Technology and Computing

**Academic Year:** 2025–2026

**Research Areas:** Cybersecurity, Network Security, Zero Trust Architecture, Access Control, Behavioral Threat Detection, and Security Analytics.

All security experiments were performed within a controlled simulation environment for academic research and educational purposes.
