# Design, Implementation, and Experimental Evaluation of a Zero Trust Network Access Defense System

An experimental cybersecurity framework for context-aware access control, behavioral threat detection, automated policy enforcement, and privacy-aware security analysis.

## 1. Project Overview

This project presents the design and implementation of a Zero Trust Network Access (ZTNA) defense system within a controlled, Mininet-based environment.

The framework evaluates how different network security architectures respond to legitimate access requests and simulated cyberattacks through three experimental phases:

1. Baseline Network:A flat network without additional security controls.
2. Traditional Firewall: Rule-based traffic filtering and rate limiting.
3. Zero Trust Architecture: Context-aware, risk-based access decisions with policy enforcement and threat containment.

The objective is to experimentally investigate the effectiveness of Zero Trust principles in restricting unauthorized access, limiting lateral movement, and improving security visibility.

## 2. Key Features

- Three-Phase Security Evaluation: Comparative analysis of baseline, firewall, and Zero Trust architectures.
- Context-Aware Access Control: Role-based source and destination identification combined with behavioral and policy evaluation.
- Behavioral Threat Detection: Identification of selected scanning, flooding, and unauthorized access behaviors.
- Risk-Based Decision Engine: Weighted event scoring and risk classification.
- Automated Policy Enforcement: ALLOW, DENY, and QUARANTINE decisions enforced through Linux networking rules.
- Least-Privilege Network Access: Restriction of unauthorized communication between network roles.
- Security Analytics Dashboard: Visualization of experimental outcomes, security decisions, and supporting evidence.
- Privacy-Aware Logging: Anonymization of sensitive network identifiers in collected records.

## 3. Experimental Methodology

| Phase | Security Architecture | Evaluation Focus |
|---|---|---|
| Phase 1 | Baseline | Network behavior without additional security controls |
| Phase 2 | Traditional Firewall | Impact of packet filtering and rate limiting |
| Phase 3 | Zero Trust | Context-aware access control and risk-based threat containment |

Experiments include normal traffic and selected adversarial scenarios such as port scanning, subnet scanning, SYN flooding, and lateral movement attempts.

## 4. Zero Trust Decision Pipeline

The Zero Trust implementation follows a structured decision process:

Identity → Behavior → Risk → Policy → Enforcement → Evidence

1. Identify source and destination network roles.
2. Evaluate traffic behavior and suspicious activities.
3. Calculate a weighted risk score.
4. Determine the appropriate access decision.
5. Enforce network restrictions using Linux firewall rules.
6. Record the outcome and supporting evidence.

Possible decisions include **ALLOW**, **DENY**, and **QUARANTINE**.

## 5. Technologies

- Python 3
- Mininet
- Linux / Ubuntu
- iptables
- Flask
- HTML / CSS
- tcpdump
- Nmap
- hping3
- CSV-based security analysis

## 6. Security Dashboard

The Flask-based dashboard presents:

- Comparative views of the three experimental phases
- Zero Trust access decisions
- Risk scores and classifications
- Expected versus actual test outcomes
- Attack scenario narratives
- Security logs and supporting evidence

The dashboard supports interpretation of experimental results and illustrates the relationships between threat behavior, policy decisions, and enforcement outcomes.

## 7. Research Contribution

The project combines controlled architectural comparison with an explainable, rule-based Zero Trust decision pipeline.

Its primary contribution is an experimental framework for examining how identity-associated network roles, behavioral indicators, risk classification, and policy enforcement can be integrated to restrict unauthorized access.

Privacy-aware logging further supports the analysis of security events while reducing the exposure of sensitive identifiers.

## 8. Scope and Limitations

This implementation is a controlled academic prototype rather than a production-ready enterprise ZTNA platform.

Identity evaluation uses predefined network role mappings, and risk assessment uses rule-based weighted scoring rather than a trained machine learning model.

The experimental conclusions are limited to the implemented network topology, security policies, and selected attack scenarios.

## 9. Future Research

Potential extensions include:

- Integration with authenticated identity providers
- Device posture verification
- Machine-learning-assisted anomaly detection
- Dynamic policy adaptation
- Larger and more realistic network topologies
- Expanded security and performance evaluation

## 10. Project Purpose

This project was developed as an undergraduate graduation research project in Information Technology and Computing at Arab Open University, Egypt.

Its purpose is to investigate Zero Trust security architectures through practical implementation, controlled experimentation, and comparative security analysis.

Research Areas: Cybersecurity, Network Security, Zero Trust Architecture, Access Control, Threat Detection, and Security Analytics.