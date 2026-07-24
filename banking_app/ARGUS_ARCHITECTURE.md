# Project ARGUS

## Banking Deception & Detection Engine

ARGUS is the security deception and detection layer integrated into the Secure Banking App.

Its purpose is to detect suspicious activity, deploy deceptive resources, collect forensic evidence, calculate threat scores, classify attacker behaviour, and provide useful intelligence to the SOC.

## Core Objectives

- Detect automated bots and suspicious form submissions
- Deploy deceptive banking endpoints and fake resources
- Log suspicious activity in a structured format
- Track visitors across multiple interactions
- Calculate a threat score
- Classify attacker behaviour
- Build an attack timeline
- Send alerts and evidence to the SOC

## Initial Architecture

```text
Secure Banking App
│
├── Real Banking Routes
│   ├── Authentication
│   ├── Accounts
│   ├── Banking
│   └── Support
│
├── ARGUS
│   ├── Form Bot Detection
│   ├── Honeypot Endpoints
│   ├── Structured Logging
│   ├── Threat Scoring
│   ├── Attacker Profiling
│   ├── Session Timeline
│   └── SOC Alerts
│
└── SOC Dashboard