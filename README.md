# NETGUARD – Unauthorized Network Communication & Anomaly Detection System

## 1. Project Overview

NETGUARD is a prototype network security monitoring system designed to identify unauthorized devices and detect unusual communication behavior.

The system verifies devices using a unique device token before allowing them to communicate with the protected server. It also monitors the request activity of authorized devices and identifies unusually high request rates as suspicious behavior.

NETGUARD provides a centralized dashboard where authorized devices, network activity, and security alerts can be viewed.

---

## 2. Problem Statement

In shared network environments such as colleges and institutions, many devices may communicate with network services at the same time. It can be difficult to identify unauthorized devices and monitor whether authorized devices are behaving unusually.

NETGUARD addresses this problem by combining:

- Device authorization
- Unauthorized access detection
- Network activity monitoring
- Anomaly detection
- Security alerts
- Centralized monitoring

---

## 3. Main Features

- **Device Authorization**  
  Verifies registered devices using a unique device token.

- **Unauthorized Device Detection**  
  Identifies unregistered devices and blocks their requests.

- **Network Activity Monitoring**  
  Records communication requests made to the protected server.

- **Anomaly Detection**  
  Detects unusually high request activity within a short period.

- **Security Alerts**  
  Generates alerts for unauthorized and suspicious activities.

- **Centralized Dashboard**  
  Displays devices, network activity, and security alerts.

- **Activity Logging**  
  Stores communication and security events in the SQLite database.

---

## 4. Working Principle

The basic working flow of NETGUARD is:

```text
Client Device
      |
      v
Communication Request
      |
      v
NETGUARD Server
      |
      v
Device Token Verification
      |
      +----------------------+
      |                      |
      v                      v
Registered              Not Registered
      |                      |
      v                      v
Monitor Activity       Block Request
      |                      |
      v                      v
Normal / Suspicious      Security Alert
      |
      v
Database + Dashboard
