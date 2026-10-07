# AI-Based APT Detection and Defense Prioritization System
**Project Architecture and Component Explanation**

This document serves as a comprehensive explanation of the entire system built so far. It explains the purpose of each file, the external libraries used, and how the data flows from the endpoint (the victim's computer) to the backend server (the central security brain) in plain, human-readable language.

---

## 1. System Overview

The project is split into two major halves:
1. **The Endpoint Agent:** A lightweight script running on the monitored computer. Its only job is to spy on running processes, quickly flag obvious suspicious behaviors, and securely send that data away.
2. **The Backend Server:** A central intelligence hub that receives data from the agent, saves it to a database, analyzes it against the MITRE ATT&CK framework, and generates actionable "Alerts" for a security analyst.

---

## 2. The Endpoint Agent (Client-Side)

### Libraries & Frameworks Used:
* **`psutil` (Process and System Utilities):** A library that safely talks to the Windows OS to get live data about running programs (like their Process ID, command lines, and CPU usage) without crashing the system.
* **`requests`:** The standard Python library for sending data over the internet using HTTP. It is used to POST the JSON data to the backend.
* **`re` (Regular Expressions):** A text-matching library. It allows us to find complex, hidden patterns in command lines (like catching `powershell -w hidden` no matter how many spaces the attacker uses).

### How the Code Works:

* **`core/monitor.py` (The Process Monitor):**
  This file contains the `ProcessMonitor` class. It acts as the "eyes" of the agent. It uses `psutil.process_iter()` to loop over every single program currently running on the computer. 
  It uses a concept called **Differential Tracking**: It remembers the Process IDs (PIDs) it saw in the last loop. When it loops again 5 seconds later, it compares the new list to the old list. Anything not in the old list is flagged as a "new process".

* **`core/detectors.py` (The Pre-Screener):**
  Before bothering the backend, the agent does a quick check. This file contains a list of known bad actor names (like `mimikatz.exe` or `nc.exe`), bad folder paths (like temporary folders where malware hides), and bad commands (like `cmd.exe /c`). It checks every new process against these rules.

* **`agent.py` (The Orchestrator):**
  This is the main script you run. It acts as the manager. It tells the monitor to get new processes, passes them to the detector, and if the detector finds something suspicious, it uses the `requests.post()` function to package the data into a structured JSON payload and send it to the backend's URL.

---

## 3. The Backend Server (Central Hub)

### Libraries & Frameworks Used:
* **`FastAPI`:** A modern, incredibly fast web framework for building APIs in Python. It acts as the receptionist, listening for incoming data from the agent and serving data out to web browsers.
* **`Uvicorn`:** The web server that actually runs the FastAPI application and handles the raw internet traffic.
* **`SQLAlchemy`:** An Object-Relational Mapper (ORM). Instead of writing raw, complex SQL queries to save data to a database, SQLAlchemy lets us define our database tables as standard Python classes.
* **`Pydantic`:** A data validation library. It acts as the bouncer for the database. Before any data from the agent is saved, Pydantic checks the JSON to ensure it perfectly matches the required structure (e.g., ensuring the Process ID is an integer, not text).
* **`SQLite`:** A lightweight, file-based database used for development. (It can be swapped for PostgreSQL in production seamlessly thanks to SQLAlchemy).

### How the Code Works:

* **`app/models/` (The Database Structure):**
  - `event.py`: Defines the `AgentEvent` table. It tells the database to create columns for the timestamp, process name, command line, etc.
  - `alert.py`: Defines the `DetectionAlert` table. This stores the final, human-readable alerts along with their MITRE classifications.

* **`app/schemas/` (The Data Bouncers):**
  Files here (like `event.py` and `alert.py`) use Pydantic `BaseModel` classes to define the strict JSON shape required for incoming API requests and outgoing API responses.

* **`app/api/routes/` (The API Endpoints):**
  - `events.py`: The `POST /api/v1/events` endpoint. When the agent sends data, this route receives it, asks SQLAlchemy to save it to the database, and then instantly triggers the Detection Engine.
  - `alerts.py`: The `GET /api/v1/alerts` endpoint. When a human opens their dashboard, this route fetches all the saved alerts from the database and sends them back.

* **`app/services/` (The Intelligence Engines):**
  - **`mitre_service.py`**: Contains a dictionary of known attacker strategies categorized by the MITRE ATT&CK framework (a globally recognized encyclopedia of hacker tactics). 
  - **`detection_service.py`**: The true brain of the backend. When an event is received, this file examines it. If it sees `cmd.exe /c`, it generates a formal "DetectionAlert". It assigns a human-friendly name ("Suspicious Command Shell Execution"), sets a severity level ("medium"), and uses the `mitre_service` to attach the exact MITRE ID (T1059.003).

* **`app/main.py` (The Startup File):**
  This file ties the backend together. It starts FastAPI, connects to the database, creates the tables, and registers all the API routes so Uvicorn can serve them to the world.

---

## 4. The Flow of Data (Summary)

1. A hacker opens a hidden PowerShell window on the computer.
2. `agent.py` loops, and `core/monitor.py` spots the new PowerShell process.
3. `core/detectors.py` flags the command line as suspicious because it contains the word "hidden".
4. `agent.py` wraps this data into JSON and sends a `POST` request to the Backend.
5. The Backend's FastAPI server (`routes/events.py`) receives the JSON.
6. Pydantic validates the JSON structure.
7. SQLAlchemy saves the raw event to the `AgentEvent` database table.
8. `services/detection_service.py` kicks in, analyzes the event, and realizes it's an evasion attempt.
9. It asks `services/mitre_service.py` for the correct MITRE tag (T1564.003).
10. SQLAlchemy saves this structured, high-level alert to the `DetectionAlert` database table.
11. A human analyst accesses `GET /api/v1/alerts` and reads the fully summarized, human-readable threat report.
