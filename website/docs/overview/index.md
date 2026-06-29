# About

**Mecha Hayabusa** connects the Windows event log analysis tool **Hayabusa** to large language models (LLMs) through the **Model Context Protocol (MCP)**, enabling natural-language driven digital forensics and threat hunting. Analysts can investigate CSV-based Windows event log datasets using capabilities such as MITRE ATT&CK tactic analysis, IOC extraction, lateral movement correlation, PowerShell decoding, and host-centric timeline analysis.

Hayabusa CSV timelines are automatically converted into a local **DuckDB** database, allowing LLMs to perform fast, structured analysis over large log datasets. The system provides capabilities including dataset switching and profiling, read-only SQL execution, cross-field search, rule title aggregation, time-window summarization, host timeline analysis, `Details` field parsing, IOC extraction, Base64-encoded PowerShell decoding, and lateral movement correlation.

Mecha Hayabusa also includes a dedicated **investigation skill** that standardizes the DFIR workflow and supports structured incident report generation in **Japanese or English**.

The key innovation of Mecha Hayabusa is enabling an LLM to execute a **structured DFIR investigation workflow through MCP**, rather than acting as a simple search interface. This approach supports the full investigation lifecycle—from dataset triage and hypothesis development to attack-phase analysis, host-level investigation, lateral movement correlation, and final report generation—while improving consistency and efficiency for incident responders.
