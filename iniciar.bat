@echo off
start "Agente SOC" c:\agente-seguranca-soc\venv\Scripts\python.exe c:\agente-seguranca-soc\agente.py
timeout /t 3
start "Dashboard SOC" c:\agente-seguranca-soc\venv\Scripts\python.exe c:\agente-seguranca-soc\dashboard.py