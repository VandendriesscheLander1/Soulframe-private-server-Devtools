@cd /d "%~dp0soulframe-private-server"
@python -c "import cryptography" 2>nul || python -m pip install cryptography
@python tools\dummy_server.py %*
@pause
