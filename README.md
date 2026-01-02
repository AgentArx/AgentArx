
# AgentArx - Secure Your Agentic Systems
AgentArx is a cooperative multi-agent system for automated security testing using LLMs. Agents work together autonomously: Reconnaissance → Analysis → Attack → Report.


---


## Quick Start

1. Install requirements.txt
2. Update configs: see [configuration files section](#configuration-files)
3. Run either the web UI or command line (see below)

### Web UI
```bash
# Production (gunicorn):
gunicorn --pythonpath src -w 2 -b 127.0.0.1:5000 --timeout 600 --worker-class gevent 'agentarx.web.app:create_app()'

# Development (default port 5000, or update WEB_PORT in .env):
PYTHONPATH=src python -m agentarx.web
# Open http://127.0.0.1:5000 in your browser
```

### Command Line
```bash
cd src
python -m agentarx.main --file ../attack_scenarios/MAS_2025_00001__Prompt_Inject_Data_Leakage.json
```


---


## Run in Docker
```bash
docker build -t agentarx:latest .

# Run web UI (access at http://localhost:5000):
docker run -it --rm \
  --name agentarx_web \
  --network host \
  -p 5000:5000 \
  --env-file .env \
  -v $(pwd)/.env:/app/.env \
  -v $(pwd)/src:/app/src \
  -v $(pwd)/attack_scenarios:/app/attack_scenarios \
  -v $(pwd)/results:/app/results \
  -v $(pwd)/logs:/app/logs \
  agentarx:latest

python -m agentarx.web  # or gunicorn command
```


---


## Sample Commands
```
# Test configuration and connectivity:
cd src
python -m agentarx.main --test-config

# Execute attack definition:
python -m agentarx.main --file ./attack_scenarios/MAS_2025_00001__Prompt_Inject_Data_Leakage.json

# Execute with findings export to configured reporter:
python -m agentarx.main --file ./attack_scenarios/MAS_2025_00001__Prompt_Inject_Data_Leakage.json --export-findings

# Start from a specific phase (using previously saved results):
# Valid values: analysis, attack, report
python -m agentarx.main --file ./attack_scenarios/MAS_2025_00001__Prompt_Inject_Data_Leakage.json --start-from report --export-findings
# Possible start-from args: analysis attack, report

# View all available options:
python -m agentarx.main --help

# Note: Target system is configured in src/agentarx/config/target_config.json
```


---


## Configuration Files

Remember to remove any `.example` suffix for your copy of the config file.
Please update `.env` and 'target_config.json`.  Changing promp yamls is optional.

- **`.env`** - Environment variables (LLM API keys, reporter settings, MCP server URL)
- **`src/agentarx/config/target_config.json`** - Target system details (URL, credentials, schema)
  - Only `target_id`, `name`, `network`, `url` are required.  Can delete rest.
  - Sample minimal target config
    '''JSON
    {
      "target_id": "my_target_001",
      "name": "My Test Target",
      "network": {
        "url": "http://localhost:8080"
      }
    }
    '''
- **`src/agentarx/config/prompts/*.yaml`** - Agent system prompts (recon, analyze, attack, report)


---


## Demo
See `./demo/README.md` for spinning up:
1. Target test system, AnythingLLM app
2. Sample vulnerability tracking system, Defect Dojo

