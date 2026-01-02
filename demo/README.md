
Doing a Full Demo of AgentArx


# AgentArx

See README.md in root workspace for how to start AgentArx via Docker.

```bash
# Run from root directory
gunicorn --pythonpath src -w 2 -b 127.0.0.1:5000 --timeout 600 --worker-class gevent 'agentarx.web.app:create_app()'
```


---


# Anything LLM
AnythingLLM is used as a sample test system for AgentArx to scan.

## Starting Anything LLM Service
1. `mkdir /tmp/anythingllm_storage`
2. `sudo chown -R $(id -u):$(id -g) /tmp/anythingllm_storage`
3. `cd <agentarx-workspace-root-dir>/demo`
4. `docker compose -f docker-compose-anythingllm.yml up -d`
   `docker logs -f anything-llm`
5. AnythngLLM is at http://localhost:3301 and Ollama is at http://localhost:11434

##  AnythingLLM UI Model Setup (Optional)
0. Browse to http://localhost:3301
1. Workspace Settings (left side: gear icon)
2. Chat Settings (top menu)
3. "Workspace LLM Provider" section click "Local AI" & gear symbol
4. Set below values
   - Base URL: http://ollama:11434/v1
   - Model: llama3.2:1b or qwen2.5:1.5b-instruct
     - Note: may need to wait and refresh for models to show up
   - Token context window: 1024
   - Leave rest as blank / default
5. Click "Save Settings" then click "Update Workspace"
   - In Workspace chat settings, ensure "Workspace chat model" is qwen2.5:1.5b-instruct
6. Go back to the workspace chat and try chatting

## Stopping Anything LLM Service
`docker compose -f docker-compose-anythingllm.yml down`


---


# Defect Dojo
Defect Dojo is used as a bug tracking system.

## Starting Defect Dojo
1. `cd <agentarx-workspace-root-dir>/demo`
2. `docker compose -f docker-compose-defect-dojo.yml up -d`
3. Get the admin password, either
    a. `docker compose -f docker-compose-defect-dojo.yml logs initializer | grep -i "admin password"`
	    If password shows, then log in with user "admin" and this password
    b. If password doesn't show, but you see "the admin user admin already exists", then
	    - create a new password via
		- `docker compose -f docker-compose-defect-dojo.yml exec uwsgi /bin/bash -c 'python manage.py createsuperuser'`
4. Browse to http://localhost:8080/ to log in
5. In the DefectDojo UI add details to match .env TRACKER_* variables
   a. Create Product to match TACKER_PRODUCT_NAME in .env
      - TRACKER_PRODUCT_TYPE_NAME should match product type
   b. Create Engagement to match TRACKER_ENGAGEMENT_NAME
   c. Under engagement create a Test
      - Make sure test ID matches 
   d. Update API Key
       i. Click on user profile icon (top right)
       ii. Click "API v2 Key"
       iii. Copy value "Your current API key is"
       iv. Update .env REPORTER_TOKEN with this API key
      

## Stopping Defect Dojo
`docker compose -f docker-compose-defect-dojo.yml down`
