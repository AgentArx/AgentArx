"""Flask web application for AgentArx"""

import json
import os
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from flask import Flask, jsonify, request, Response, send_from_directory
from flask_cors import CORS

from ..orchestrator import AgentArxOrchestrator
from ..config.settings import settings


# Global state for running assessments
running_assessments: Dict[str, Dict[str, Any]] = {}
orchestrator = None


def create_app():
    """Application factory for production WSGI servers"""
    global orchestrator
    
    app = Flask(__name__, static_folder='static', static_url_path='')
    CORS(app)
    
    # Initialize orchestrator if not already done
    if orchestrator is None:
        orchestrator = AgentArxOrchestrator()
    
    # Register routes
    register_routes(app)
    
    return app


def register_routes(app):
    """Register all routes on the Flask app"""
    
    @app.route('/')
    def index():
        """Serve main HTML page"""
        return send_from_directory(app.static_folder, 'index.html')

    
    @app.route('/favicon.ico')
    def favicon():
        """Serve favicon"""
        return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/x-icon')

    
    @app.route('/api/config/status', methods=['GET'])
    def config_status():
        """Check configuration status"""
        errors = []
        
        # Check OpenAI configuration
        try:
            settings.validate()
        except ValueError as e:
            errors.append(str(e))
        
        # Check LLM provider availability
        if not orchestrator.llm_provider.is_available():
            errors.append("LLM provider not available. Check OPENAI_API_KEY.")
        
        return jsonify({
            'configured': len(errors) == 0,
            'errors': errors
        })


    @app.route('/api/reporter/status', methods=['GET'])
    def reporter_status():
        """Get reporter type and configuration status"""
        return jsonify({
            'reporter_type': settings.reporter_type,
            'reporter_name': orchestrator.reporter.get_name(),
            'configured': orchestrator.reporter.is_configured()
        })


    @app.route('/api/scenarios', methods=['GET'])
    def list_scenarios():
        """Get list of available attack scenarios"""
        scenarios = get_scenario_files()
        return jsonify({
            'scenarios': scenarios,
            'count': len(scenarios)
        })


    @app.route('/api/run/<scenario_id>', methods=['POST'])
    def run_scenario(scenario_id: str):
        """Start running an attack scenario"""
        # Get export_findings parameter from request
        data = request.get_json() or {}
        export_findings = data.get('export_findings', False)
        
        # Validate configuration before starting
        try:
            settings.validate()
        except ValueError as e:
            return jsonify({
                'success': False,
                'error': f'Configuration error: {str(e)}. Please check your .env file and ensure OPENAI_API_KEY is set.'
            }), 400
        
        # Verify LLM provider is available
        if not orchestrator.llm_provider.is_available():
            return jsonify({
                'success': False,
                'error': 'LLM provider not available. Check OPENAI_API_KEY in your .env file.'
            }), 400
        
        # Check if scenario exists
        scenario_file = Path("attack_scenarios") / f"{scenario_id}.json"
        if not scenario_file.exists():
            return jsonify({
                'success': False,
                'error': f'Scenario not found: {scenario_id}'
            }), 404
        
        # Create session ID
        session_id = f"session_{scenario_id}"
        
        # Check if already running
        if session_id in running_assessments and running_assessments[session_id]['status'] == 'running':
            return jsonify({
                'success': False,
                'error': 'Scenario is already running',
                'session_id': session_id,
                'status': 'running'
            }), 409
        
        # Initialize assessment state
        running_assessments[session_id] = {
            'scenario_id': scenario_id,
            'status': 'starting',
            'start_time': None,
            'end_time': None,
            'result': None,
            'error': None
        }
        
        # Start assessment in background thread
        thread = threading.Thread(
            target=run_assessment_thread,
            args=(scenario_id, session_id, export_findings),
            daemon=True
        )
        thread.start()
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'status': 'starting',
            'message': f'Started assessment for {scenario_id}'
        })


    @app.route('/api/status/<session_id>', methods=['GET'])
    def get_status(session_id: str):
        """Get status of a running or completed assessment"""
        if session_id not in running_assessments:
            return jsonify({
                'success': False,
                'error': 'Session not found'
            }), 404
        
        assessment = running_assessments[session_id]
        
        response = {
            'success': True,
            'session_id': session_id,
            'scenario_id': assessment['scenario_id'],
            'status': assessment['status'],
            'start_time': assessment.get('start_time'),
            'end_time': assessment.get('end_time'),
        }
        
        if assessment['status'] == 'failed':
            response['error'] = assessment.get('error')
        
        if assessment['status'] == 'completed':
            response['result'] = assessment.get('result')
        
        return jsonify(response)


    @app.route('/api/stream/<session_id>')
    def stream_logs(session_id: str):
        """Stream logs using Server-Sent Events"""
        
        def generate():
            """Generator function that yields log lines"""
            try:
                log_file = Path("logs") / f"{session_id}.log"
                
                # Send initial connection message
                yield f"data: {json.dumps({'type': 'log', 'message': 'Connecting to log stream...'})}\n\n"
                
                # Wait for log file to be created (up to 30 seconds)
                wait_time = 0
                while not log_file.exists() and wait_time < 30:
                    time.sleep(1)
                    wait_time += 1
                
                if not log_file.exists():
                    error_msg = f"Log file not found after {wait_time} seconds: {log_file}"
                    print(f"SSE Error: {error_msg}")
                    yield f"data: {json.dumps({'type': 'error', 'message': error_msg})}\n\n"
                    return
                
                yield f"data: {json.dumps({'type': 'log', 'message': f'Log file found, streaming from {log_file}'})}\n\n"
                
                # Start tailing the file
                last_heartbeat = time.time()
                last_size = 0
                
                with open(log_file, 'r', encoding='utf-8') as f:
                    # Send existing content
                    existing_content = f.read()
                    if existing_content:
                        for line in existing_content.splitlines():
                            yield f"data: {json.dumps({'type': 'log', 'message': line})}\n\n"
                    
                    last_size = f.tell()
                    
                    # Keep tailing new content
                    while True:
                        # Check for new content
                        f.seek(last_size)
                        new_content = f.read()
                        
                        if new_content:
                            for line in new_content.splitlines():
                                yield f"data: {json.dumps({'type': 'log', 'message': line})}\n\n"
                            last_size = f.tell()
                            last_heartbeat = time.time()
                        else:
                            # Check if assessment is complete
                            if session_id in running_assessments:
                                status = running_assessments[session_id]['status']
                                if status in ['completed', 'failed']:
                                    # Send completion message
                                    yield f"data: {json.dumps({'type': 'status', 'status': status})}\n\n"
                                    break
                            
                            # Send heartbeat every 15 seconds to keep connection alive
                            current_time = time.time()
                            if current_time - last_heartbeat > 15:
                                yield f": heartbeat\n\n"
                                last_heartbeat = current_time
                            
                            # No new data, wait a bit
                            time.sleep(0.5)
            
            except GeneratorExit:
                # Client disconnected, clean up silently
                pass
            except Exception as e:
                # Log server-side errors
                import traceback
                error_trace = traceback.format_exc()
                print(f"SSE Stream Error: {error_trace}")
                try:
                    yield f"data: {json.dumps({'type': 'error', 'message': f'Stream error: {str(e)}'})}\n\n"
                except:
                    pass
        
        response = Response(generate(), mimetype='text/event-stream')
        response.headers['Cache-Control'] = 'no-cache'
        response.headers['X-Accel-Buffering'] = 'no'
        return response


    @app.route('/api/results/<session_id>', methods=['GET'])
    def get_results(session_id: str):
        """Get complete results for a session"""
        # Try to load from results directory
        scenario_id = session_id.replace('session_', '')
        result_file = Path("results") / scenario_id / "report.json"
        
        if not result_file.exists():
            return jsonify({
                'success': False,
                'error': 'Results not found'
            }), 404
        
        with open(result_file, 'r') as f:
            results = json.load(f)
        
        return jsonify({
            'success': True,
            'results': results
        })


    @app.route('/api/config/env', methods=['GET'])
    def get_env_config():
        """Get environment variables for editing"""
        # .env file is in project root - navigate from this file's location
        app_root = Path(__file__).resolve().parent.parent.parent.parent
        env_file = app_root / ".env"
        
        if not env_file.exists():
            return jsonify({
                'success': False,
                'error': 'Environment file not found'
            }), 404
        
        try:
            with open(env_file, 'r') as f:
                content = f.read()
            
            # Parse .env file preserving comments
            variables = []
            lines = content.split('\n')
            
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                    
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Detect sensitive fields
                    is_sensitive = any(s in key.upper() for s in ['KEY', 'TOKEN', 'PASSWORD', 'SECRET'])
                    
                    variables.append({
                        'key': key,
                        'value': value,
                        'is_sensitive': is_sensitive
                    })
            
            return jsonify({
                'success': True,
                'variables': variables,
                'raw_content': content
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Failed to read .env file: {str(e)}'
            }), 500


    @app.route('/api/config/env', methods=['POST'])
    def save_env_config():
        """Save environment variables"""
        # .env file is in project root - navigate from this file's location
        app_root = Path(__file__).resolve().parent.parent.parent.parent
        env_file = app_root / ".env"
        
        try:
            data = request.get_json()
            variables = data.get('variables', [])
            
            if not variables:
                return jsonify({
                    'success': False,
                    'error': 'No variables provided'
                }), 400
            
            # Read current .env to preserve comments and structure
            current_content = ""
            if env_file.exists():
                with open(env_file, 'r') as f:
                    current_content = f.read()
            
            # Create backup
            if env_file.exists():
                backup_file = env_file.with_suffix('.env.backup')
                with open(backup_file, 'w') as f:
                    f.write(current_content)
            
            # Build new content preserving comments
            new_lines = []
            var_dict = {v['key']: v['value'] for v in variables}
            processed_keys = set()
            
            for line in current_content.split('\n'):
                stripped = line.strip()
                
                # Preserve comments and empty lines
                if not stripped or stripped.startswith('#'):
                    new_lines.append(line)
                    continue
                
                # Update existing variables
                if '=' in line:
                    key = line.split('=', 1)[0].strip()
                    if key in var_dict:
                        new_lines.append(f"{key}={var_dict[key]}")
                        processed_keys.add(key)
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            # Add any new variables not in original file
            for var in variables:
                if var['key'] not in processed_keys:
                    new_lines.append(f"{var['key']}={var['value']}")
            
            # Write new content
            with open(env_file, 'w') as f:
                f.write('\n'.join(new_lines))
            
            return jsonify({
                'success': True,
                'message': 'Environment configuration saved successfully'
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Failed to save .env file: {str(e)}'
            }), 500


    @app.route('/api/config/prompts/<agent_name>', methods=['GET'])
    def get_prompt_config(agent_name: str):
        """Get agent prompt configuration"""
        valid_agents = ['recon', 'attack', 'analyze', 'report']
        
        if agent_name not in valid_agents:
            return jsonify({
                'success': False,
                'error': f'Invalid agent name. Must be one of: {", ".join(valid_agents)}'
            }), 400
        
        prompt_file = Path(f"src/agentarx/config/prompts/{agent_name}_agent.yaml")
        
        if not prompt_file.exists():
            return jsonify({
                'success': False,
                'error': f'Prompt file not found: {prompt_file}'
            }), 404
        
        try:
            with open(prompt_file, 'r') as f:
                content = f.read()
            
            return jsonify({
                'success': True,
                'content': content,
                'agent_name': agent_name
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Failed to read prompt file: {str(e)}'
            }), 500


    @app.route('/api/config/prompts/<agent_name>', methods=['POST'])
    def save_prompt_config(agent_name: str):
        """Save agent prompt configuration"""
        valid_agents = ['recon', 'attack', 'analyze', 'report']
        
        if agent_name not in valid_agents:
            return jsonify({
                'success': False,
                'error': f'Invalid agent name. Must be one of: {", ".join(valid_agents)}'
            }), 400
        
        prompt_file = Path(f"src/agentarx/config/prompts/{agent_name}_agent.yaml")
        
        try:
            data = request.get_json()
            content = data.get('content', '')
            
            if not content:
                return jsonify({
                    'success': False,
                    'error': 'No content provided'
                }), 400
            
            # Validate YAML syntax
            import yaml
            try:
                parsed = yaml.safe_load(content)
            except yaml.YAMLError as e:
                return jsonify({
                    'success': False,
                    'error': f'Invalid YAML syntax: {str(e)}'
                }), 400
            
            # Validate required fields
            required_fields = ['agent_name', 'system_prompt', 'prompt_templates']
            missing = [f for f in required_fields if f not in parsed]
            
            if missing:
                return jsonify({
                    'success': False,
                    'error': f'Missing required fields: {", ".join(missing)}'
                }), 400
            
            # Create backup
            if prompt_file.exists():
                backup_file = prompt_file.with_suffix('.yaml.backup')
                with open(prompt_file, 'r') as f:
                    backup_content = f.read()
                with open(backup_file, 'w') as f:
                    f.write(backup_content)
            
            # Save new content
            with open(prompt_file, 'w') as f:
                f.write(content)
            
            return jsonify({
                'success': True,
                'message': f'{agent_name.title()} Agent prompt saved successfully'
            })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Failed to save prompt file: {str(e)}'
            }), 500


    @app.route('/api/config/prompts/<agent_name>/reset', methods=['POST'])
    def reset_prompt_config(agent_name: str):
        """Reset agent prompt to backup/default"""
        valid_agents = ['recon', 'attack', 'analyze', 'report']
        
        if agent_name not in valid_agents:
            return jsonify({
                'success': False,
                'error': f'Invalid agent name. Must be one of: {", ".join(valid_agents)}'
            }), 400
        
        prompt_file = Path(f"src/agentarx/config/prompts/{agent_name}_agent.yaml")
        backup_file = prompt_file.with_suffix('.yaml.backup')
        
        try:
            # Use backup if exists, otherwise keep current (it's the default)
            if backup_file.exists():
                with open(backup_file, 'r') as f:
                    default_content = f.read()
                
                with open(prompt_file, 'w') as f:
                    f.write(default_content)
                
                return jsonify({
                    'success': True,
                    'message': f'{agent_name.title()} Agent prompt reset to default',
                    'content': default_content
                })
            else:
                # No backup exists, current file is default
                with open(prompt_file, 'r') as f:
                    content = f.read()
                
                return jsonify({
                    'success': True,
                    'message': 'Already at default (no backup found)',
                    'content': content
                })
            
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Failed to reset prompt file: {str(e)}'
            }), 500


    @app.route('/api/config/target', methods=['GET'])
    def get_target_config():
        """Get current target configuration"""
        config_file = Path("src/agentarx/config/target_config.json")
        
        if not config_file.exists():
            return jsonify({
                'success': False,
                'error': 'Target configuration file not found'
            }), 404
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            return jsonify({
                'success': True,
                'config': config
            })
        except json.JSONDecodeError as e:
            return jsonify({
                'success': False,
                'error': f'Invalid JSON in config file: {str(e)}'
            }), 500
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Failed to read config: {str(e)}'
            }), 500


    @app.route('/api/config/target', methods=['POST'])
    def save_target_config():
        """Save target configuration"""
        config_file = Path("src/agentarx/config/target_config.json")
        
        try:
            # Get JSON from request
            new_config = request.get_json()
            
            if not new_config:
                return jsonify({
                    'success': False,
                    'error': 'No configuration data provided'
                }), 400
            
            # Validate required fields
            required_fields = ['target_id', 'name', 'network']
            missing_fields = [f for f in required_fields if f not in new_config]
            
            if missing_fields:
                return jsonify({
                    'success': False,
                    'error': f'Missing required fields: {", ".join(missing_fields)}'
                }), 400
            
            # Validate network object
            if 'network' in new_config:
                network_required = ['url']
                network_missing = [f for f in network_required if f not in new_config['network']]
                if network_missing:
                    return jsonify({
                        'success': False,
                        'error': f'Missing required network fields: {", ".join(network_missing)}'
                    }), 400
            
            # Create backup of existing config
            if config_file.exists():
                backup_file = config_file.with_suffix('.json.backup')
                with open(config_file, 'r') as f:
                    backup_content = f.read()
                with open(backup_file, 'w') as f:
                    f.write(backup_content)
            
            # Save new config
            with open(config_file, 'w') as f:
                json.dump(new_config, f, indent=2)
            
            return jsonify({
                'success': True,
                'message': 'Configuration saved successfully'
            })
            
        except json.JSONDecodeError as e:
            return jsonify({
                'success': False,
                'error': f'Invalid JSON: {str(e)}'
            }), 400
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Failed to save config: {str(e)}'
            }), 500


# Initialize Flask app for direct execution
app = create_app()


def get_scenario_files():
    """Get list of attack scenario JSON files"""
    scenario_dir = Path("attack_scenarios")
    if not scenario_dir.exists():
        return []
    
    scenarios = []
    for json_file in sorted(scenario_dir.glob("*.json")):
        scenario_id = json_file.stem
        
        # Try to parse JSON to get name
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                name = data.get('name', scenario_id)
                category = data.get('category', 'Unknown')
        except Exception:
            name = scenario_id
            category = 'Unknown'
        
        # Check if there's a running or completed status
        status = "ready"
        session_id = f"session_{scenario_id}"
        
        if session_id in running_assessments:
            status = running_assessments[session_id]['status']
        
        scenarios.append({
            'id': scenario_id,
            'name': name,
            'category': category,
            'status': status,
            'file': json_file.name
        })
    
    return scenarios


def run_assessment_thread(scenario_id: str, session_id: str, export_findings: bool = False):
    """Run assessment in background thread"""
    try:
        # Update status
        running_assessments[session_id]['status'] = 'running'
        running_assessments[session_id]['start_time'] = datetime.now().isoformat()
        
        # Get scenario file path
        scenario_file = Path("attack_scenarios") / f"{scenario_id}.json"
        
        # Run assessment
        result = orchestrator.execute_assessment(
            attack_json_path=str(scenario_file),
            export_findings=export_findings
        )
        
        # Update status
        running_assessments[session_id]['status'] = 'completed'
        running_assessments[session_id]['end_time'] = datetime.now().isoformat()
        running_assessments[session_id]['result'] = result
        
    except Exception as e:
        # Log the error to console and file
        import traceback
        error_msg = f"\n{'='*60}\nERROR: {str(e)}\n{'='*60}\n"
        print(error_msg)
        print(traceback.format_exc())
        
        # Update status on error
        running_assessments[session_id]['status'] = 'failed'
        running_assessments[session_id]['error'] = str(e)
        running_assessments[session_id]['end_time'] = datetime.now().isoformat()


def run_server():
    """Start the Flask development server"""
    print(f"\n{'='*60}")
    print("AgentArx Web UI (Development Server)")
    print(f"{'='*60}")
    print(f"Starting server at http://{settings.web_host}:{settings.web_port}")
    print(f"Press Ctrl+C to stop")
    print(f"{'='*60}\n")
    
    app.run(
        host=settings.web_host,
        port=settings.web_port,
        debug=False,
        threaded=True
    )


if __name__ == '__main__':
    run_server()
