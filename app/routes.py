from flask import Blueprint, render_template, request, jsonify
from app.scanner import NetworkScanner
from threading import Thread

main = Blueprint('main', __name__)
scanner = NetworkScanner()

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target', '')
    ports = data.get('ports', '')
    options = data.get('options', {})
    
    if not target:
        return jsonify({'success': False, 'error': 'Target is required'})
    
    # Start scan in background
    Thread(
        target=scanner.start_scan,
        args=(target, ports, options),
        daemon=True
    ).start()
    
    return jsonify({'success': True, 'message': 'Scan started'})

@main.route('/scan_status')
def scan_status():
    return jsonify(scanner.get_status())

@main.route('/scan_results')
def scan_results():
    return jsonify(scanner.get_results())
