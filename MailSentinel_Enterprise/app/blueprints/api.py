from flask import Blueprint, request, jsonify
from app.services.analyzer import EmailAnalyzerService

api_bp = Blueprint('api', __name__)

@api_bp.route('/analyze', methods=['POST'])
def api_analyze():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get('raw_content'), str):
        return jsonify({'error': 'Send JSON containing a raw_content string.'}), 400
    try:
        return jsonify(EmailAnalyzerService.analyze_raw_content(data['raw_content'])), 200
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception:
        return jsonify({'error': 'Analysis failed. Check server logs.'}), 500
