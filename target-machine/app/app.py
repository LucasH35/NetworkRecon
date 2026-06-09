"""
Application web de démonstration pour la cible.
Contient des vulnérabilités intentionnelles pour les tests de sécurité.
"""

import os
import subprocess
import sqlite3
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-key-123')

# ---- MySQL connection ----
def get_db():
    import pymysql
    return pymysql.connect(
        host='127.0.0.1',
        user='webapp_user',
        password='webapp_pass',
        database='webapp',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )


# ---- Routes ----

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/users')
def api_users():
    """Liste les utilisateurs (vulnérable SQL injection via search)"""
    db = get_db()
    cursor = db.cursor()

    search = request.args.get('search', '')
    if search:
        # VULNÉRABILITÉ: SQL Injection
        query = f"SELECT id, username, email, role FROM users WHERE username LIKE '%{search}%'"
    else:
        query = "SELECT id, username, email, role FROM users"

    cursor.execute(query)
    users = [{'id': r['id'], 'username': r['username'], 'email': r['email'], 'role': r['role']} for r in cursor.fetchall()]
    db.close()
    return jsonify(users)


@app.route('/api/articles')
def api_articles():
    """Liste les articles publiés"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, title, content, author_id, views, created_at FROM articles WHERE status='published'")
    articles = [{'id': r['id'], 'title': r['title'], 'content': r['content'], 'author_id': r['author_id'], 'views': r['views'], 'created_at': str(r['created_at'])} for r in cursor.fetchall()]
    db.close()
    return jsonify(articles)


@app.route('/api/articles/<int:article_id>')
def api_article_detail(article_id):
    """Détail d'un article (vulnérable: IDOR)"""
    db = get_db()
    cursor = db.cursor()
    # VULNÉRABILITÉ: pas de vérification de propriété
    cursor.execute("SELECT id, title, content, author_id, views FROM articles WHERE id=%s", (article_id,))
    r = cursor.fetchone()
    db.close()
    if r:
        return jsonify({'id': r['id'], 'title': r['title'], 'content': r['content'], 'author_id': r['author_id'], 'views': r['views']})
    return jsonify({'error': 'Not found'}), 404


@app.route('/api/login', methods=['POST'])
def api_login():
    """Authentification (vulnérable: timing attack + pas de rate limit)"""
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    db = get_db()
    cursor = db.cursor()
    # VULNÉRABILITÉ: injection SQL + pas de hachage
    query = f"SELECT id, username, role FROM users WHERE username='{username}' AND password='{password}'"
    try:
        cursor.execute(query)
        user = cursor.fetchone()
    except Exception:
        db.close()
        return jsonify({'error': 'Database error'}), 500

    db.close()

    if user:
        return jsonify({'id': user['id'], 'username': user['username'], 'role': user['role'], 'token': 'fake-jwt-token'})
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/settings')
def api_settings():
    """Settings (vulnérable: expose secrets)"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT setting_key, setting_value FROM settings")
    settings = {r['setting_key']: r['setting_value'] for r in cursor.fetchall()}
    db.close()
    return jsonify(settings)


@app.route('/api/exec', methods=['POST'])
def api_exec():
    """Commande système (vulnérabilité RCE volontaire)"""
    data = request.get_json() or {}
    cmd = data.get('command', '')
    if cmd:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            return jsonify({'stdout': result.stdout, 'stderr': result.stderr, 'code': result.returncode})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'No command'}), 400


@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'server': 'target-lab', 'uptime': subprocess.run('uptime -p', shell=True, capture_output=True, text=True).stdout.strip()})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
