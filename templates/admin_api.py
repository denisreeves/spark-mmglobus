# admin_api.py
from flask import Blueprint, request, jsonify, render_template, session
import mysql.connector
from mysql.connector import Error
import os
import logging
import pandas as pd
import jwt
import uuid
from functools import wraps
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Tuple

# Create Blueprint for admin routes
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# JWT Secret (should match the one in main app)
JWT_SECRET = "your-secret-key"

# Database configuration from .env
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

# Connect to MySQL
def connect_db():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        return conn
    except Error as e:
        logging.error(f"Error connecting to MySQL: {e}")
        raise

# Admin auth decorator
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
        if not token:
            return jsonify({'success': False, 'message': 'Token is missing'}), 401
            
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            
            # Check if user is admin
            conn = connect_db()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM usersSpark WHERE id = %s AND email = %s", 
                          (data['user_id'], 'admin@example.com'))
            admin_user = cursor.fetchone()
            conn.close()
            
            if not admin_user:
                raise Exception("Not an admin user")
                
        except Exception as e:
            return jsonify({'success': False, 'message': 'Invalid or unauthorized token'}), 401
            
        return f(*args, **kwargs)
    
    return decorated

# Serve admin dashboard
@admin_bp.route('/')
def admin_dashboard():
    return render_template('admin/dashboard.html')

# Get users
@admin_bp.route('/users', methods=['GET'])
@admin_required
def get_users():
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        search = request.args.get('search', '')
        
        # Calculate offset
        offset = (page - 1) * limit
        
        conn = connect_db()
        cursor = conn.cursor(dictionary=True)
        
        # Query with search if provided
        if search:
            search_term = f"%{search}%"
            cursor.execute("""
                SELECT * FROM usersSpark 
                WHERE name LIKE %s OR email LIKE %s 
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """, (search_term, search_term, limit, offset))
            
            # Get total count for pagination
            cursor.execute("""
                SELECT COUNT(*) as count FROM usersSpark 
                WHERE name LIKE %s OR email LIKE %s
            """, (search_term, search_term))
        else:
            cursor.execute("""
                SELECT * FROM usersSpark 
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """, (limit, offset))
            
            # Get total count for pagination
            cursor.execute("SELECT COUNT(*) as count FROM usersSpark")
        
        # Format results
        users = [dict(row) for row in cursor.fetchall()]
        total_count = cursor.fetchone()['count']
        
        # Remove password hashes from response
        for user in users:
            if 'password' in user:
                del user['password']
        
        conn.close()
        
        return jsonify({
            'success': True,
            'users': users,
            'total': total_count,
            'page': page,
            'limit': limit,
            'pages': (total_count + limit - 1) // limit  # Ceiling division
        }), 200
        
    except Error as e:
        logging.error(f"Error fetching users: {e}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# Add/Update user
@admin_bp.route('/users', methods=['POST'])
@admin_required
def add_update_user():
    data = request.json
    
    if not data or not data.get('email') or not data.get('name'):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
    try:
        user_id = data.get('id')
        
        conn = connect_db()
        cursor = conn.cursor()
        
        # Check if email already exists (for new users)
        if not user_id:
            cursor.execute("SELECT id FROM usersSpark WHERE email = %s", (data['email'],))
            existing_user = cursor.fetchone()
            
            if existing_user:
                return jsonify({'success': False, 'message': 'Email already registered'}), 400
                
            # Import hash_password function
            from email_sender import hash_password
            
            # Create new user
            user_id = data.get('id', str(uuid.uuid4()))
            
            cursor.execute('''
            INSERT INTO usersSpark (id, name, email, password, created_at)
            VALUES (%s, %s, %s, %s, %s)
            ''', (
                user_id,
                data['name'],
                data['email'],
                hash_password(data.get('password', 'changeme')),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'User created successfully',
                'user_id': user_id
            }), 201
        
        else:
            # Update existing user
            cursor.execute("SELECT id FROM usersSpark WHERE id = %s", (user_id,))
            existing_user = cursor.fetchone()
            
            if not existing_user:
                return jsonify({'success': False, 'message': 'User not found'}), 404
            
            # Update user fields
            update_fields = []
            params = []
            
            if data.get('name'):
                update_fields.append("name = %s")
                params.append(data['name'])
                
            if data.get('email'):
                # Check if new email exists for another user
                cursor.execute("SELECT id FROM usersSpark WHERE email = %s AND id != %s", 
                               (data['email'], user_id))
                email_exists = cursor.fetchone()
                
                if email_exists:
                    return jsonify({'success': False, 'message': 'Email already in use'}), 400
                    
                update_fields.append("email = %s")
                params.append(data['email'])
            
            if data.get('password'):
                from email_sender import hash_password
                update_fields.append("password = %s")
                params.append(hash_password(data['password']))
            
            if data.get('status'):
                update_fields.append("status = %s")
                params.append(data['status'])
            
            # Add user_id to params
            params.append(user_id)
            
            # Execute update
            cursor.execute(f'''
            UPDATE usersSpark SET {', '.join(update_fields)}, updated_at = %s
            WHERE id = %s
            ''', params + [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id])
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'User updated successfully',
                'user_id': user_id
            }), 200
            
    except Error as e:
        logging.error(f"Error adding/updating user: {e}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# Delete user
@admin_bp.route('/users/<user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    try:
        conn = connect_db()
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT id FROM usersSpark WHERE id = %s", (user_id,))
        existing_user = cursor.fetchone()
        
        if not existing_user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        # Delete user
        cursor.execute("DELETE FROM usersSpark WHERE id = %s", (user_id,))
        
        # Also delete user's resumes
        try:
            with connect_db() as resume_conn:
                resume_cursor = resume_conn.cursor()
                resume_cursor.execute("DELETE FROM resumes WHERE user_id = %s", (user_id,))
                resume_conn.commit()
        except Error as e:
            logging.error(f"Error deleting user's resumes: {e}")
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'User deleted successfully'
        }), 200
        
    except Error as e:
        logging.error(f"Error deleting user: {e}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# Get user analytics
@admin_bp.route('/analytics/users', methods=['GET'])
@admin_required
def user_analytics():
    try:
        # Get date range parameters
        start_date = request.args.get('start_date', (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
        end_date = request.args.get('end_date', datetime.now().strftime('%Y-%m-%d'))
        
        conn = connect_db()
        
        # Use pandas for analytics
        users_df = pd.read_sql_query('''
            SELECT 
                DATE(created_at) as signup_date,
                COUNT(*) as signup_count
            FROM usersSpark
            WHERE DATE(created_at) BETWEEN %s AND %s
            GROUP BY DATE(created_at)
            ORDER BY DATE(created_at)
        ''', conn, params=(start_date, end_date))
        
        # Get total user count
        total_users = pd.read_sql_query('SELECT COUNT(*) as count FROM usersSpark', conn).iloc[0]['count']
        
        # Get active users (with at least one resume)
        with connect_db() as resume_conn:
            active_users = pd.read_sql_query('''
                SELECT COUNT(DISTINCT user_id) as count FROM resumes
            ''', resume_conn).iloc[0]['count']
        
        conn.close()
        
        return jsonify({
            'success': True,
            'signups_by_date': users_df.to_dict(orient='records'),
            'total_users': int(total_users),
            'active_users': int(active_users),
            'activation_rate': round(active_users / total_users * 100, 2) if total_users > 0 else 0
        }), 200
        
    except Error as e:
        logging.error(f"Error fetching user analytics: {e}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# Get resume analytics
@admin_bp.route('/analytics/resumes', methods=['GET'])
@admin_required
def resume_analytics():
    try:
        # Get date range parameters
        start_date = request.args.get('start_date', (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
        end_date = request.args.get('end_date', datetime.now().strftime('%Y-%m-%d'))
        
        conn = connect_db()
        
        # Use pandas for analytics
        resumes_df = pd.read_sql_query('''
            SELECT 
                DATE(created_at) as creation_date,
                COUNT(*) as resume_count
            FROM resumes
            WHERE DATE(created_at) BETWEEN %s AND %s
            GROUP BY DATE(creation_date)
            ORDER BY DATE(creation_date)
        ''', conn, params=(start_date, end_date))
        
        # Get total resume count
        total_resumes = pd.read_sql_query('SELECT COUNT(*) as count FROM resumes', conn).iloc[0]['count']
        
        # Get average resumes per user
        avg_resumes_per_user = pd.read_sql_query('''
            SELECT AVG(resume_count) as avg_count
            FROM (
                SELECT user_id, COUNT(*) as resume_count
                FROM resumes
                GROUP BY user_id
            )
        ''', conn).iloc[0]['avg_count']
        
        conn.close()
        
        return jsonify({
            'success': True,
            'resumes_by_date': resumes_df.to_dict(orient='records'),
            'total_resumes': int(total_resumes),
            'avg_resumes_per_user': round(float(avg_resumes_per_user), 2) if avg_resumes_per_user else 0
        }), 200
        
    except Error as e:
        logging.error(f"Error fetching resume analytics: {e}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# Export users data
@admin_bp.route('/export/users', methods=['GET'])
@admin_required
def export_users():
    try:
        conn = connect_db()
        
        # Use pandas to export data
        users_df = pd.read_sql_query('''
            SELECT id, name, email, created_at, updated_at, last_login, status
            FROM usersSpark
            ORDER BY created_at DESC
        ''', conn)
        
        # Convert to CSV
        csv_data = users_df.to_csv(index=False)
        
        conn.close()
        
        return jsonify({
            'success': True,
            'data': csv_data,
            'filename': f'users_export_{datetime.now().strftime("%Y%m%d")}.csv'
        }), 200
        
    except Error as e:
        logging.error(f"Error exporting users: {e}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500

# Admin login
@admin_bp.route('/login', methods=['POST'])
def admin_login():
    data = request.json
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'success': False, 'message': 'Missing email or password'}), 400
    
    try:
        conn = connect_db()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM usersSpark WHERE email = %s", (data['email'],))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        # Verify password
        from email_sender import verify_password
        if not verify_password(data['password'], user['password']):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        # Check if user is admin
        if user['email'] != 'admin@example.com':
            return jsonify({'success': False, 'message': 'Unauthorized access'}), 403
        
        # Generate token
        token = jwt.encode({
            'user_id': user['id'],
            'email': user['email'],
            'exp': datetime.utcnow() + timedelta(hours=8)
        }, JWT_SECRET, algorithm="HS256")
        
        # Update last login
        cursor.execute('''
            UPDATE usersSpark SET last_login = %s WHERE id = %s
        ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id']))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'token': token,
            'user': {
                'id': user['id'],
                'name': user['name'],
                'email': user['email']
            }
        }), 200
        
    except Error as e:
        logging.error(f"Error during admin login: {e}")
        return jsonify({'success': False, 'message': f'Error: {str(e)}'}), 500
    
# Initialize admin user
def init_admin_user():
    try:
        conn = connect_db()
        cursor = conn.cursor()
        
        # Check if admin exists
        cursor.execute("SELECT id FROM usersSpark WHERE email = %s", ('admin@example.com',))
        admin_exists = cursor.fetchone()
        
        if not admin_exists:
            from email_sender import hash_password
            
            # Create admin user
            admin_id = str(uuid.uuid4())
            admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')  # Should use env variable
            
            cursor.execute('''
            INSERT INTO usersSpark (id, name, email, password, created_at, status)
            VALUES (%s, %s, %s, %s, %s, %s)
            ''', (
                admin_id,
                'Admin User',
                'admin@example.com',
                hash_password(admin_password),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'active'
            ))
            
            conn.commit()
            logging.info("Admin user created successfully")
            
        conn.close()
    except Error as e:
        logging.error(f"Error initializing admin user: {e}")

# Call this function when the application starts
# init_admin_user()