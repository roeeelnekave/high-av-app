from flask import Flask, request, render_template, redirect, url_for
import psycopg2
import threading
import psutil
import os
import boto3
import json
import sys

app = Flask(__name__)

# Function to get the secret from AWS Secrets Manager
def get_secret(secret_id):
    client = boto3.client('secretsmanager', region_name="us-west-2")
    try:
        response = client.get_secret_value(SecretId=secret_id)
        secret_string = response.get('SecretString')
        if not secret_string:
            raise ValueError("SecretString is empty.")
        return json.loads(secret_string)
    except Exception as e:
        print(f"Failed to fetch the secret from AWS Secrets Manager: {e}")
        sys.exit(1)

# Function to get the RDS instance endpoint
def get_rds_endpoint(db_instance_identifier):
    client = boto3.client('rds', region_name="us-west-2")
    try:
        response = client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)
        endpoint = response['DBInstances'][0]['Endpoint']['Address']
        return endpoint
    except Exception as e:
        print(f"Failed to fetch the RDS instance endpoint: {e}")
        sys.exit(1)

# Fetch the secret and RDS endpoint
def setup_environment():
    secret_id = 'rds-db-sec-023'  # Replace with your secret ID
    db_instance_identifier = 'mydb'  # Replace with your RDS instance ID

    # Fetch the secret
    secret_data = get_secret(secret_id)
    db_user = secret_data.get('username')
    db_pass = secret_data.get('password')
    db_host = get_rds_endpoint(db_instance_identifier)

    if not db_user or not db_pass:
        print("Failed to extract username or password from the secret.")
        sys.exit(1)

    # Set environment variables
    os.environ['DB_USER'] = db_user
    os.environ['DB_PASS'] = db_pass
    os.environ['DB_HOST'] = db_host

# Fetch secrets and RDS endpoint and set environment variables
setup_environment()

# Database connection details
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_NAME = "postgres" 
DB_PASS = os.getenv("DB_PASS") 

DB_PORT = 5432

# Function to connect to the database
def get_db_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )
    return conn

# Function to create the submissions table if it doesn't exist
def create_table():
    conn = get_db_connection()
    with conn:
        with conn.cursor() as cur:
            cur.execute('''
                CREATE TABLE IF NOT EXISTS submissions (
                    id SERIAL PRIMARY KEY,
                    data TEXT NOT NULL
                )
            ''')

# Route to display the form
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        data = request.form['data']
        # Save data to the database
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO submissions (data) VALUES (%s)', (data,))
        return redirect(url_for('index'))

    return render_template('index.html')

# Route to display all submissions
@app.route('/submissions')
def submissions():
    conn = get_db_connection()
    with conn:
        with conn.cursor() as cur:
            cur.execute('SELECT * FROM submissions')
            rows = cur.fetchall()
    return render_template('submissions.html', submissions=rows)

# Function to simulate multiple users
def simulate_users(num_users):
    for i in range(num_users):
        conn = get_db_connection()
        with conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO submissions (data) VALUES (%s)', (f'Simulated User {i + 1}',))

# Route to simulate multiple users
@app.route('/simulate/<int:num_users>')
def simulate(num_users):
    thread = threading.Thread(target=simulate_users, args=(num_users,))
    thread.start()
    return f'Simulating {num_users} users...'

# Route to get CPU and memory usage
@app.route('/usage')
def get_usage():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_percent = psutil.virtual_memory().percent
    return {'cpu': cpu_percent, 'memory': memory_percent}

if __name__ == '__main__':
    create_table()
    app.run(debug=True, host="0.0.0.0")
