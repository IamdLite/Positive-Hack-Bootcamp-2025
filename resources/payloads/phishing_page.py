 from flask import Flask, request, render_template_string, redirect, url_for
import os

app = Flask(__name__)

# Flag for the CTF (normally this would be in /home/Admin)
FLAG = os.getenv('FLAG', 'CTF{simulated_flag_for_education}')

# Simple database to store "captured" credentials (in memory only)
captured_credentials = []

@app.route('/')
def phishing_page():
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Login Portal</title>
            <style>
                body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
                .login-box { 
                    width: 300px; padding: 20px; background: white; 
                    margin: 100px auto; box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    border-radius: 5px;
                }
                input { width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; }
                button { 
                    background-color: #4CAF50; color: white; padding: 10px 15px; 
                    border: none; width: 100%; cursor: pointer;
                }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>Company Secure Login</h2>
                <form method="POST" action="/login">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                    
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                    
                    <button type="submit">Sign In</button>
                </form>
            </div>
        </body>
        </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])  # Now accepts both GET and POST
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Store the captured credentials
        captured_credentials.append({'username': username, 'password': password})
        print(f"Captured credentials: {username}:{password}")
        
        # Show failed login message with potential flag
        return render_template_string('''
            <h2>Login Failed</h2>
            <p>Your credentials were incorrect. Please try again.</p>
            <a href="/">Go back</a>
            
            <!-- Hidden flag for the CTF challenge -->
            {% if username == "Admin" %}
                <div style="display:none;">Flag: {{ flag }}</div>
            {% endif %}
        ''', flag=FLAG)
    else:
        # Handle GET request by showing the login form
        return redirect(url_for('phishing_page'))

@app.route('/admin')
def admin():
    # This would be the real admin page in a real scenario
    return f"Admin panel - Flag: {FLAG}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
