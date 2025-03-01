from flask import Flask, render_template, redirect, url_for, request
from Crypto.Hash import SHA256
from Server import Server

app = Flask(__name__)
server = Server()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['val_password']

        # Check if passwords match
        if password != confirm_password:
            return "Passwords do not match. Please try again."

        # Validate username and password length
        if len(username) < 3 or not username.isalnum():  # username must be alphanumeric
            return "Invalid username. Only alphanumeric characters are allowed."
        if len(password) < 6:  # password must be longer than 6 characters
            return "Password must be longer than 6 characters."

        # Register the user
        server.register_user(username, password)
        return redirect(url_for('login'))  # Redirect to login after successful registration

    return render_template('register.html')

def generate_otp_token(password, iterations):
    """ Generate an OTP chain by hashing the password multiple times """
    current_value = password
    for _ in range(iterations):
        sha = SHA256.new()
        sha.update(current_value.encode('utf-8'))
        current_value = sha.hexdigest()
    return current_value

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Send login data to server for validation
        login_valid, counter = server.validate_login(username, password)

        if login_valid:
            # Hash the password up to the counter times and send OTP token
            otp_token = generate_otp_token(password, 100-counter)
            print(f"Generated OTP token: {otp_token}")  # Debugging log

            # Send OTP to the server for validation
            if server.validate_otp(username, otp_token):
                return redirect(url_for('welcome', username=username))
            else:
                return "Invalid OTP. Please try again."
        else:
            return "Invalid credentials. Please try again."
        
    return render_template('login.html')


@app.route('/welcome/<username>')
def welcome(username):
    return render_template('welcome.html', username=username)

@app.route('/')
def main_screen():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
