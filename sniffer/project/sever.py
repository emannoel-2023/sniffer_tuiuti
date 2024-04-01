from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        return f"Login successful for user: {username} with password: {password}"
    else:
        return render_template('site.html')

if __name__ == "__main__":
    app.run(port=5001)
