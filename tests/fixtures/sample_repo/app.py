from flask import Flask, request
from crypto_utils import encrypt_data

app = Flask(__name__)

@app.route("/api/encrypt", methods=["POST"])
def handle_encrypt():
    data = request.get_json()
    result = encrypt_data(data["payload"])
    return {"result": result}

if __name__ == "__main__":
    app.run()
