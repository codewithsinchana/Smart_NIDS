from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token

auth = Blueprint("auth", __name__)

USERNAME = "admin"
PASSWORD = "admin123"

@auth.route("/api/login", methods=["POST"])
def login():

    data = request.get_json()

    if (
        data.get("username") == USERNAME
        and data.get("password") == PASSWORD
    ):

        token = create_access_token(identity=USERNAME)

        return jsonify({
            "success": True,
            "token": token
        })

    return jsonify({
        "success": False
    }), 401