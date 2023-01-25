"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException

api = Blueprint('api', __name__)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200


@api.route("/signup", methods=["POST"])
def signup():
    user = User()
    email = request.json.get("email")
    password = request.json.get("password")
    
    found_email = User.query.filter_by(email=email).first()

    if found_email is not None:
        return jsonify({
            "msg": "Ya existe un usuario registrado con este email"
        }), 400

    user.name = request.json.get("name")
    user.email = email
    password_hash = bcrypt.generate_password_hash(password)
    user.password = password_hash
    

    db.session.add(user)
    db.session.commit()

    return jsonify({
        "msg": "usuario registrado correctamente"
        }), 200

@api.route("/login", methods=["POST"])
def login():
    password = request.json.get("password")
    email = request.json.get("email")

    found_user = User.query.filter_by(email=email).first()

    if found_user is None:
        return jsonify ({
            "msg": "contraseña o rut invalido"
        }), 404
    
    if bcrypt.check_password_hash(found_user.password, password):
        access_token = create_access_token(identity=found_user.id)
        return jsonify({
            "access_token": access_token,
            "data": found_user.serialize(),
            "success": True
        }), 200
    
    else:
        return jsonify ({
            "msg": "contraseña o rut invalido"
        })

