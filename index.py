##
## ===========================================
## =============== API TESTE ===============
## ===========================================
## =======2020/2021 ==============================
## ===========================================
## ===========================================
##
## Authors: 
##   Goncalo Marques 
## updated in 06/12/2023 to notice some intentional problems 

from flask import Flask, jsonify, request
import logging, time, psycopg2, jwt, json
from datetime import datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)   

##This is not correct! - passwords need to be configured as environments variables
#app.config['SECRET_KEY'] = 'it\xb5u\xc3\xaf\xc1Q\xb9\n\x92W\tB\xe4\xfe__\x87\x8c}\xe9\x1e\xb8\x0f'

NOT_FOUND_CODE = 400
OK_CODE = 200
SUCCESS_CODE = 201
BAD_REQUEST_CODE = 400
UNAUTHORIZED_CODE = 401
FORBIDDEN_CODE = 403
NOT_FOUND = 404
SERVER_ERROR = 500
  
@app.route('/', methods = ["GET"])
def home():        
    return "Bem vindo a API"

##########################################################
## DATABASE ACCESS
##########################################################
def db_connection():
    ##The credentials and access to database are stored in a environment variable
    database = os.environ.get('database')
    user = os.environ.get('user')
    password = os.environ.get('pass')
    host = os.environ.get('hostname')
    #print(database, user, password, host)
    db = psycopg2.connect(dbname = database, user = user, password = password, host = host, port = 5432)
    return db

def generate_token(user_id):
    secret_key = os.environ.get('SECRET_KEY') 

    if secret_key:
        token = jwt.encode({'user_id': user_id}, secret_key, algorithm='HS256')
        return token
    else:
        raise ValueError("Chave secreta não encontrada")


##########################################################
## TOKEN INTERCEPTOR
##########################################################
def auth_user(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        content = request.get_json()
        if content is None or "uti_token" not in content or not content["uti_token"]:
            return jsonify({'Erro': 'Token está em falta!', 'Code': UNAUTHORIZED_CODE})

        try:
            token = content["uti_token"]
            data = jwt.decode(token, app.config['SECRET_KEY'])

            decoded_token = jwt.decode(content['token'], app.config['SECRET_KEY'])
            if(decoded_token["uti_token_expiration"] < str(datetime.utcnow())):
                ####Attention: The error code should not be sent in JSON body!!! Check the Example bellow.
                return jsonify({"Erro": "O Token expirou!", "Code": NOT_FOUND_CODE})

        except Exception as e:
            ##correct way!!!
            return jsonify({'Erro': 'Token inválido'}), FORBIDDEN_CODE
        return func(*args, **kwargs)
    return decorated


##########################################################
## LOGIN
##########################################################
@app.route("/loginUti", methods=['POST'])
def verifyUti():
    content = request.get_json()

    if "uti_login" not in content or "uti_password" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})

    get_user_info = """
                SELECT *
                FROM Utilizadores
                WHERE uti_login = %s AND uti_password = %s;
                """

    values = [content["uti_login"], content["uti_password"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()

                token = generate_token(rows[0][0])
                #print(token)

                if rows:
                    update_token = """
                    UPDATE Utilizadores
                    SET uti_token = %s, uti_token_expiration = %s, uti_online = %s
                    WHERE uti_id = %s;
                    """

                    user_id = rows[0][0]
                    token = generate_token(user_id)
                    print(token)
                    expiration_time = datetime.utcnow() + timedelta(hours=1)
                    values_token = [token, expiration_time,True ,user_id]

                    try:
                        conn1 = db_connection()
                        cursor1 = conn1.cursor()

                        cursor1.execute(update_token, values_token)
                        conn1.commit()

                        conn1.close()
                    except (Exception, psycopg2.DatabaseError) as error:
                        print(error)
                        return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Erro no update"})
                    return jsonify({"uti_id": rows[0][0], "uti_login": rows[0][1], "uti_password": rows[0][2], "uti_token": rows[0][3], "uti_online": rows[0][4], "uti_token_expiration":rows[0][5]})
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Utilizador não encontrado"})
    return jsonify({"uti_id": rows[0][0], "uti_login": rows[0][1], "uti_password": rows[0][2], "uti_token": rows[0][3], "uti_online": rows[0][4], "uti_token_expiration":rows[0][5]})


##########################################################
## LOGOUT
##########################################################
@app.route("/logoutUti",methods=['POST'])
def logoutUti():
    content = request.get_json()

    if "uti_id" not in content:
        return jsonify({"Code:":BAD_REQUEST_CODE, "Erro":"Parãmetros inválidos"})
    
    get_user_info = """
                    UPDATE Utilizadores
                    SET uti_online = %s, uti_token = %s
                    WHERE uti_id = %s;
                    """
    
    values = [False,"",content["uti_id"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.fetchall()
                conn.close()
                if rows:
                    return True
                else:
                    return False
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": "Não foi possivel fazer o logout"})
            
    










##########################################################
## REGISTO DE UTILIZADOR
##########################################################
@app.route("/addUti", methods=['POST'])
def addUti():
    content = request.get_json()

    if "uti_login" not in content or "uti_password" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})
    
    #a password devia ser encryptada
    get_user_info = """
                INSERT INTO Utilizadores(uti_login, uti_password, uti_token) 
                VALUES(%s, %s, %s);
                """

    values = [content["uti_login"], content["uti_password"], ""]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    finally:
        conn.close()
    return {"Code": OK_CODE}

##########################################################
## CONSULTAR UTILIZADOR
##########################################################
@app.route("/getUti", methods=['GET'])
#@auth_user
def getUti():
    content = request.get_json()

    if "uti_id" not in content:
        return jsonify({"Code:":BAD_REQUEST_CODE, "Erro":"Parãmetros inválidos"})
    
    conn = db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM Utilizadores WHERE uti_id = %s;", (content["uti_id"]))
    rows = cur.fetchall()

    conn.close()
    return jsonify({"uti_id": rows[0][0], "uti_login": rows[0][1], "uti_password": rows[0][2], "uti_token": rows[0][3], "uti_online": rows[0][4], "uti_token_expiration":rows[0][5]})


if __name__ == "__main__":
    app.run(port=8080, debug=True, threaded=True)
