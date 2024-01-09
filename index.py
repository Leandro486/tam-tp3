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
## LOGIN
##########################################################
@app.route("/loginUti", methods=['POST'])
def loginUti():
    content = request.get_json()

    #print(content)

    if "uti_login" not in content or "uti_password" not in content:
        return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})

    get_user_info = """
                SELECT *
                FROM Utilizadores
                WHERE uti_login = %s AND uti_password = %s
                AND (uti_token IS NULL OR uti_token_expiration IS NULL)
                AND uti_online = False;
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
                    #print(token)
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
                    #return jsonify({"uti_id": rows[0][0], "uti_login": rows[0][1], "uti_password": rows[0][2], "uti_token": rows[0][3], "uti_online": rows[0][4], "uti_token_expiration":rows[0][5]})
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
                    SET uti_online = %s, uti_token = %s, uti_token_expiration = %s
                    WHERE uti_id = %s;
                    """
    
    values = [False,"",None,content["uti_id"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, values)
                rows = cursor.rowcount
                if rows > 0:
                    conn.commit()
                    return jsonify({"Logout": "successful"})
                else:
                    return jsonify({"Code": "NOT_FOUND_CODE", "Erro": "Não foi possível fazer o logout, usuário não encontrado"})
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
    
    get_user_info = """
                    SELECT COUNT(*)
                    FROM Utilizadores
                    WHERE uti_login = %s;
                    """
    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(get_user_info, [content["uti_login"]])
                user_count = cursor.fetchone()[0]

            if user_count > 0:
                return jsonify({"Code": BAD_REQUEST_CODE, "Erro": "Login já existe"})

            #a password devia ser encryptada
            insert_user_info = """
                                INSERT INTO Utilizadores(uti_login, uti_password, uti_token) 
                                VALUES(%s, %s, %s);
                                """
            
            insert_values = [content["uti_login"], content["uti_password"], ""]

            try:
                with db_connection() as conn1:
                    with conn1.cursor() as cursor1:
                        cursor1.execute(insert_user_info, insert_values)
                    conn1.commit()

            except (Exception, psycopg2.DatabaseError) as error:
                return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})

            conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    finally:
        conn.close()
    return "Utilizador Registado"

##########################################################
## CONSULTAR UTILIZADOR
##########################################################
@app.route("/getUti", methods=['GET'])
def getUti():
    uti_id = request.args.get('uti_id')

    if uti_id is None:
        return jsonify({"Code:": BAD_REQUEST_CODE, "Erro": "Parâmetros inválidos"})
    
    conn = db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM Utilizadores WHERE uti_id = %s;", (uti_id,))
    rows = cur.fetchall()

    conn.close()

    if len(rows) == 0:
        return jsonify({"Erro": "Utilizador não encontrado"})

    return jsonify({
        "uti_id": rows[0][0],
        "uti_login": rows[0][1],
        "uti_password": rows[0][2],
        "uti_token": rows[0][3],
        "uti_online": rows[0][4],
        "uti_token_expiration": rows[0][5]
    })

##########################################################
## ADICIONAR MEDICAMENTOS
##########################################################
@app.route("/addMed",methods=["POST"])
def addMed():
    content = request.get_json()

    if "med_nome" not in content or "med_dosagem" not in content or "med_forma" not in content or "med_posologia" not in content or "med_horario1" not in content or "med_horario2" not in content or "med_horario3" not in content or "med_horario4" not in content or "med_quantidade" not in content or "med_data" not in content or "med_administrado" not in content or "uti_id" not in content:
        return jsonify({"Code:":BAD_REQUEST_CODE, "Erro":"Parãmetros inválidos"})
    
    insert_med_info = """
                  INSERT INTO Medicamentos(med_nome, med_dosagem, med_forma, med_posologia, med_horario1, med_horario2, med_horario3, med_horario4, med_quantidade, med_duracao, med_data, med_administrado, uti_id)
                  VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);
                """
    insert_values = [content['med_nome'],content['med_dosagem'],content['med_forma'],content['med_posologia'],content['med_horario1'],content['med_horario2'],content['med_horario3'],content['med_horario4'],content['med_quantidade'],content['med_duracao'],content['med_data'],content['med_administrado'],content['uti_id']]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(insert_med_info,insert_values)
            conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Code": NOT_FOUND_CODE, "Erro": str(error)})
    finally:
        conn.close()
    return "Medicamento Registado"

##########################################################
## LISTAR MEDICAMENTOS
##########################################################
@app.route("/getAllMed",methods=["GET"])
def getAllMed():
    content = request.get_json()

    return

##########################################################
## GET MEDICAMENTO
##########################################################
@app.route("/getMed",methods=["GET"])
def getMed():
    content = request.get_json()

    return

##########################################################
## UPDATE MEDICAMENTO
##########################################################
@app.route("/updateMed",methods=["PUT"])
def updateMed():
    content = request.get_json()

    return

##########################################################
## DELETE MEDICAMENTO
##########################################################
@app.route("/deleteMed",methods=["DELETE"])
def deleteMed():
    content = request.get_json()

    return







if __name__ == "__main__":
    app.run(port=8080, debug=True, threaded=True)
