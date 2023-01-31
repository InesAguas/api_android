from flask import Flask, jsonify, request
import psycopg2, jwt, json
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

app.config['SECRET_KEY'] = 'it\xb5u\xc3\xaf\xc1Q\xb9\n\x92W\tB\xe4\xfe__\x87\x8c}\xe9\x1e\xb8\x0f'

BAD_REQUEST = 400
UNAUTHORIZED_CODE = 401
SERVER_ERROR = 500
SUCCESS = 200

@app.route("/")
def welcome():
    return "meter aqui as rotas possiveis....."

#token interceptor
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        #checks if token is in request header
        if 'token' not in request.headers:
            return jsonify({"Error:": "Missing token"}), BAD_REQUEST

        try:
            token = request.headers['token']
           #decodes the token and checks if date is valid
            token_decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
            if(token_decoded["expiration"] < str(datetime.utcnow())):
                 return jsonify({"Error:": "Token expired"}), UNAUTHORIZED_CODE
        except Exception as error:
            print(error)
            return jsonify({"Error": "Invalid token!"}), UNAUTHORIZED_CODE
        return f(*args, **kwargs)
    return decorator


#login, creates token
@app.route("/user/login", methods=['POST'])
def user_login():
    content = request.get_json()
    print(content)

    if 'username' not in content or 'password' not in content:
        return jsonify({"Error:": "Missing values"}), BAD_REQUEST

    try:
        conn = connection()
        cur = conn.cursor()
        query = """SELECT id, username FROM users WHERE username = %s AND password = crypt(%s, password);"""
        cur.execute(query, (content['username'], content['password']))
        results = cur.fetchone()
        print(results)
        if results is None:
            return jsonify({"Error:": "Wrong credentials"}), BAD_REQUEST

        token = jwt.encode({
                    'id': results[0],
                    'expiration': str(datetime.utcnow() + timedelta(hours=1))
                }, app.config['SECRET_KEY'])
        conn.close()
        return jsonify({"id": results[0], "username": results[1], "token": token}), SUCCESS

    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
        return jsonify({"Error:": "Something went wrong"}), SERVER_ERROR


#register user
@app.route("/user/register", methods=['POST'])
def user_add():
    content = request.get_json()

    if 'username' not in content or 'password' not in content:
        return jsonify({"Error:": "Missing values"}), BAD_REQUEST
    
    username = content['username']
    password = content['password']

    if(not username.strip() or not password.strip()):
        return jsonify({"Error:": "Values can't be empty"}), BAD_REQUEST

    try:
        conn = connection()
        cur = conn.cursor()
        query_check = """SELECT id, username FROM users WHERE username = %s AND password = crypt(%s, password);"""
        cur.execute(query_check, [username, password])
        result = cur.fetchone()
        if result:
            return jsonify({"Error:": "User already exists"}), BAD_REQUEST
        query = """INSERT INTO users (username, password) VALUES (%s, crypt(%s, gen_salt('bf')));"""
        cur.execute(query,[username, password])
        conn.commit()
        conn.close()
        return jsonify({"Message:": "The user was registered"}), SUCCESS
    except (Exception, psycopg2.DatabaseError):
        return jsonify({"Error:": "Something went wrong"}), SERVER_ERROR


#add a game, token is required
@app.route("/games/add", methods=['POST'])
@token_required
def add_game():
    content = request.get_json()

    if 'player1' not in content or 'player2' not in content or 'tournament' not in content or 'score1' not in content or 'score2' not in content or 'date' not in content:
        return jsonify({"Error:": "Missing values"}), BAD_REQUEST
    
    player1 = content['player1']
    player2 = content['player2']
    tournament = content['tournament']
    score1 = content['score1']
    score2 = content['score2']
    date = content['date']
    token = request.headers['token']
    token_decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")

    if(not player1.strip() or not player2.strip() or not tournament.strip()):
        return jsonify({"Error:": "Values can't be empty"}), BAD_REQUEST

    try:
        conn = connection()
        cur = conn.cursor()
        query = """INSERT INTO games (user_id, player1, player2, tournament, score1, score2, date) VALUES (%s,%s, %s, %s, %s, %s, %s);"""
        cur.execute(query,[token_decoded['id'],player1, player2, tournament, score1, score2, date])
        conn.commit()
        conn.close()
        return jsonify({"Message:": "Game saved"}), SUCCESS

    except (Exception, psycopg2.DatabaseError):
        return jsonify({"Error:": "Something went wrong"}), SERVER_ERROR

#view all games, token is required
@app.route("/games/all", methods=['GET'])
@token_required
def view_games():
    try:
        conn = connection()
        cur = conn.cursor()
        query = """SELECT * FROM games;"""
        cur.execute(query)
        results = cur.fetchall()
        conn.close()
        finalresults = []
        for row in results:
            finalresults.append({"player1":row[2], "player2":row[3],"tournament":row[4],"score1":row[5], "score2":row[6], "date":row[7].strftime("%Y-%m-%d")})
        return jsonify(finalresults), SUCCESS
    except (Exception, psycopg2.DatabaseError):
        return jsonify({"Error:": "Something went wrong"}), SERVER_ERROR

def connection():
    conn = psycopg2.connect(host="aid.estgoh.ipc.pt", database="db2020155202", user="a2020155202", password="a2020155202")
    return conn
