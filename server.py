#Fastapi_servr
import hmac
import hashlib
import base64
import json
from typing import Optional
from fastapi import FastAPI, Form, Cookie
from fastapi import responses
from fastapi.datastructures import Default   # импортируем фастапи
from fastapi.responses import Response  # с помощью Response мы можем слать ответы в браузер


app = FastAPI()

SECRET_KEY = '46310817ca99a40cde8c48e04d068212c789d74d23a3f05a9501cf3b78e4f997'
PASSWORD_SALT = '5bea48bf0c54cc4c65b7c97490d795917310f49562143e18f151ac00ebc9c4dc'

def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign,sign):
        return username
    
def sign_data(data : str) -> str:
    '''Возвращает подписанные данные data'''

    return hmac.new(SECRET_KEY.encode(),
                   msg = data.encode(),
                   digestmod = hashlib.sha256, 
                    ).hexdigest().upper()


users = {
    'alexey@user.com':{
        'name':'alexey',
        'password':'8df3e840d447d1907672bd0760eb9dc0145a24a978313810d09ebb2f0d6d519f',
        'balance':1000000
        },
    'petr@user.com':{
        'name' :'petr',
        'password' : 'df585b220db10103fe0c17e845b71bd80925e851817a789ff3647d103a03edff',
        'balance' : 50000000
        }    
}
def verify_password (username,password :str) -> bool:
    password_hash = hashlib.sha256((password+PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = (users[username]['password']).lower()
    return password_hash == stored_password_hash

@app.get("/") #  функция ниже будет выполняться, когда придёт get запрос на корневую страницу (/)
def index_page(username : Optional[str] = Cookie(default = None)): # создаём пайтон функцию, которая обрабатывает наш ответ
    with open("templates/login.html",'r') as f:
        login_page = f.read()
    if not username:    
        return Response(login_page,media_type="text/html")    
    if username:    
        valid_username = get_username_from_signed_string(username)
        if not valid_username:
            response =  Response(login_page,media_type="text/html") 
            response.delete_cookie(key="username")
            return response     

        try:
            user = users[valid_username]['name']
        except KeyError:
            response =  Response(login_page,media_type="text/html")  
            response.delete_cookie(key='username') 
            return response

        return Response(f'Привет, {user}',media_type="text/css")    
    

@app.post("/login")
def process_login_page(username : str = Form(...), password : str = Form(...)):
    user = users.get(username)
    
    if not user or not verify_password(username,password):
        return Response(
            json.dumps({
                "sucsess": False,
                'message' : 'Я вас не знаю'
            }),media_type="application/json")

    response =  Response(
        json.dumps(
            {
                "success": True,
                'message': f"Привет {user['name']}\nВаш баланс:{user['balance']}"
            }
        ),media_type="application/json")

    username_signet = base64.b64encode(username.encode()).decode() + '.' + sign_data(username)
    response.set_cookie(key='username',value=username_signet)
    return response
    
