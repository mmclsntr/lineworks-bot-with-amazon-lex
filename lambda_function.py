import json
import jwt
import requests
import urllib
import boto3
import os
from datetime import datetime
from base64 import b64encode, b64decode
import hashlib
import hmac

from requests.structures import CaseInsensitiveDict

ssm = boto3.client('ssm')
lex = boto3.client('lex-runtime')

####################################
# Systems Manager パラメータストア #
####################################
def get_parameter(key):
    """
    SSMパラメータストアからパラメータ取得
    """
    response = ssm.get_parameters(
        Names=[
            key
        ],
        WithDecryption=True
    )
    parameters = response["Parameters"]
    if len(parameters) > 0:
        return response['Parameters'][0]["Value"]
    else:
        return ""


def put_parameter(key, value):
    """
    SSMパラメータストアへパラメータを格納
    """
    response = ssm.put_parameter(
        Name=key,
        Value=value,
        Type='SecureString',
        Overwrite=True
    )


##############
# Amazon Lex #
##############
def post_text_to_lex(text, user_id, bot_name, bot_alias):
    """
    Amazon Lexへテキストを送信 & 返答取得
    """
    response = lex.post_text(
        botName=bot_name,
        botAlias=bot_alias,
        userId=user_id,
        inputText=text
    )

    print(response)
    return response["message"]


##################
# LINE WORKS API #
##################
def get_jwt(server_list_id, server_list_privatekey):
    """
    LINE WORKS アクセストークンのためのJWT取得
    """
    current_time = datetime.now().timestamp()
    iss = server_list_id
    iat = current_time
    exp = current_time + (60 * 60) # 1時間

    secret = server_list_privatekey

    jwstoken = jwt.encode(
        {
            "iss": iss,
            "iat": iat,
            "exp": exp
        }, secret, algorithm="RS256")

    return jwstoken.decode('utf-8')


def get_server_token(api_id, jwttoken):
    """
    LINE WORKS アクセストークン取得
    """
    url = 'https://authapi.worksmobile.com/b/{}/server/token'.format(api_id)

    headers = {
        'Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'
    }

    params = {
        "grant_type" : urllib.parse.quote("urn:ietf:params:oauth:grant-type:jwt-bearer"),
        "assertion" : jwttoken
    }

    form_data = params

    r = requests.post(url=url, data=form_data, headers=headers)

    body = json.loads(r.text)
    access_token = body["access_token"]

    return access_token


def validate_request(body, signature, api_id):
    """
    LINE WORKS リクエスト検証
    """
    # API IDを秘密鍵に利用
    secretKey = api_id.encode()
    payload = body.encode()

    # HMAC-SHA256 アルゴリズムでエンコード
    encoded_body = hmac.new(secretKey, payload, hashlib.sha256).digest()
    # BASE64 エンコード
    encoded_b64_body = b64encode(encoded_body).decode()

    # 比較
    return encoded_b64_body == signature


def send_message(content, api_id, botno, consumer_key, access_token, account_id):
    """
    LINE WORKS メッセージ送信
    """
    url = 'https://apis.worksmobile.com/{}/message/sendMessage/v2'.format(api_id)

    headers = {
          'Content-Type' : 'application/json;charset=UTF-8',
          'consumerKey' : consumer_key,
          'Authorization' : "Bearer " + access_token
        }

    params = {
            "botNo" : int(botno),
            "accountId" : account_id,
            "content" : content
        }

    form_data = json.dumps(params)

    r = requests.post(url=url, data=form_data, headers=headers)

    if r.status_code == 200:
        return True

    return False

######################
# Lambda関数ハンドラ #
######################
def update_token_handler(event, context):
    """
    LINE WORKS アクセストークン定期更新 Lambdaハンドラー関数
    """
    # SSMパラメータストアからLINE WORKSのパラメータを取得
    api_id = get_parameter("lw_api_id")
    server_list_id = get_parameter("lw_server_list_id")
    server_list_privatekey = get_parameter("lw_server_list_private_key").replace("\\n", "\n")
    # JWT取得
    jwttoken = get_jwt(server_list_id, server_list_privatekey)

    # Server token取得
    access_token = get_server_token(api_id, jwttoken)

    # Access Tokenをパラメータストアに設定
    put_parameter("lw_access_token", access_token)

    return


def chat_with_lex_handler(event, content):
    """
    LINE WORKS チャットボット Lambdaハンドラー関数
    """
    botno = os.environ.get("BOTNO")
    lex_bot_name = os.environ.get("LEX_BOT_NAME")
    lex_bot_alias = os.environ.get("LEX_BOT_ALIAS")
    # SSMパラメータストアからLINE WORKSのパラメータを取得
    api_id = get_parameter("lw_api_id")
    consumer_key = get_parameter("lw_server_api_consumer_key")
    access_token = get_parameter("lw_access_token")

    event = CaseInsensitiveDict(event)
    headers = event["headers"]
    body = event["body"]

    # リクエスト検証
    if not validate_request(body, headers.get("x-works-signature"), api_id):
        # 不正なリクエスト
        return

    # Jsonへパース
    request = json.loads(body)

    # 送信ユーザー取得
    account_id = request["source"]["accountId"]

    res_content = {
        "type" : "text",
        "text" : "Only text"
    }

    # 受信したメッセージの中身を確認
    request_type = request["type"]
    ## Message
    if request_type == "message":
        content = request["content"]
        content_type = content["type"]
        ## Text
        if content_type == "text":
            text = content["text"]

            # Amazon Lexと連携
            reply_txt = post_text_to_lex(text, account_id.replace("@", "a"), lex_bot_name, lex_bot_alias)

            res_content = {
                "type" : "text",
                "text" : reply_txt
            }

    # 送信
    rst = send_message(res_content, api_id, botno, consumer_key, access_token, account_id)

    res_body = {
        "code": 200,
        "message": "OK"
    }
    response = {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "body": json.dumps(res_body)
    }

    return response
