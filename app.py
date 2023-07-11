import json
import time

import boto3
from flask import Flask, request, url_for, session, redirect
#from dotenv import load_dotenv
from flask_session import Session
import base64
import os
from requests import post
import spotipy
from spotipy.oauth2 import SpotifyOAuth
import time
import webbrowser
import pandas as pd

app = Flask(__name__)


#These are needed to verify my app with spotify
client_id = os.getenv("CLIENT_ID")
client_secret = os.getenv("CLIENT_SECRET")

#app.secret_key = "fdfdasjklnfdlsf"
#app.config["SESSION_COOKIE_NAME"] = "Brandon Cookie"
app.config['SECRET_KEY'] = os.urandom(64)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './.flask_session/'
TOKEN_INFO = "token_info"
Session(app)

@app.route('/home')
def home(): # put application's code here

    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=url_for('home', _external=True),
        scope=("user-read-currently-playing", "user-read-private"),
        cache_handler=cache_handler

    )

    if request.args.get("code"):
        # Step 2. Being redirected from Spotify auth page
        auth_manager.get_access_token(request.args.get("code"))
        return redirect('/home')

    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        # Step 1. Display sign in link when no token
        auth_url = auth_manager.get_authorize_url()

        return f'<h2><a href="{auth_url}">Sign in</a></h2>'
    add_current_user()
    # Step 3. Signed in, display data
    spotify = spotipy.Spotify(auth_manager=auth_manager)
    #print(auth_manager.get_access_token())


    return f'<h2>Hi {spotify.me()["display_name"]}, ' \
            f'<small><a href="/sign_out">[sign out]<a/></small></h2>' \
            f'<a href="/playlists">my playlists</a> | ' \
            f'<a href="/getTrack">currently playing</a> | ' \
            f'<a href="/current_user">me</a>' \
 \



@app.route('/logout')
def logout():
    #for key in list(session.keys()):
        #session.pop(key)

    session.pop("token_info", None)

    session[TOKEN_INFO] = ""
    return redirect(url_for("home", _external=True))
    #return redirect('https://accounts.spotify.com/en/logout')


@app.route('/redirect')
def redirectPage():

    #sp_oauth = create_spotify_oauth()
    #code = request.args.get('code')
    #token_info = sp_oauth.get_access_token(code)
    #print(token_info)
    #session[TOKEN_INFO] = token_info



    #add_current_user()

    #check if usser is the db


    return redirect(url_for('getTrack', _external=True))



@app.route("/get-user-track/<id>")
def get_user_track(id):
    token_info = get_user_token_info(id)
    session.modified = True
    #if not authorized:
        #return redirect('/')
    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    name = get_users_user_name(id)
    output = ""
    results = sp.currently_playing()
    # results = sp.current_user_top_tracks(limit=10, offset=0, time_range='short_term')

    if results is None:
        return name + " is not listening to anything"

    item = results['item']

    track = item["name"]
    artist = item["artists"][0]
    artist_name = artist["name"]

    return name + " is listening to " + track + " - " + artist_name
@app.route("/listUsers")
def listUsers():
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table("users")
    items = table.scan()['Items']
    for item in items:
        print(item)

    return "test"
@app.route("/getTrack")
def getTrack():

    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=url_for('getTrack', _external=True),
        cache_handler=cache_handler

    )

    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        return redirect('/home')
    sp = spotipy.Spotify(auth_manager=auth_manager)

    name = get_users_name()
    output = ""
    results = sp.currently_playing()
    #results = sp.current_user_top_tracks(limit=10, offset=0, time_range='short_term')

    if results is None:
        return name + " is not listening to anything"

    item = results['item']

    track = item["name"]
    artist = item["artists"][0]
    artist_name = artist["name"]


    return name + " is listening to " + track + " - " + artist_name



def get_user_token_info(id):
    dynamodb = boto3.resource('dynamodb')
    dynamodb_client = boto3.client('dynamodb')
    table = dynamodb.Table('users')

    auth_manager = authenticate_current_user()
    response = dynamodb_client.query(
        TableName='users',
        KeyConditionExpression='id = :id',
        ExpressionAttributeValues={
            ':id' : {'S' : id}
        }
    )


    item = response['Items']
    access_token = item[0].get('access_token').get('S')
    refresh_token = item[0].get('refresh_token').get('S')
    expires_at = item[0].get('expires_at').get('N')


    token_info = {'access_token':access_token, 'refresh_token':refresh_token, 'expires_at': int(expires_at)}

    if auth_manager.is_token_expired(token_info):
        token_info = auth_manager.refresh_access_token(token_info.get('refresh_token'))
        token = token_info['access_token']
        sp = spotipy.Spotify(auth=token)

    return token_info


def get_users_user_name(id):
    token_info = get_user_token_info(id)
    session.modified = True
    #if not authorized:
        #return redirect('/')

    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    results = sp.current_user()
    name = results["display_name"]

    return name
def get_users_name():

    auth_manager = authenticate_current_user()
    sp = spotipy.Spotify(auth_manager=auth_manager)
    results = sp.current_user()
    name = results["display_name"]

    return name

def get_user_id():

    auth_manager = authenticate_current_user()
    sp = spotipy.Spotify(auth_manager=auth_manager)
    results = sp.current_user()
    id = results["id"]

    return id

def authenticate_current_user():
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=url_for('getTrack', _external=True),
        cache_handler=cache_handler

    )
    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        return redirect('/home')

    return auth_manager
def add_current_user():
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('users')

    username = get_users_name()
    id = get_user_id()

    auth_manager = authenticate_current_user()
    table.put_item(
        Item={
            'id': id,
            'username': username,
            'access_token': auth_manager.get_cached_token().get('access_token'),
            'refresh_token':auth_manager.get_cached_token().get('refresh_token'),
            'expires_at': auth_manager.get_cached_token().get('expires_at')
        }
    )

    response = table.get_item(
        Key={
            'username': username,
            'id': id
        }
    )
    item = response['Item']
    #print(item)
    return


if __name__ == '__main__':

    app.run(port=8000)

#pip install python-dotenv
#pip install requests
#pip install urllib3==1.26.6
#pip install spotipy
#pip install pandas


#def get_token():
#     token_valid = False
#     token_info = session.get(TOKEN_INFO, {})
# # Checking if the session already has a token stored
#     if not (session.get('token_info', False)):
#         token_valid = False
#         return token_info, token_valid
#
#     # Checking if token has expired
#     now = int(time.time())
#     is_token_expired = session.get('token_info').get('expires_at') - now < 60
#
#     # Refreshing token if it has expired
#     if (is_token_expired):
#         sp_oauth = create_spotify_oauth()
#         token_info = sp_oauth.refresh_access_token(session.get('token_info').get('refresh_token'))
#
#     token_valid = True
#     return token_info, token_valid


# def get_user_token(id):
#
#     #get the original info for the user
#     access_token, refresh_token, expires_at = get_user_token_info(id)
#     # Checking if token has expired
#     now = int(time.time())
#     is_token_expired = expires_at - now < 60
#
#     # Refreshing token if it has expired
#     if (is_token_expired):
#         sp_oauth = create_spotify_oauth()
#         token_info = sp_oauth.refresh_access_token(refresh_token)
#
#     #new tokens ready to be returned
#     access_token = token_info['access_token']
#     refresh_token = token_info['refresh_token']
#     expires_at = token_info['expires_at']
#     token_valid = True
#     return access_token, refresh_token, expires_at



#

# def get_token():
#
#     auth_string = client_id + ":" + client_secret
#     auth_bytes = auth_string.encode("utf-8")
#     auth_base64 = str(base64.b64encode(auth_bytes), "utf-8")
#     url = "https://accounts.spotify.com/api/token"
#
#     headers = {
#         "Authorization": "Basic " + auth_base64,
#         "Content-Type": "application/x-www-form-urlencoded"
#     }
#
#     data = {"grant_type": "client_credentials"}
#
#     result = post(url, headers=headers, data=data)
#     json_result = json.loads(result.content)
#     token = json_result["access_token"]
#     return token


#

# def get_auth_header(token):
#     return {"Authorization": "Bearer " + token}