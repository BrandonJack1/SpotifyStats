import json
import time

from flask import Flask, request, url_for, session, redirect
#from dotenv import load_dotenv
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

app.secret_key = "fdfdasjklnfdlsf"
app.config["SESSION_COOKIE_NAME"] = "Brandon Cookie"
TOKEN_INFO = "token_info"

@app.route('/home')
def home(): # put application's code here
    sp_oauth = create_spotify_oauth()
    auth_url = sp_oauth.get_authorize_url()

    return redirect(auth_url)
    #load_dotenv()
    #token = get_token()
    #print(token)
    #print(client_id, client_secret)


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

    sp_oauth = create_spotify_oauth()
    session.clear()
    code = request.args.get('code')
    token_info = sp_oauth.get_access_token(code)
    session[TOKEN_INFO] = token_info
    return redirect(url_for('getTrack', _external=True))


@app.route("/getTrack")
def getTrack():
    session['token_info'], authorized = get_token()
    session.modified = True
    if not authorized:
        return redirect('/')
    sp = spotipy.Spotify(auth=session.get('token_info').get('access_token'))

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


        # for idx, item in enumerate(curGroup):
        #     track = item['track']
        #     val = track['name'] + " - " + track['artists'][0]['name']
        #     results += str([val])
        # if (len(curGroup) < 50):
        #     break

    #df = pd.DataFrame(results, columns=["song names"])
    #df.to_csv('songs.csv', index=False)


def get_token():
    token_valid = False
    token_info = session.get(TOKEN_INFO, {})
# Checking if the session already has a token stored
    if not (session.get('token_info', False)):
        token_valid = False
        return token_info, token_valid

    # Checking if token has expired
    now = int(time.time())
    is_token_expired = session.get('token_info').get('expires_at') - now < 60

    # Refreshing token if it has expired
    if (is_token_expired):
        sp_oauth = create_spotify_oauth()
        token_info = sp_oauth.refresh_access_token(session.get('token_info').get('refresh_token'))

    token_valid = True
    return token_info, token_valid

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

def get_auth_header(token):
    return {"Authorization": "Bearer " + token}


def get_users_name():
    session['token_info'], authorized = get_token()
    session.modified = True
    if not authorized:
        return redirect('/')
    sp = spotipy.Spotify(auth=session.get('token_info').get('access_token'))

    results = sp.current_user()
    name = results["display_name"]

    return name


def create_spotify_oauth():
    return SpotifyOAuth(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=url_for('redirectPage', _external=True),
        scope="user-read-currently-playing",

    )

if __name__ == '__main__':

    app.run(port=8000)

#pip install python-dotenv
#pip install requests
#pip install urllib3==1.26.6
#pip install spotipy
#pip install pandas