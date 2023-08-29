import json
import time
from flask_cors import CORS
import boto3
import flask
from flask import Flask, request, url_for, session, redirect, render_template
# from dotenv import load_dotenv
from flask_session import Session
import base64
import os
from requests import post
import spotipy
from spotipy.oauth2 import SpotifyOAuth
import time
import webbrowser
import pandas as pd
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key, Attr
import threading

app = Flask(__name__)

app.config['SECRET_KEY'] = os.urandom(64)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './.flask_session/'
TOKEN_INFO = "token_info"
Session(app)
CORS(app, supports_credentials=True)
#REDIRECT_URI = 'ec2-18-233-84-132.compute-1.amazonaws.com:80/home'
REDIRECT_URI = 'http://127.0.0.1:5000/home'
aws_access_key_id='ASIA3TN67ELMW3C3RA5M'
aws_secret_access_key='/17ZJdqae7XFRbq4rsmVXfAf21Ryy36WDRDTtK6c'
aws_session_token='FwoGZXIvYXdzEPD//////////wEaDBKAt2492Tb1m+rRMCLAASOGIQXALKaiu3I33sUMUxOweli8b8Z++40qP9CF13syqtFA3M6CW+W7+0NgHlRvHLWRHDyhHEgxsflSG3yXOTLV9VWcuYazoVMWaTOsJrkILc2J4uWef8UN00r0Z92ejkQrbHOxdvwUDbIN6lu1N1+GkcUwWHMTItPzheK6fGVimsIACeaY8/OA1oBCfHV4pzBTghhVhYjUDorlUDiP4ggJWdeuzL8xEwVf53XOyBrn6GZkZrwe2pMl8Q0xDrIe0yifqo+mBjItVV/qMkXLRMlod7zbJL1GEKbGodS7/vKw1F70vLjbCrELcGj1g0TLFA3WyBko'
SPOTIFY_CLIENT = ""
SPOTIFY_SECRET = ""

REGION_NAME = 'us-east-1'


@app.route('/home', methods=['GET'])
def home():  # put application's code here

    get_secret()
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=SPOTIFY_CLIENT,
        client_secret=SPOTIFY_SECRET,
        redirect_uri=REDIRECT_URI,
        scope=("user-read-currently-playing", "user-read-private", "user-read-recently-played", "user-top-read", "user-read-email"),
        cache_handler=cache_handler
    )

    if request.args.get("code"):
        # Step 2. Being redirected from Spotify auth page
        auth_manager.get_access_token(request.args.get("code"))

        return redirect(REDIRECT_URI)

    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        # Step 1. Display sign in link when no token
        auth_url = auth_manager.get_authorize_url()

        return render_template('home-signed-out.html', url=auth_url)


    add_current_user()
    # Step 3. Signed in, display data
    spotify = spotipy.Spotify(auth_manager=auth_manager)
    # print(auth_manager.get_access_token())
    username = spotify.me()['display_name']
    return render_template('home-signed-in.html', display_name=username)



@app.route('/add-friend')
def search_friend():
    return render_template("add-friend.html")

@app.route('/add-friend', methods=['POST'])
def search_friend_post():
    email = request.form['email']
    add_friend(email)
    return redirect(url_for('friends'))


@app.route('/add-friend/<friend_email>')
def add_friend(friend_email):
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)

    friend_id = get_user_id_by_email(friend_email)
    table = dynamodb.Table('friends')
    username = get_users_name()
    curr_id = get_user_id()
    friend_username = get_users_user_name(friend_id)
    auth_manager = authenticate_current_user()
    table.put_item(
        Item={
            'id': curr_id,
            'username': username,
            'friend_id': friend_id,
            'friend_username': friend_username,

        }
    )

    return "added"

@app.route('/friends', methods = ['GET'])
def friends():
    id = get_user_id()

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    dynamodb_client = boto3.client('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    table = dynamodb.Table('friends')

    auth_manager = authenticate_current_user()
    response = dynamodb_client.query(
        TableName='friends',
        KeyConditionExpression='id = :id',
        ExpressionAttributeValues={
            ':id': {'S': id}
        }
    )
    items = response['Items']

    friends = []
    for x in items:
        friend_id = x.get('friend_id').get('S')

        friend_username = x.get('friend_username').get('S')
        dict = {'id': friend_id, 'username':friend_username}
        friends.append(dict)

    for i in range(5):
        dict = {'id': "", 'username': ""}
        friends.append(dict)

    return render_template("friends.html", friends=friends)


@app.route('/friends/<friend_id>')
def friendsProfile(friend_id):

    current_song = get_user_track(friend_id)
    current_song_album = get_user_current_track_album(friend_id)
    name = get_users_user_name(friend_id)

    print(current_song)
    recentTracks = get_user_recently_played(friend_id)

    recent1 = recentTracks[0]
    recent2 = recentTracks[1]
    recent3 = recentTracks[2]
    recent4 = recentTracks[3]
    recent5 = recentTracks[4]

    longTracks, longAlbums = get_user_top_tracks(friend_id, 'long_term')
    for i in range(5):
        longTracks.append("")
        longAlbums.append("")
    mediumTracks, mediumAlbums = get_user_top_tracks(friend_id, 'medium_term')

    for i in range(5):
        mediumTracks.append("")
        mediumAlbums.append("")
    shortTracks, shortAlbums = get_user_top_tracks(friend_id, 'short_term')

    for i in range(5):
        shortTracks.append("")
        shortAlbums.append("")

    artistNames, artistImages = get_top_artists(friend_id)
    for x in range(5):
        artistNames.append("")
        artistImages.append("")

    data = {"username": name, "current_song": current_song, "current_song_album": current_song_album,
            "recent1": recent1, "recent2": recent2, "recent3": recent3, "recent4": recent4, "recent5": recent5,
            "long1": longTracks[0], "longAlbum1": longAlbums[0], "long2": longTracks[1], "longAlbum2": longAlbums[1],
            "long3": longTracks[2], "longAlbum3": longAlbums[2], "long4": longTracks[3], "longAlbum4": longAlbums[3],
            "long5": longTracks[4], "longAlbum5": longAlbums[4],
            "medium1": mediumTracks[0], "medium2": mediumTracks[1], "medium3": mediumTracks[2],
            "medium4": mediumTracks[3], "medium5": mediumTracks[4], "mediumAlbum1": mediumAlbums[0],
            "mediumAlbum2": mediumAlbums[1], "mediumAlbum3": mediumAlbums[2], "mediumAlbum4": mediumAlbums[3],
            "mediumAlbum5": mediumAlbums[4],
            "short1": shortTracks[0], "short2": shortTracks[1], "short3": shortTracks[2], "short4": shortTracks[3],
            "short5": shortTracks[4], "shortAlbum1": shortAlbums[0], "shortAlbum2": shortAlbums[1],
            "shortAlbum3": shortAlbums[2], "shortAlbum4": shortAlbums[3], "shortAlbum5": shortAlbums[4],
            "artist1": artistNames[0], "artist2": artistNames[1], "artist3": artistNames[2], "artist4": artistNames[3],
            "artist5": artistNames[4], "artistImage1": artistImages[0], "artistImage2": artistImages[1],
            "artistImage3": artistImages[2], "artistImage4": artistImages[3], "artistImage5": artistImages[4]
            }


    return render_template("friends-profile.html", data=data)


@app.route('/me', methods=['GET'])
def me():

    current_song = getTrack()
    current_song_album = get_current_album()
    recentTracks = current_user_recently_played()
    recent1 = recentTracks[0]
    recent2 = recentTracks[1]
    recent3 = recentTracks[2]
    recent4 = recentTracks[3]
    recent5 = recentTracks[4]

    longTracks, longAlbums = get_top_tracks('long_term')
    for x in range(5):
        longTracks.append("")

    mediumTracks, mediumAlbums = get_top_tracks('medium_term')
    for x in range(5):
        mediumTracks.append("")

    shortTracks, shortAlbums = get_top_tracks('short_term')
    for x in range(5):
        shortTracks.append("")

    artistNames, artistImages = get_top_artists("")
    for x in range(5):
        artistNames.append("")
        artistImages.append("")


    data = {"current_song":current_song,"current_song_album": current_song_album,
            "recent1": recent1, "recent2":recent2,"recent3":recent3,"recent4":recent4,"recent5":recent5,
            "long1": longTracks[0], "longAlbum1":longAlbums[0], "long2": longTracks[1], "longAlbum2": longAlbums[1],  "long3":longTracks[2], "longAlbum3":longAlbums[2], "long4":longTracks[3], "longAlbum4":longAlbums[3], "long5":longTracks[4], "longAlbum5": longAlbums[4],
            "medium1": mediumTracks[0], "medium2":mediumTracks[1], "medium3":mediumTracks[2], "medium4":mediumTracks[3], "medium5":mediumTracks[4], "mediumAlbum1": mediumAlbums[0],"mediumAlbum2": mediumAlbums[1], "mediumAlbum3": mediumAlbums[2],"mediumAlbum4": mediumAlbums[3],"mediumAlbum5": mediumAlbums[4],
            "short1": shortTracks[0], "short2":shortTracks[1], "short3":shortTracks[2], "short4":shortTracks[3], "short5":shortTracks[4], "shortAlbum1":shortAlbums[0],"shortAlbum2":shortAlbums[1], "shortAlbum3":shortAlbums[2], "shortAlbum4":shortAlbums[3], "shortAlbum5":shortAlbums[4],
            "artist1":artistNames[0],"artist2":artistNames[1],"artist3":artistNames[2],"artist4":artistNames[3],"artist5":artistNames[4],"artistImage1": artistImages[0],"artistImage2": artistImages[1],"artistImage3": artistImages[2],"artistImage4": artistImages[3],"artistImage5": artistImages[4]
            }
    return render_template("my-profile.html", data=data)

def current_user_recently_played():
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=SPOTIFY_CLIENT,
        client_secret=SPOTIFY_SECRET,
        redirect_uri=url_for('getTrack', _external=True),
        cache_handler=cache_handler

    )

    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        return redirect('/home')
    sp = spotipy.Spotify(auth_manager=auth_manager)

    recentlyPlayed = []
    response = sp.current_user_recently_played(5)
    items = response['items']

    for track in items:
        itemName = track['track']['name']
        itemArtist = track['track']['artists'][0]['name']
        track = itemName + " by " + itemArtist
        recentlyPlayed.append(track)

    return recentlyPlayed

def get_user_recently_played(friend_id):

    token_info = get_user_token_info(friend_id)
    session.modified = True
    # if not authorized:
    # return redirect('/')
    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    recentlyPlayed = []
    response = sp.current_user_recently_played(5)
    items = response['items']

    for track in items:
        itemName = track['track']['name']
        itemArtist = track['track']['artists'][0]['name']
        track = itemName + " by " + itemArtist
        recentlyPlayed.append(track)

    return recentlyPlayed
def get_top_tracks(time):
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=SPOTIFY_CLIENT,
        client_secret=SPOTIFY_SECRET,
        redirect_uri=url_for('getTrack', _external=True),
        cache_handler=cache_handler

    )

    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        return redirect('/home')
    sp = spotipy.Spotify(auth_manager=auth_manager)
    topTracks = []
    response = sp.current_user_top_tracks(5, 0, time)
    items = response['items']

    for track in items:
        itemName = track['name']
        itemArtist = track['artists'][0]['name']
        track = itemName + " by " + itemArtist
        topTracks.append(track)

    topAlbums = []
    for album in items:
        image = album['album']['images'][0]['url']
        topAlbums.append(image)

    return topTracks, topAlbums

def get_user_top_tracks(friend_id, time):
    token_info = get_user_token_info(friend_id)
    session.modified = True
    # if not authorized:
    # return redirect('/')
    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    topTracks = []
    response = sp.current_user_top_tracks(5, 0, time)
    items = response['items']
    counter = 0
    for track in items:
        itemName = track['name']
        itemArtist = track['artists'][0]['name']
        track = itemName + " by " + itemArtist
        topTracks.append(track)

    topAlbums = []
    for album in items:
        image = album['album']['images'][0]['url']
        topAlbums.append(image)


    return topTracks, topAlbums
@app.route('/sign-out')
def sign_out():
    session.pop("token_info", None)
    return redirect('/home')


@app.route('/redirect')
def redirectPage():
    # sp_oauth = create_spotify_oauth()
    # code = request.args.get('code')
    # token_info = sp_oauth.get_access_token(code)
    # print(token_info)
    # session[TOKEN_INFO] = token_info

    # add_current_user()

    # check if usser is the db

    return redirect(url_for('getTrack', _external=True))

def get_top_artists(id):

    if id == "":
        cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
        auth_manager = spotipy.oauth2.SpotifyOAuth(
            client_id=SPOTIFY_CLIENT,
            client_secret=SPOTIFY_SECRET,
            redirect_uri=url_for('getTrack', _external=True),
            cache_handler=cache_handler

        )
        sp = spotipy.Spotify(auth_manager=auth_manager)
    else:
        token_info = get_user_token_info(id)
        session.modified = True
        # if not authorized:
        # return redirect('/')
        sp = spotipy.Spotify(auth=token_info.get('access_token'))



    response = sp.current_user_top_artists(5,0, 'long_term')

    items = response['items']
    artistNames = []
    artistImages = []

    for artist in items:
        name = artist['name']
        artistNames.append(name)

        image = artist['images'][0]['url']
        artistImages.append(image)

    return artistNames, artistImages






@app.route("/get-user-track/<id>")
def get_user_track(id):
    token_info = get_user_token_info(id)
    session.modified = True
    # if not authorized:
    # return redirect('/')
    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    name = get_users_user_name(id)
    output = ""
    results = sp.currently_playing()
    # results = sp.current_user_top_tracks(limit=10, offset=0, time_range='short_term')

    if results is None:
        return 'nothing'

    item = results['item']

    track = item["name"]
    artist = item["artists"][0]
    artist_name = artist["name"]

    # return name + " is listening to " + track + " - " + artist_name
    return track + ' by ' + artist_name
def get_current_album():
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=SPOTIFY_CLIENT,
        client_secret=SPOTIFY_SECRET,
        redirect_uri=url_for('getTrack', _external=True),
        cache_handler=cache_handler

    )

    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        return redirect('/home')
    sp = spotipy.Spotify(auth_manager=auth_manager)

    name = get_users_name()
    output = ""
    results = sp.currently_playing()


    if results is None:
        return "nothing"

    item = results['item']

    image = item['album']['images'][0]['url']

    return image
def get_user_current_track_album(id):
    token_info = get_user_token_info(id)
    session.modified = True
    # if not authorized:
    # return redirect('/')
    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    name = get_users_user_name(id)
    output = ""
    results = sp.currently_playing()
    # results = sp.current_user_top_tracks(limit=10, offset=0, time_range='short_term')

    if results is None:
        return 'nothing'

    item = results['item']

    image = item['album']['images'][0]['url']


    return image


@app.route("/listUsers")
def listUsers():
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    table = dynamodb.Table("users")
    items = table.scan()['Items']
    for item in items:
        print(item)


    return "test"
@app.route("/listFriends")
def listFriends():
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    table = dynamodb.Table("friends")
    items = table.scan()['Items']
    for item in items:
        print(item)


    return "test"


@app.route("/getTrack")
def getTrack():
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=SPOTIFY_CLIENT,
        client_secret=SPOTIFY_SECRET,
        redirect_uri=url_for('getTrack', _external=True),
        cache_handler=cache_handler

    )

    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        return redirect('/home')
    sp = spotipy.Spotify(auth_manager=auth_manager)

    name = get_users_name()
    output = ""
    results = sp.currently_playing()
    # results = sp.current_user_top_tracks(limit=10, offset=0, time_range='short_term')

    if results is None:
        return "nothing"

    item = results['item']

    track = item["name"]
    artist = item["artists"][0]
    artist_name = artist["name"]

    return track + ' by ' + artist_name


def get_user_token_info(id):
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    dynamodb_client = boto3.client('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                                   aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    table = dynamodb.Table('users')

    auth_manager = authenticate_current_user()
    response = dynamodb_client.query(
        TableName='users',
        KeyConditionExpression='id = :id',
        ExpressionAttributeValues={
            ':id': {'S': id}
        }
    )

    item = response['Items']
    access_token = item[0].get('access_token').get('S')
    refresh_token = item[0].get('refresh_token').get('S')
    expires_at = item[0].get('expires_at').get('N')

    token_info = {'access_token': access_token, 'refresh_token': refresh_token, 'expires_at': int(expires_at)}

    if auth_manager.is_token_expired(token_info):
        token_info = auth_manager.refresh_access_token(token_info.get('refresh_token'))
        token = token_info['access_token']
        sp = spotipy.Spotify(auth=token)

    return token_info
def get_user_token_info_by_email(email):

    #dynamodb_client = boto3.client('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                                   #aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)

    dynamodb = boto3.resource('dynamodb',region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                                   aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    table = dynamodb.Table('users')

    auth_manager = authenticate_current_user()
    response = table.scan(
       FilterExpression=Key('email').eq(email.lower())
    )

    print(email)
    print(response)
    item = response['Items']
    access_token = item[0].get('access_token')
    refresh_token = item[0].get('refresh_token')
    expires_at = item[0].get('expires_at')

    token_info = {'access_token': access_token, 'refresh_token': refresh_token, 'expires_at': int(expires_at)}

    if auth_manager.is_token_expired(token_info):
        token_info = auth_manager.refresh_access_token(token_info.get('refresh_token'))
        token = token_info['access_token']
        sp = spotipy.Spotify(auth=token)

    return token_info

def get_users_user_name(id):
    token_info = get_user_token_info(id)
    session.modified = True
    # if not authorized:
    # return redirect('/')

    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    results = sp.current_user()
    name = results["display_name"]

    return name

def get_user_id_by_email(email):
    token_info = get_user_token_info_by_email(email)
    session.modified=True

    sp = spotipy.Spotify(auth=token_info.get('access_token'))
    results = sp.current_user()
    id = results['id']

    return id



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

def get_user_email():
    auth_manager = authenticate_current_user()
    sp = spotipy.Spotify(auth_manager=auth_manager)
    results = sp.current_user()
    email = results['email']

    return email

def authenticate_current_user():
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=SPOTIFY_CLIENT,
        client_secret=SPOTIFY_SECRET,
        redirect_uri=url_for('getTrack', _external=True),
        cache_handler=cache_handler

    )
    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        return redirect('/home')

    return auth_manager


def add_current_user():
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1',aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token = aws_session_token)
    table = dynamodb.Table('users')

    username = get_users_name()
    id = get_user_id()
    email = get_user_email()

    auth_manager = authenticate_current_user()
    table.put_item(
        Item={
            'id': id,
            'username': username,
            'email':email,
            'access_token': auth_manager.get_cached_token().get('access_token'),
            'refresh_token': auth_manager.get_cached_token().get('refresh_token'),
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
    # print(item)
    return


def get_secret():
    secret_name = "credentials"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        aws_access_key_id = aws_access_key_id,
        aws_secret_access_key = aws_secret_access_key,
        aws_session_token= aws_session_token
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    # Decrypts secret using the associated KMS key.
    secret = get_secret_value_response['SecretString']

    # Your code goes here.
    res = json.loads(secret)

    global SPOTIFY_CLIENT
    SPOTIFY_CLIENT= res.get('spotify_client')
    global SPOTIFY_SECRET
    SPOTIFY_SECRET= res.get('spotify_secret')
    return res


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)




