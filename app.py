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

app = Flask(__name__)

# These are needed to verify my app with spotify
# client_id = os.getenv("CLIENT_ID")
# client_secret = os.getenv("CLIENT_SECRET")

# app.secret_key = "fdfdasjklnfdlsf"
# app.config["SESSION_COOKIE_NAME"] = "Brandon Cookie"
app.config['SECRET_KEY'] = os.urandom(64)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './.flask_session/'
TOKEN_INFO = "token_info"
Session(app)
CORS(app, supports_credentials=True)
#REDIRECT_URI = 'ec2-18-233-84-132.compute-1.amazonaws.com:80/home'
REDIRECT_URI = 'http://127.0.0.1:5000/home'
aws_access_key_id='ASIA3TN67ELM77ALY3VN'
aws_secret_access_key='hOwmQMvdYW7wXx8OOb8w9LnK/d/4pvZFaLdV4GdW'
aws_session_token='FwoGZXIvYXdzEAYaDJSkMmM2jTVfgqtWIyLAASh8b7PeQIZQJxccIlfYHAgBHTE7WxmKG3XxhLqk09UFCFnO42azqKylNiTh6eWaYizXdAv4wa5x6EK/uGuJVhtL5X1CCfuZy8cpp7+bfIlHdusTydIyz12ywWKzjXne59fGj50TUlmUrlGVFHs3wEKCL8C/RZpEI4u0FOVMA9kXs1CgErnF4IJ4Mf0e4ry7FZOVAXSYoPp5hW9AdRPbFhhEdKGssBsaN/sUUPwUogdUtA3/GMPn63p/lVeWjirLDSie9NulBjItERREtaAy//CWnz8jJrYV8GOqJrqiKC5qjbwHMQPVL+OilcgHNvz+t8wg2+zW'
REGION_NAME = 'us-east-1'


@app.route('/home', methods=['GET'])
def home():  # put application's code here

    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=get_secret().get('spotify_client'),
        client_secret=get_secret().get('spotify_secret'),
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

    return redirect(url_for('home'))


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
    name = get_users_user_name(friend_id)

    print(current_song)
    recentTracks = get_user_recently_played(friend_id)

    recent1 = recentTracks[0]
    recent2 = recentTracks[1]
    recent3 = recentTracks[2]
    recent4 = recentTracks[3]
    recent5 = recentTracks[4]

    longTracks = get_user_top_tracks(friend_id, 'long_term')

    for i in range(5):
        longTracks.append("")
    mediumTracks = get_user_top_tracks(friend_id, 'medium_term')

    for i in range(5):
        mediumTracks.append("")
    shortTracks = get_user_top_tracks(friend_id, 'short_term')

    for i in range(5):
        shortTracks.append("")

    return f'<h2> {name} is currently listening to <b> {current_song}</b> \n\n' \
           f'<h2> Some of the songs {name} recently played: \n' \
           f'<h4>1. {recent1}\n' \
           f'<h4>2. {recent2}\n' \
           f'<h4>3. {recent3}\n' \
           f'<h4>4. {recent4}\n' \
           f'<h4>5. {recent5}\n' \
           f'<h2> {name}s top tracks:\n' \
           f'<h3> All Time: ' \
           f'<h4> 1. {longTracks[0]}\t\t' \
           f'<h4> 2. {longTracks[1]}\t\t' \
           f'<h4> 3. {longTracks[2]}\t\t' \
           f'<h4> 4. {longTracks[3]}\t\t' \
           f'<h4> 5. {longTracks[4]}\t\t' \
           f'<h3> Past 6 Months:' \
           f'<h4> 1. {mediumTracks[0]}\t\t' \
           f'<h4> 2. {mediumTracks[1]}\t\t' \
           f'<h4> 3. {mediumTracks[2]}\t\t' \
           f'<h4> 4. {mediumTracks[3]}\t\t' \
           f'<h4> 5. {mediumTracks[4]}\t\t' \
           f'<h3> Past 4 Weeks:' \
           f'<h4> 1. {shortTracks[0]}\t\t' \
           f'<h4> 2. {shortTracks[1]}\t\t' \
           f'<h4> 3. {shortTracks[2]}\t\t' \
           f'<h4> 4. {shortTracks[3]}\t\t' \
           f'<h4> 5. {shortTracks[4]}\t\t' \
 \

@app.route('/me', methods=['GET'])
def me():

    current_song = getTrack()
    recentTracks = current_user_recently_played()
    recent1 = recentTracks[0]
    recent2 = recentTracks[1]
    recent3 = recentTracks[2]
    recent4 = recentTracks[3]
    recent5 = recentTracks[4]

    longTracks = get_top_tracks('long_term')
    for x in range(5):
        longTracks.append("")

    mediumTracks = get_top_tracks('medium_term')
    for x in range(5):
        mediumTracks.append("")

    shortTracks = get_top_tracks('short_term')
    for x in range(5):
        shortTracks.append("")

    return f'<h2> You are currently listenting to <b>{current_song}</b> \n\n' \
           f'<h2> Some of the songs you recently played: \n' \
           f'<h4>1. {recent1}\n' \
           f'<h4>2. {recent2}\n' \
           f'<h4>3. {recent3}\n' \
           f'<h4>4. {recent4}\n' \
           f'<h4>5. {recent5}\n'\
           f'<h2> Your top tracks:\n'\
           f'<h3> All Time: ' \
           f'<h4> 1. {longTracks[0]}\t\t' \
           f'<h4> 2. {longTracks[1]}\t\t' \
           f'<h4> 3. {longTracks[2]}\t\t' \
           f'<h4> 4. {longTracks[3]}\t\t' \
           f'<h4> 5. {longTracks[4]}\t\t' \
           f'<h3> Past 6 Months:' \
           f'<h4> 1. {mediumTracks[0]}\t\t' \
           f'<h4> 2. {mediumTracks[1]}\t\t' \
           f'<h4> 3. {mediumTracks[2]}\t\t' \
           f'<h4> 4. {mediumTracks[3]}\t\t' \
           f'<h4> 5. {mediumTracks[4]}\t\t' \
           f'<h3> Past 4 Weeks:' \
           f'<h4> 1. {shortTracks[0]}\t\t' \
           f'<h4> 2. {shortTracks[1]}\t\t' \
           f'<h4> 3. {shortTracks[2]}\t\t' \
           f'<h4> 4. {shortTracks[3]}\t\t' \
           f'<h4> 5. {shortTracks[4]}\t\t' \
 \
 \
 \


def current_user_recently_played():
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=get_secret().get('spotify_client'),
        client_secret=get_secret().get('spotify_secret'),
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
        client_id=get_secret().get('spotify_client'),
        client_secret=get_secret().get('spotify_secret'),
        redirect_uri=url_for('getTrack', _external=True),
        cache_handler=cache_handler

    )

    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        return redirect('/home')
    sp = spotipy.Spotify(auth_manager=auth_manager)
    topTracks = []
    response = sp.current_user_top_tracks(5, 0, time)
    items = response['items']
    counter = 0
    for track in items:
        itemName = track['name']
        itemArtist = track['artists'][0]['name']
        track = itemName + " by " + itemArtist
        topTracks.append(track)


    return topTracks

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


    return topTracks
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


@app.route("/listUsers")
def listUsers():
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    table = dynamodb.Table("users")
    items = table.scan()['Items']
    for item in items:
        print(item)

    get_secret()
    return "test"
@app.route("/listFriends")
def listFriends():
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    table = dynamodb.Table("friends")
    items = table.scan()['Items']
    for item in items:
        print(item)

    get_secret()
    return "test"


@app.route("/getTrack")
def getTrack():
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=get_secret().get('spotify_client'),
        client_secret=get_secret().get('spotify_secret'),
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
        client_id=get_secret().get('spotify_client'),
        client_secret=get_secret().get('spotify_secret'),
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
    return res


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)

