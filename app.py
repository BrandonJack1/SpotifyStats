import json
from flask_cors import CORS
import boto3
from flask import Flask, request, url_for, session, redirect, render_template
from flask_session import Session
import os
import spotipy
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(64)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './.flask_session/'
TOKEN_INFO = "token_info"

Session(app)
CORS(app, supports_credentials=True)
REDIRECT_URI = 'http://127.0.0.1:5000/home'

# AWS credentials
aws_access_key_id = "key"
aws_secret_access_key = "key"
aws_session_token = "key"
REGION_NAME = 'us-east-1'


@app.route('/home', methods=['GET'])
def home():
    # initialize API credentials
    get_secret()

    # assign cache session handler
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)

    # initialize oAuth
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=SPOTIFY_CLIENT,
        client_secret=SPOTIFY_SECRET,
        redirect_uri=REDIRECT_URI,
        scope=("user-read-currently-playing", "user-read-private", "user-read-recently-played", "user-top-read",
               "user-read-email"),
        cache_handler=cache_handler
    )

    # if user is already signed in, send them back to home page
    if request.args.get("code"):
        auth_manager.get_access_token(request.args.get("code"))
        return redirect(REDIRECT_URI)

    # if user is not signed in, prompt them to sign in via Spotify
    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        auth_url = auth_manager.get_authorize_url()

        return render_template('home-signed-out.html', url=auth_url)

    # if the user hasn't already been added to the db, add them
    add_current_user()

    # assign spotify auth manager for authentication for each API Request
    spotify = spotipy.Spotify(auth_manager=auth_manager)

    # HTML render template variables
    username = spotify.me()['display_name']
    return render_template('home-signed-in.html', display_name=username)


def get_secret():
    secret_name = "credentials"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token
    )

    # get API keys
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

    # get API keys from json
    res = json.loads(secret)
    global SPOTIFY_CLIENT
    SPOTIFY_CLIENT = res.get('spotify_client')
    global SPOTIFY_SECRET
    SPOTIFY_SECRET = res.get('spotify_secret')
    return res

@app.route('/add-friend')
def search_friend():
    return render_template("add-friend.html")


@app.route('/add-friend', methods=['POST'])
def search_friend_post():
    # get email from text box
    email = request.form['email']

    # add friend to users friend list
    add_friend(email)
    return redirect(url_for('friends'))


@app.route('/add-friend/<friend_email>')
def add_friend(friend_email):
    # db credentials
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)

    # get users id from using their email
    friend_id = get_user_id_by_email(friend_email)

    table = dynamodb.Table('friends')
    username = get_users_name()
    curr_id = get_user_id()

    # get friends spotify username
    friend_username = get_users_user_name(friend_id)

    # put friend in the table
    table.put_item(
        Item={
            'id': curr_id,
            'username': username,
            'friend_id': friend_id,
            'friend_username': friend_username,

        }
    )
    return "added"

@app.route('/friends', methods=['GET'])
def friends():

    # get current users id
    id = get_user_id()

    dynamodb = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    dynamodb_client = boto3.client('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                                   aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)

    # get friends of current user
    response = dynamodb_client.query(
        TableName='friends',
        KeyConditionExpression='id = :id',
        ExpressionAttributeValues={
            ':id': {'S': id}
        }
    )
    items = response['Items']

    # display friends from response dictionary
    friends = []
    for x in items:
        friend_id = x.get('friend_id').get('S')
        friend_username = x.get('friend_username').get('S')
        dict = {'id': friend_id, 'username': friend_username}
        friends.append(dict)

    for i in range(5):
        dict = {'id': "", 'username': ""}
        friends.append(dict)

    return render_template("friends.html", friends=friends)


@app.route('/friends/<friend_id>')
def friendsProfile(friend_id):

    # get friends current song with their id
    current_song = get_user_track(friend_id)

    # get friends current album art with their id
    current_song_album = get_user_current_track_album(friend_id)

    # get friends username with their id
    name = get_users_user_name(friend_id)

    # get friends recent tracks with their id
    recentTracks = get_user_recently_played(friend_id)

    # assign recent songs to variables
    recent1 = recentTracks[0]
    recent2 = recentTracks[1]
    recent3 = recentTracks[2]
    recent4 = recentTracks[3]
    recent5 = recentTracks[4]

    # for the top songs of all time assign the track and album art to the arrays
    longTracks, longAlbums = get_user_top_tracks(friend_id, 'long_term')
    # append blanks in case there isn't 5 present to prevent null errors
    for i in range(5):
        longTracks.append("")
        longAlbums.append("")

    # for top songs past 6 months, assign each track and album art to the arrays
    mediumTracks, mediumAlbums = get_user_top_tracks(friend_id, 'medium_term')
    # append blanks in case there isn't 5 present to prevent null errors
    for i in range(5):
        mediumTracks.append("")
        mediumAlbums.append("")

    # for top songs past month, assign each track and album art to the arrays
    shortTracks, shortAlbums = get_user_top_tracks(friend_id, 'short_term')
    # append blanks in case there isn't 5 present to prevent null errors
    for i in range(5):
        shortTracks.append("")
        shortAlbums.append("")

    # For the top artists, assign each artist and image to the arrays
    artistNames, artistImages = get_top_artists(friend_id)
    # append blanks in case there isn't 5 present to prevent null errors
    for x in range(5):
        artistNames.append("")
        artistImages.append("")

    # data to be sent to HTML render template
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
    # same as friend method above except for current user
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

    data = {"current_song": current_song, "current_song_album": current_song_album,
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
    return render_template("my-profile.html", data=data)


def get_user_recently_played(friend_id):

    # get friends token info from db
    token_info = get_user_token_info(friend_id)
    session.modified = True

    # get authentication using friends tokens
    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    # recently played array
    recentlyPlayed = []

    # get users last 5 played songs
    response = sp.current_user_recently_played(5)
    items = response['items']

    # for each item in the response, add it to the recently played song
    for track in items:
        itemName = track['track']['name']
        itemArtist = track['track']['artists'][0]['name']
        track = itemName + " by " + itemArtist
        recentlyPlayed.append(track)

    return recentlyPlayed


def get_top_tracks(time):

    # assign cache handler
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)

    # setup auth manager
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=SPOTIFY_CLIENT,
        client_secret=SPOTIFY_SECRET,
        redirect_uri=url_for('getTrack', _external=True),
        cache_handler=cache_handler

    )

    # if the user is not signed in, return them home to start the sign in process
    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        return redirect('/home')

    # assign auth manager for authentication for each API request
    sp = spotipy.Spotify(auth_manager=auth_manager)

    # top tracks array
    topTracks = []

    # get users top tracks for the specified time
    response = sp.current_user_top_tracks(5, 0, time)
    items = response['items']

    # iterate through response and append tracks to array
    for track in items:
        itemName = track['name']
        itemArtist = track['artists'][0]['name']
        track = itemName + " by " + itemArtist
        topTracks.append(track)

    # iterate through response and append album art to array
    topAlbums = []
    for album in items:
        image = album['album']['images'][0]['url']
        topAlbums.append(image)

    return topTracks, topAlbums


def get_user_top_tracks(friend_id, time):

    # get friends token info
    token_info = get_user_token_info(friend_id)
    session.modified = True

    # use friends token info for the auth manager
    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    # top tracks array
    topTracks = []
    # top albums array
    topAlbums = []

    # get top tracks for the time period specified
    response = sp.current_user_top_tracks(5, 0, time)
    items = response['items']

    # iterate through the response and add tracks to the array
    for track in items:
        itemName = track['name']
        itemArtist = track['artists'][0]['name']
        track = itemName + " by " + itemArtist
        topTracks.append(track)

    # iterate through the response and add tracks to the array
    for album in items:
        image = album['album']['images'][0]['url']
        topAlbums.append(image)

    return topTracks, topAlbums


def get_users_user_name(id):
    # get friends token info
    token_info = get_user_token_info(id)
    session.modified = True

    # setup auth manager with friends access token
    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    # get friends display name
    results = sp.current_user()
    name = results["display_name"]

    return name


def get_user_id_by_email(email):
    # get users token info with their email from db
    token_info = get_user_token_info_by_email(email)
    session.modified = True

    # setup auth manager with the users token info
    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    # get users spotify ID from the API
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

@app.route('/sign-out')
def sign_out():
    # drop users token info from the session
    session.pop("token_info", None)
    return redirect('/home')

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

    response = sp.current_user_top_artists(5, 0, 'long_term')

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

    # get users token info
    token_info = get_user_token_info(id)
    session.modified = True

    # setup auth manager for authentication for each API request
    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    results = sp.currently_playing()

    # if the user is not listening anything return nothing
    if results is None:
        return 'nothing'

    item = results['item']
    track = item["name"]
    artist = item["artists"][0]
    artist_name = artist["name"]

    return track + ' by ' + artist_name


def get_current_album():

    # assign cache handler
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)

    # auth manager setup
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=SPOTIFY_CLIENT,
        client_secret=SPOTIFY_SECRET,
        redirect_uri=url_for('getTrack', _external=True),
        cache_handler=cache_handler

    )

    # if the user is not currently signed in, return them home to start the sign in process
    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        return redirect('/home')

    # assign auth manager used to authenticate each API request
    sp = spotipy.Spotify(auth_manager=auth_manager)

    results = sp.currently_playing()

    # if the user is not currently listening to anything return nothing for the album
    if results is None:
        return "nothing"

    item = results['item']
    image = item['album']['images'][0]['url']

    return image


def get_user_current_track_album(id):

    # get friends token info using their id
    token_info = get_user_token_info(id)
    session.modified = True

    # setup auth manager
    sp = spotipy.Spotify(auth=token_info.get('access_token'))

    results = sp.currently_playing()

    # if the friend is currently not listening to anything then return nothing
    if results is None:
        return 'nothing'

    item = results['item']
    image = item['album']['images'][0]['url']

    return image

@app.route("/getTrack")
def getTrack():

    # assign cache handler
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)

    # setup auth manager
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=SPOTIFY_CLIENT,
        client_secret=SPOTIFY_SECRET,
        redirect_uri=url_for('getTrack', _external=True),
        cache_handler=cache_handler

    )

    # if the user is not signed in then return home
    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        return redirect('/home')

    # assign auth manager used to authenticate each API request
    sp = spotipy.Spotify(auth_manager=auth_manager)

    results = sp.currently_playing()

    if results is None:
        return "nothing"

    item = results['item']

    track = item["name"]
    artist = item["artists"][0]
    artist_name = artist["name"]

    return track + ' by ' + artist_name


def get_user_token_info(id):

    # db setup
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    dynamodb_client = boto3.client('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                                   aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)

    # start auth manager
    auth_manager = authenticate_current_user()

    # get specified user
    response = dynamodb_client.query(
        TableName='users',
        KeyConditionExpression='id = :id',
        ExpressionAttributeValues={
            ':id': {'S': id}
        }
    )

    # get users token info from the db
    item = response['Items']
    access_token = item[0].get('access_token').get('S')
    refresh_token = item[0].get('refresh_token').get('S')
    expires_at = item[0].get('expires_at').get('N')

    # put token info into dictionary
    token_info = {'access_token': access_token, 'refresh_token': refresh_token, 'expires_at': int(expires_at)}

    # if the users token info is expired then refresh access token
    if auth_manager.is_token_expired(token_info):
        token_info = auth_manager.refresh_access_token(token_info.get('refresh_token'))
        token = token_info['access_token']
        sp = spotipy.Spotify(auth=token)

    return token_info


def get_user_token_info_by_email(email):

    # setup db
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    table = dynamodb.Table('users')

    # auth manager setup
    auth_manager = authenticate_current_user()

    # get user that matches the specified email
    response = table.scan(
        FilterExpression=Key('email').eq(email.lower())
    )

    # pull token info from request
    item = response['Items']
    access_token = item[0].get('access_token')
    refresh_token = item[0].get('refresh_token')
    expires_at = item[0].get('expires_at')

    # put token info into a dictionary
    token_info = {'access_token': access_token, 'refresh_token': refresh_token, 'expires_at': int(expires_at)}

    # if the token info access token is expired then refresh it
    if auth_manager.is_token_expired(token_info):
        token_info = auth_manager.refresh_access_token(token_info.get('refresh_token'))
        token = token_info['access_token']
        sp = spotipy.Spotify(auth=token)

    return token_info

def authenticate_current_user():

    # get current user from cache handler
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)

    # setup auth manager
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

    # setup db
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id=aws_access_key_id,
                              aws_secret_access_key=aws_secret_access_key, aws_session_token=aws_session_token)
    table = dynamodb.Table('users')

    # get current users information
    username = get_users_name()
    id = get_user_id()
    email = get_user_email()
    auth_manager = authenticate_current_user()

    # put users info into the db
    table.put_item(
        Item={
            'id': id,
            'username': username,
            'email': email,
            'access_token': auth_manager.get_cached_token().get('access_token'),
            'refresh_token': auth_manager.get_cached_token().get('refresh_token'),
            'expires_at': auth_manager.get_cached_token().get('expires_at')
        }
    )
    return

def current_user_recently_played():
    # assign cache handler
    cache_handler = spotipy.cache_handler.FlaskSessionCacheHandler(session)

    # assign auth manager
    auth_manager = spotipy.oauth2.SpotifyOAuth(
        client_id=SPOTIFY_CLIENT,
        client_secret=SPOTIFY_SECRET,
        redirect_uri=url_for('getTrack', _external=True),
        cache_handler=cache_handler

    )

    # if the user is not signed in, return them to home page to start sign in process
    if not auth_manager.validate_token(cache_handler.get_cached_token()):
        return redirect('/home')

    # assign auth manager for authentication for each request
    sp = spotipy.Spotify(auth_manager=auth_manager)

    # recently played array
    recentlyPlayed = []

    # get users last 5 played songs from api
    response = sp.current_user_recently_played(5)
    items = response['items']

    # append each item in the response to the recently played array
    for track in items:
        itemName = track['track']['name']
        itemArtist = track['track']['artists'][0]['name']
        track = itemName + " by " + itemArtist
        recentlyPlayed.append(track)

    return recentlyPlayed


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=80)
