import os

from flask import Flask, session, url_for, redirect, request
from dotenv import load_dotenv
from spotipy import Spotify
from spotipy.oauth2 import SpotifyOAuth
from spotipy.cache_handler import FlaskSessionCacheHandler

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(64)

# Defining our API's client ID and secret.
# A better code practice is to store it as environment variables or with more security
client_id = os.environ.get('CLIENT_ID')
client_secret = os.environ.get('CLIENT_SECRET')
redirect_uri = os.environ.get('REDIRECT_URL')
scope = 'playlist-read-private'

# creating the session
cache_handler = FlaskSessionCacheHandler(session)
#creating the authentication manager
sp_oauth = SpotifyOAuth(
    client_id=client_id,
    client_secret=client_secret,
    redirect_uri=redirect_uri,
    scope=scope,
    cache_handler=cache_handler,
    show_dialog=True
)

# Create an instance of client within Spotify API
sp = Spotify(auth_manager=sp_oauth)

# Creating first destiny to the API reach our code
# main method
@app.route('/')
def home():
    # Checking if the user is logged or not
    if not sp_oauth.validate_token(cache_handler.get_cached_token()):
        auth_url = sp_oauth.get_authorize_url()
        return redirect(auth_url)
    
    # Get an url and redirect to 'get_playlists'
    return redirect(url_for('get_playlists'))

# This method is where Spotify comes back after authenticating
@app.route('/callback')
def callback():
    sp_oauth.get_access_token(request.args['code'])
    return redirect(url_for('get_playlists'))

# Creating the method that actually gets the playlists
@app.route('/get_playlists')
def get_playlists():
      # Checking if the user is logged or not
    if not sp_oauth.validate_token(cache_handler.get_cached_token()):
        auth_url = sp_oauth.get_authorize_url()
        return redirect(auth_url)
    
    #If user is logged in, now we should call the method current_user_playlists
    playlists = sp.current_user_playlists()
    playlists_info = [(pl['name'], pl['external_urls']['spotify']) for pl in playlists['items']]
    playlists_html = '<br>'.join([f'{name}: {url}' for name, url in playlists_info])

    return playlists_html

# Creating the log out session
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(port=5000)

