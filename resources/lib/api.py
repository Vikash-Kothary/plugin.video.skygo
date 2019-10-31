import hashlib
import time
import re

import arrow

from .matthuisman import userdata, plugin, settings
from .matthuisman.session import Session
from .matthuisman.log import log
from .matthuisman.exceptions import Error

from .constants import HEADERS, AUTH_URL, RENEW_URL, CHANNELS_URL, TOKEN_URL, DEVICE_IP, CONTENT_URL, PLAY_URL, WIDEVINE_URL, SUBSCRIPTIONS_URL
from .language import _

class APIError(Error):
    pass

class API(object):
    def new_session(self):
        self.logged_in = False
        self._session = Session(HEADERS)
        self._set_authentication()

    def _set_authentication(self):
        token = userdata.get('access_token')
        if not token:
            return

        self._session.headers.update({'sky-x-access-token': token})
        self.logged_in = True

    def series(self, id):
        return self._session.get(CONTENT_URL + id).json()

    def content(self, section='', sortby='TITLE', text='', title=None, channels='', start=0):
        params = {
            'title': title or '',
            'genre': '',
            'rating': '',
            'text': text,
            'sortBy': sortby,
            'lastChance': 'true' if sortby == 'LASTCHANCE' else 'false',
            'type': '',
            'channel': channels,
            'section': section,
            'size': 100,
            'start': start,
        }

        return self._session.get(CONTENT_URL, params=params).json()

    def channels(self):
        data = self._session.get(CHANNELS_URL).json()
        return data['entries']
        
    def login(self, username, password):
        device_id = hashlib.md5(username.encode('utf8')).hexdigest()

        data = {
            "deviceDetails": "test",
            "deviceID": device_id,
            "deviceIP": DEVICE_IP,
            "password": password,
            "username": username
        }

        resp = self._session.post(AUTH_URL, json=data)
        data = resp.json()
        if resp.status_code != 200 or 'sessiontoken' not in data:
            raise APIError(_(_.LOGIN_ERROR, message=data.get('message')))

        userdata.set('access_token', data['sessiontoken'])
        userdata.set('device_id', device_id)

        if settings.getBool('save_password', False):
            userdata.set('pswd', password)

        self._set_authentication()

        data = self._session.get(SUBSCRIPTIONS_URL.format(data['profileId'])).json()
        userdata.set('subscriptions', data['onlineSubscriptions'])

    def _renew_token(self):
        password = userdata.get('pswd')

        if password:
            self.login(userdata.get('username'), password)
            return

        data = {
            "deviceID": userdata.get('device_id'),
            "deviceIP": DEVICE_IP,
            "sessionToken": userdata.get('access_token'),
        }

        resp = self._session.post(RENEW_URL, json=data)
        data = resp.json()

        if resp.status_code != 200 or 'sessiontoken' not in data:
            raise APIError(_(_.RENEW_TOKEN_ERROR, message=data.get('message')))

        userdata.set('access_token', data['sessiontoken'])

        self._set_authentication()

    def _get_play_token(self):
        self._renew_token()

        params = {
            'profileId':   userdata.get('device_id'),
            'deviceId':    userdata.get('device_id'),
            'partnerId':   'skygo',
            'description': 'ANDROID',
        }

        resp = self._session.get(TOKEN_URL, params=params)
        data = resp.json()

        if resp.status_code != 200 or 'token' not in data:
            raise APIError(_(_.TOKEN_ERROR, message=data.get('message')))

        return data['token']

    def play_media(self, id):
        token = self._get_play_token()

        params = {
            'form': 'json',
            'types': None,
            'fields': 'id,content',
            'byId': id,
        }

        data = self._session.get(PLAY_URL, params=params).json()

        videos = data['entries'][0]['media$content']

        chosen = videos[0]
        for video in videos:
            if video['plfile$format'] == 'MPEG-DASH':
                chosen = video
                break

        if chosen['plfile$format'].upper() == 'F4M':
            raise APIError(_.ADOBE_ERROR)
 
        url = '{}&auth={}&formats=mpeg-dash&tracking=true&format=SMIL'.format(chosen['plfile$url'], token)
        r = self._session.get(url)

        smil = r.text
        
        url = re.search('video src="(.*?)"', smil)
        if not url:
            error_msg = re.search('title="(.*?)"', smil)
            if not error_msg:
                error_msg = ''
            else:
                error_msg = error_msg.group(1)

            raise APIError(_(_.PLAY_ERROR, message=error_msg))
            
        url     = url.group(1)
        pid     = re.search('pid=(.*?)\|', smil).group(1)
        license = WIDEVINE_URL.format(token=token, pid=pid, challenge='B{SSM}')

        return url, license

    def logout(self):
        userdata.delete('device_id')
        userdata.delete('access_token')
        userdata.delete('pswd')
        userdata.delete('subscriptions')
        self.new_session()