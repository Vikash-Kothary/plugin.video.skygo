import os
import re
import shutil
import posixpath
import time

from threading import Thread
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urlparse import urlparse, urljoin

import xbmc

from . import userdata, gui, router, inputstream, router
from .constants import ADDON_DEV
from .language import _
from .constants import QUALITY_ASK, QUALITY_BEST, QUALITY_CUSTOM, QUALITY_PASS, QUALITY_LOWEST, DEFAULT_QUALITY, ROUTE_QUALITY
from .log import log
from .exceptions import Error
from .parser import M3U8, MPD

PROXY_FILE = xbmc.translatePath('special://temp/proxy_playlist.m3u8')

def select_quality(qualities=None, is_settings=False):
    options = []

    if is_settings:
        options.append([QUALITY_ASK, _.QUALITY_ASK])

    options.append([QUALITY_BEST, _.QUALITY_BEST])
    options.extend(qualities or [[QUALITY_CUSTOM, _.QUALITY_CUSTOM]])
    options.append([QUALITY_LOWEST, _.QUALITY_LOWEST])
    options.append([QUALITY_PASS, _.QUALITY_PASSTHROUGH])

    values = [x[0] for x in options]
    labels = [x[1] for x in options]

    if is_settings:
        current = userdata.get('quality', DEFAULT_QUALITY)
    else:
        current = userdata.get('last_quality')

    default = 0
    if current:
        try:
            default = values.index(current)
        except:
            if not qualities:
                default = values.index(QUALITY_CUSTOM) if current > 0 else 0
            else:
                default = values.index(qualities[-1][0])

                for quality in qualities:
                    if quality[0] <= current:
                        default = values.index(quality[0])
                        break
                
    index = gui.select(_.SELECT_QUALITY, labels, preselect=default)
    if index < 0:
        return None

    value = values[index]
    label = labels[index]

    if value == QUALITY_CUSTOM:
        value = gui.numeric(_.QUALITY_CUSTOM_INPUT, default=current if current > 0 else '')
        if not value:
            return None

        value = int(value)
        label = _(_.QUALITY_BITRATE, bandwidth=float(value)/1000000, resolution='', fps='').strip()

    if is_settings:
        userdata.set('quality', value)
        gui.notification(_(_.QUALITY_SET, label=label))
    else:
        userdata.set('last_quality', value)

    return value

@router.route(ROUTE_QUALITY)
def _select_quality(**kwargs):
    select_quality(is_settings=True)

class MainHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', os.path.getsize(PROXY_FILE))
        self.send_header('Content-Type', 'application/x-mpegURL')
        self.end_headers()

        with open(PROXY_FILE, 'rb') as f:
            shutil.copyfileobj(f, self.wfile)

    def log_message(self, format, *args):
        log.debug('Proxy - {}'.format(format%args))

def parse_m3u8(item, quality):
    from .session import Session

    playlist_url = item.path.split('|')[0]

    try:
        resp = Session().get(playlist_url, headers=item.headers, cookies=item.cookies)
    except Exception as e:
        log.exception(e)
        result = False
    else:
        result = resp.ok

    if not result:
        raise Error(_(_.PLAYBACK_ERROR, error_code=resp.status_code))

    item.headers = resp.request.headers
    item.cookies.update(resp.cookies)
    item.mimetype = 'application/x-mpegURL'

    m3u8 = M3U8(resp.text, resp.url)
    qualities = m3u8.qualities()
    if not qualities:
        return True

    if quality == QUALITY_ASK:
        quality = select_quality(qualities)
        if not quality:
            return False

    if quality == QUALITY_PASS:
        return True

    text = m3u8.at_quality(quality)
    with open(PROXY_FILE, 'wb') as f:
        f.write(text)

    server_address = ('127.0.0.1', 9977)

    ## need to use .m3u8 or headers break
    item.path = 'http://{host}:{port}/{random}/playlist.m3u8'.format(host=server_address[0], port=server_address[1], random=int(time.time()))

    httpd          = HTTPServer(server_address, MainHandler)
    httpd.timeout  = 5
    httpd_thread   = Thread(target=single_request, args=(httpd,))
    httpd_thread.daemon = True

    if not ADDON_DEV:
        httpd_thread.start()

    return True

def single_request(httpd):
    log.debug('Single Request Thread: STARTED')
    httpd.handle_request()
    log.debug('Single Request Thread: DONE')
    
    try:
        os.remove(PROXY_FILE)
    except:
        pass

def reset_ia_settings(settings):
    log.debug('Quality Settings Reset Thread: STARTED')

    monitor    = xbmc.Monitor()
    player     = xbmc.Player()
    sleep_time = 100#ms

    #wait upto 3 seconds for playback to start
    count = 0
    while not monitor.abortRequested():
        if player.isPlaying():
            break

        if count > 3*(1000/sleep_time):
            break

        count += 1
        xbmc.sleep(sleep_time)

    #wait upto 30 seconds for playback to start
    count = 0
    while not monitor.abortRequested():
        if not player.isPlaying() or player.getTime() > 0:
            break

        if count > 30*(1000/sleep_time):
            break

        count += 1
        xbmc.sleep(sleep_time)

    inputstream.set_settings(settings)

    log.debug('Quality Settings Reset Thread: DONE')

def parse_ia(item, quality):
    from .session import Session

    playlist_url = item.path.split('|')[0]

    try:
        resp = Session().get(playlist_url, headers=item.headers, cookies=item.cookies)
    except Exception as e:
        log.exception(e)
        result = False
    else:
        result = resp.ok

    if not result:
        raise Error(_(_.PLAYBACK_ERROR, error_code=resp.status_code))

    min_bandwidth, max_bandwidth = quality, quality

    if item.mimetype == 'application/x-mpegURL':
        m3u8 = M3U8(resp.text, resp.url)
        qualities = m3u8.qualities()
        if not qualities:
            return True

        if quality == QUALITY_ASK:
            quality = select_quality(qualities)

            if not quality:
                return False

            elif quality == QUALITY_PASS:
                return True

        min_bandwidth, max_bandwidth = m3u8.bandwidth_range(quality)
    else:
        mpd = MPD(resp.text)
        qualities = mpd.qualities()
        if not qualities:
            return True

        if quality == QUALITY_ASK:
            quality = select_quality(qualities)

            if not quality:
                return False

            elif quality == QUALITY_PASS:
                return True

        min_bandwidth, max_bandwidth = mpd.bandwidth_range(quality)

    settings = {
        'MINBANDWIDTH':        '0',
        'MAXBANDWIDTH':        '0',
        'IGNOREDISPLAY':       'true',
        'STREAMSELECTION':     '0',
        'MEDIATYPE':           '0',
        'MAXRESOLUTION':       '0',
        'MAXRESOLUTIONSECURE': '0',
    }

    orig_settings = inputstream.get_settings(settings.keys())
    if not orig_settings:
        return True

    settings.update({'MINBANDWIDTH': min_bandwidth, 'MAXBANDWIDTH': max_bandwidth})
    inputstream.set_settings(settings)

    settings_thread = Thread(target=reset_ia_settings, args=(orig_settings,))
    settings_thread.daemon = True
    settings_thread.start()

    return True

def parse(item, quality=None):
    url   = item.path.split('|')[0]
    parse = urlparse(url.lower())
    
    if 'http' not in parse.scheme:
        return True

    if parse.path.endswith('.m3u') or parse.path.endswith('.m3u8'):
        item.mimetype = 'application/x-mpegURL'
    elif parse.path.endswith('.mpd'):
        item.mimetype = 'application/dash+xml'

    if item.properties.get('inputstreamaddon') or (item.inputstream and item.inputstream.check()):
        method = parse_ia
    elif item.mimetype == 'application/x-mpegURL':
        method = parse_m3u8
    else:
        return True

    if quality is None:
        quality = userdata.get('quality', DEFAULT_QUALITY)
    else:
        quality = int(quality)

    if quality == QUALITY_PASS:
        return True

    return method(item, quality)