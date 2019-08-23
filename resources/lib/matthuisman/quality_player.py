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

PROXY_FILE = xbmc.translatePath('special://temp/proxy_playlist.m3u8')

QUALIITES = [
    [8000000, _.QUALITY_1080P],
    [6000000, _.QUALITY_720P],
    [4000000, _.QUALITY_540P],
    [2000000, _.QUALITY_480P],
]

def get_quality():
    return userdata.get('quality', DEFAULT_QUALITY)

def select_quality(qualities=None, ask_option=False, save=False, current=None):
    options = []
    if ask_option:
        options.append([QUALITY_ASK, _.QUALITY_ASK])

    options.append([QUALITY_BEST, _.QUALITY_BEST])
    options.extend(qualities or QUALIITES)
    options.append([QUALITY_CUSTOM, _.QUALITY_CUSTOM])
    options.append([QUALITY_LOWEST, _.QUALITY_LOWEST])
    options.append([QUALITY_PASS, _.QUALITY_PASSTHROUGH])

    values = [x[0] for x in options]
    labels = [x[1].format(bandwidth=int(x[0]/1000000)) for x in options]

    if current:
        try:
            default = values.index(current)
        except:
            default = values.index(QUALITY_CUSTOM) if current > 0 else 0
    else:
        default = 0

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
        label = _(_.QUALITY_CUSTOM_LABEL, bandwidth=value)

    if save:
        userdata.set('quality', value)
        gui.notification(_(_.QUALITY_SET, label=label))    

    return value

@router.route(ROUTE_QUALITY)
def _select_quality(**kwargs):
    select_quality(ask_option=True, save=True, current=get_quality())

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

    parsed_url = urlparse(resp.url)
    prefix     = parsed_url.scheme + '://' + parsed_url.netloc
    path       = parsed_url.path.replace('//', '/')
    base_path  = posixpath.normpath(path + '/..')
    base_url   = urljoin(prefix, base_path)

    if not base_url.endswith('/'):
        base_url += '/'

    text = re.sub(r'URI="((?!http://|https://).*)"', r'URI="{}\1"'.format(base_url), resp.text, flags=re.I)

    lines = []
    streams = []
    found = None
    marker = '#EXT-X-STREAM-INF:'
    pattern = re.compile(r'''((?:[^,"']|"[^"]*"|'[^']*')+)''')

    for line in text.split('\n'):
        line = line.strip()

        if not line:
            continue

        if line.startswith(marker):
            found = line
        elif found and not line.startswith('#'):
            url = line
            if not url.lower().startswith('http'):
                url = urljoin(base_url, url)

            params = pattern.split(found.replace(marker, ''))[1::2]

            attributes = {}
            for param in params:
                name, value = param.split('=', 1)
                name  = name.replace('-', '_').lower().strip()
                value = value.lstrip('"').rstrip('"')

                attributes[name] = value

            bandwidth = attributes.get('bandwidth')
            if bandwidth:
                streams.append({'bandwidth': int(bandwidth), 'resolution': attributes.get('resolution', ''), 'framerate': attributes.get('frame-rate', ''), 'url': url, 'line': found})

            found = None
        else:
            lines.append(line)

    streams = sorted(streams, key=lambda s: s['bandwidth'], reverse=True)
    if not streams:
        return

    if quality == QUALITY_BEST:
        selected = streams[0]
    elif quality == QUALITY_LOWEST:
        selected = streams[-1]
    else:
        selected = streams[-1]

        for stream in streams:
            if stream['bandwidth'] <= quality:
                selected = stream
                break
    
    lines.append(selected['line'])
    lines.append(selected['url'])

    text = '\n'.join(lines)

    with open(PROXY_FILE, 'wb') as f:
        f.write(text)

    server_address = ('127.0.0.1', 9977)

    httpd          = HTTPServer(server_address, MainHandler)
    httpd.timeout  = 5
    httpd_thread   = Thread(target=single_request, args=(httpd,))
    httpd_thread.daemon = True

    if not ADDON_DEV:
        httpd_thread.start()

    item.cookies.update(resp.cookies)
    item.mimetype = 'application/x-mpegURL'

    ## need to use .m3u8 or headers break
    item.path = 'http://{host}:{port}/{random}/playlist.m3u8'.format(host=server_address[0], port=server_address[1], random=int(time.time()))

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
        return

    if quality == QUALITY_BEST:
        quality = 1000000000
    elif quality == QUALITY_LOWEST:
        quality = 1

    settings.update({'MINBANDWIDTH': quality, 'MAXBANDWIDTH': quality})
    inputstream.set_settings(settings)

    settings_thread = Thread(target=reset_ia_settings, args=(orig_settings,))
    settings_thread.daemon = True
    settings_thread.start()

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
        quality = get_quality()
    else:
        quality = int(quality)

    if quality == QUALITY_ASK:
        quality = select_quality()
        if not quality:
            return False

    if quality == QUALITY_PASS:
        return True

    method(item, quality)

    return True