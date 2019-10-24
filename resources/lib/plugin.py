import codecs
from string import ascii_uppercase

from kodi_six import xbmcplugin

from .matthuisman import plugin, gui, userdata, signals, inputstream, settings
from .matthuisman.exceptions import Error

from .api import API
from .constants import IMAGE_URL, HEADERS
from .language import _

api = API()

@signals.on(signals.BEFORE_DISPATCH)
def before_dispatch():
    api.new_session()
    plugin.logged_in = api.logged_in

@plugin.route('')
def home(**kwargs):
    folder = plugin.Folder()

    if not api.logged_in:
        folder.add_item(label=_(_.LOGIN, _bold=True), path=plugin.url_for(login))
    else:
        folder.add_item(label=_(_.LIVE_TV, _bold=True),  path=plugin.url_for(live_tv))
        folder.add_item(label=_(_.TV_SHOWS, _bold=True), path=plugin.url_for(content, label=_.TV_SHOWS, section='tvshows'))
        folder.add_item(label=_(_.MOVIES, _bold=True),   path=plugin.url_for(content, label=_.MOVIES, section='movies'))
        folder.add_item(label=_(_.SPORTS, _bold=True),   path=plugin.url_for(content, label=_.SPORTS, section='sport'))
        folder.add_item(label=_(_.BOX_SETS, _bold=True), path=plugin.url_for(content, label=_.BOX_SETS, section='boxsets'))
        folder.add_item(label=_(_.CHANNELS, _bold=True), path=plugin.url_for(channels))
        folder.add_item(label=_(_.SEARCH, _bold=True),   path=plugin.url_for(search))

        folder.add_item(label=_.LOGOUT, path=plugin.url_for(logout))

    folder.add_item(label=_.SETTINGS, path=plugin.url_for(plugin.ROUTE_SETTINGS))

    return folder

def _is_subscribed(subscriptions, categories):
    if not subscriptions or not categories:
        return True

    for row in categories:
        if row['media$scheme'] == 'urn:sky:subscription' and row['media$name'] not in subscriptions:
            return False

    return True

def _get_image(row):
    images = row.get('media$thumbnails')

    if not images:
        images = row.get('media$content')

    if not images:
        return None

    for row in images:
        if 'SkyGoChannelLogoScroll' in row['plfile$assetTypes'] or 'SkyGOChannelLogo' in row['plfile$assetTypes']:
            return row['plfile$streamingUrl']

    return images[-1]['plfile$streamingUrl']

def _get_channels():
    subscriptions = userdata.get('subscriptions', [])
    channels = []
    rows = api.channels()

    def _get_play_url(content):
        for row in content:
            if 'SkyGoStream' in row['plfile$assetTypes']:
                return row['plfile$streamingUrl']

        return None

    for row in sorted(rows, key=lambda r: float(r.get('sky$liveChannelOrder', 'inf'))):
        if 'Live' not in row.get('sky$channelType', []):
            continue

        channel_id = row['plmedia$publicUrl'].rsplit('/')[-1]

        label = row['title']

        subscribed = _is_subscribed(subscriptions, row.get('media$categories'))
        play_url   = _get_play_url(row.get('media$content'))

        if not subscribed:
            label = _(_.LOCKED, label=label)
        elif 'faxs' in play_url:
            label = _(_.ADOBE_DRM, label=label)

        if settings.getBool('hide_unplayable', False) and (not subscribed or 'faxs' in play_url):
            continue

        channels.append({
            'label': label,
            'channel': row.get('sky$skyGOChannelID', ''),
            'description': row.get('description'),
            'image': _get_image(row),
            'path':  plugin.url_for(play_channel, id=channel_id, _is_live=True),
        })

    return channels

@plugin.route()
def live_tv(**kwargs):
    folder = plugin.Folder(_.LIVE_TV)

    for row in _get_channels():
        folder.add_item(
            label    = row['label'],
            info     = {'description': row['description']},
            art      = {'thumb': row['image']},
            path     = row['path'],
            playable = True,
        )

    return folder

@plugin.route()
def channels(**kwargs):
    folder = plugin.Folder(_.CHANNELS)

    subscriptions = userdata.get('subscriptions', [])

    for row in sorted(api.channels(), key=lambda row: row['title']):
        label = row['title']

        subscribed = _is_subscribed(subscriptions, row.get('media$categories'))

        if not subscribed:
            label = _(_.LOCKED, label=label)

        if settings.getBool('hide_unplayable', False) and not subscribed:
            continue

        folder.add_item(
            label    = label,
            info     = {'description': row.get('description')},
            art      = {'thumb': _get_image(row)},
            path     = plugin.url_for(content, label=row['title'], sortby='TITLE', title='', channels=row.get('sky$skyGOChannelID', '')),
        )

    return folder

@plugin.route()
def content(label, section='', sortby=None, title=None, channels='', start=0, **kwargs):
    start = int(start)
    folder = plugin.Folder(label)

    if not sortby:
        items = [[_.A_Z, 'TITLE'], [_.LATEST, 'LATEST'], [_.LAST_CHANCE, 'LASTCHANCE']]
        for item in items:
            folder.add_item(label=item[0], path=plugin.url_for(content, label=item[0], section=section, sortby=item[1], channels=channels))

    elif sortby == 'TITLE' and title == None:
        items = [[c, c] for c in ascii_uppercase]
        items.insert(0, [_.ALL, ''])
        items.append([_.ZERO_9, '0-9'])
        
        for item in items:
            folder.add_item(label=item[0], path=plugin.url_for(content, label=item[0], section=section, sortby=sortby, title=item[1], channels=channels))

    else:
        data   = api.content(section, sortby=sortby, title=title, channels=channels, start=start)
        items = _process_content(data['data'])
        folder.add_items(items)

        if items and data['index'] < data['available']:
            folder.add_item(
                label = _(_.NEXT_PAGE, _bold=True),
                path  = plugin.url_for(content, label=label, section=section, sortby=sortby, title=title, channels=channels, start=data['index']),
            )

    return folder

@plugin.route()
def search(query=None, start=0, **kwargs):
    start = int(start)

    if not query:
        query = gui.input(_.SEARCH, default=userdata.get('search', '')).strip()
        if not query:
            return

        userdata.set('search', query)

    folder = plugin.Folder(_(_.SEARCH_FOR, query=query))

    data = api.content(text=query, start=start)
    items = _process_content(data['data'])
    folder.add_items(items)

    if items and data['index'] < data['available']:
        folder.add_item(
            label = _(_.NEXT_PAGE, _bold=True),
            path  = plugin.url_for(search, query=query, start=data['index']),
        )

    return folder

def _process_content(rows):
    items = []
    subscriptions = userdata.get('subscriptions', [])

    for row in rows:
        if row['suspended']:
            continue

        label = row['title']

        if 'subCode' in row and subscriptions and row['subCode'] not in subscriptions:
            label = _(_.LOCKED, label=label)

            if settings.getBool('hide_unplayable', False):
                continue

        if row['type'] == 'movie':
            items.append(plugin.Item(
                label = label,
                info = {
                    'plot': row.get('synopsis'),
                    'duration': int(row.get('duration', '0 mins').strip(' mins')) * 60,
                    'mediatype': 'movie',
                },
                art  = {'thumb': IMAGE_URL.format(row['images'].get('MP',''))},
                path = plugin.url_for(play, id=row['mediaId']),
                playable = True,
            ))

        elif row['type'] == 'season':
            items.append(plugin.Item(
                label = label,
                art   = {'thumb': IMAGE_URL.format(row['images'].get('MP',''))},
                path  = plugin.url_for(series, id=row['id']),
            ))

    return items

@plugin.route()
def series(id, **kwargs):
    data   = api.series(id)

    folder = plugin.Folder(data['title'], fanart=IMAGE_URL.format(data['images'].get('PS','')), sort_methods=[xbmcplugin.SORT_METHOD_EPISODE, xbmcplugin.SORT_METHOD_UNSORTED, xbmcplugin.SORT_METHOD_LABEL, xbmcplugin.SORT_METHOD_DATEADDED])

    for row in data.get('subContent', []):
        folder.add_item(
            label = row['episodeTitle'],
            info  = {
                'tvshowtitle': data.get('seriesTitle', data['title']),
                'plot': row.get('episodeSynopsis'),
                'duration': int(row.get('duration', '0 mins').strip(' mins')) * 60,
                'season': int(row.get('seasonNumber', 0)),
                'episode': int(row.get('episodeNumber', 0)),
                'mediatype': 'episode',
            },
            art   = {'thumb': IMAGE_URL.format(data['images'].get('MP',''))},
            path  = plugin.url_for(play, id=row['mediaId']),
            playable = True,
        )

    return folder
    
@plugin.route()
def login(**kwargs):
    username = gui.input(_.ASK_USERNAME, default=userdata.get('username', '')).strip()
    if not username:
        return

    userdata.set('username', username)

    password = gui.input(_.ASK_PASSWORD, hide_input=True).strip()
    if not password:
        return

    api.login(username=username, password=password)
    gui.refresh()

@plugin.route()
def logout(**kwargs):
    if not gui.yes_no(_.LOGOUT_YES_NO):
        return

    api.logout()
    gui.refresh()

@plugin.route()
@plugin.login_required()
def play(id, **kwargs):
    url, license = api.play_media(id)

    return plugin.Item(
        path        = url,
        headers     = HEADERS,
        inputstream = inputstream.Widevine(
            license_key  = license,
            challenge    = '',
            content_type = '',
            response     = 'JBlicense',
        ),
    )

@plugin.route()
@plugin.login_required()
def play_channel(id, **kwargs):
    url = api.play_channel(id)

    return plugin.Item(
        path        = url,
        headers     = HEADERS,
        inputstream = inputstream.HLS(),
    )

@plugin.route()
@plugin.merge()
def playlist(output, **kwargs):
    with codecs.open(output, 'w', encoding='utf8') as f:
        f.write(u'#EXTM3U\n')

        for row in _get_channels():
            f.write(u'#EXTINF:-1 tvg-id="{id}" tvg-chno="{channel}" tvg-logo="{logo}",{name}\n{path}\n'.format(
                        id=row['channel'], channel=row['channel'], name=row['label'], logo=row['image'], path=row['path']))