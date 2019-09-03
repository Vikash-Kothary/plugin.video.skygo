import re
import xml.etree.ElementTree as ET

from os.path import dirname
from urlparse import urljoin
from xml.parsers import expat

from .language import _
from .constants import QUALITY_BEST, QUALITY_LOWEST

class M3U8(object):
    def __init__(self, text, url):
        base_url = dirname(url) + '/'
        pattern  = re.compile('(URI\s*=\s*["\']?)(?!http)([^"\'>]+)', re.IGNORECASE)
        text     = pattern.sub(lambda m: m.group(1) + urljoin(base_url, m.group(2)), text)

        self._streams = []
        self._lines   = []

        marker = '#EXT-X-STREAM-INF:'
        pattern = re.compile(r'''((?:[^,"']|"[^"]*"|'[^']*')+)''')

        line1 = None
        for line in text.split('\n'):
            line = line.strip()

            if not line:
                continue

            if line.startswith(marker):
                line1 = line
            elif line1 and not line.startswith('#'):
                if not line.lower().startswith('http'):
                    line = urljoin(base_url, line)

                params = pattern.split(line1.replace(marker, ''))[1::2]

                attributes = {}
                for param in params:
                    name, value = param.split('=', 1)
                    name  = name.replace('-', '_').lower().strip()
                    value = value.lstrip('"').rstrip('"')

                    attributes[name] = value

                num_codecs = len(attributes.get('codecs').split(','))
                bandwidth  = attributes.get('bandwidth')
                resolution = attributes.get('resolution', '')
                frame_rate = attributes.get('frame_rate', '')

                if bandwidth and (num_codecs > 1 or resolution or frame_rate):
                    self._streams.append({'bandwidth': int(bandwidth), 'resolution': resolution, 'frameRate': frame_rate, 'line1': line1, 'line2': line})

                line1 = None

            self._lines.append(line)

        self._streams = sorted(self._streams, key=lambda s: s['bandwidth'], reverse=True)

    def streams(self):
        return self._streams

    def qualities(self):
        qualities  = []
        bandwidths = []

        for stream in self._streams:
            if stream['bandwidth'] in bandwidths:
                continue

            bandwidths.append(stream['bandwidth'])

            fps = ''
            if stream['frameRate']:
                try:
                    if '/' in stream['frameRate']:
                        split = stream['frameRate'].split('/')
                        stream['frameRate'] = float(split[0]) / float(split[1])

                    fps = _(_.QUALITY_FPS, fps=float(stream['frameRate']))
                except:
                    fps = ''

            qualities.append([stream['bandwidth'], _(_.QUALITY_BITRATE, bandwidth=float(stream['bandwidth'])/1000000, resolution=stream['resolution'], fps=fps)])

        return qualities

    def bandwidth_range(self, quality):
        qualities = []
        for stream in self._streams:
            if stream['bandwidth'] not in qualities:
                qualities.append(stream['bandwidth'])

        if quality == QUALITY_BEST:
            selected = qualities[0]
        elif quality == QUALITY_LOWEST:
            selected = qualities[-1]
        else:
            selected = qualities[-1]

            for bandwidth in qualities:
                if bandwidth <= quality:
                    selected = bandwidth
                    break

        qualities.insert(0, 1)
        qualities.append(0)

        index = qualities.index(selected)

        return qualities[index+1]+1, qualities[index-1]-1

    def at_quality(self, quality):
        qualities = []
        for stream in self._streams:
            if stream['bandwidth'] not in qualities:
                qualities.append(stream['bandwidth'])

        if quality == QUALITY_BEST:
            selected = qualities[0]
        elif quality == QUALITY_LOWEST:
            selected = qualities[-1]
        else:
            selected = qualities[-1]

            for bandwidth in qualities:
                if bandwidth <= quality:
                    selected = bandwidth
                    break

        to_remove = []
        for stream in self._streams:
            if stream['bandwidth'] != selected:
                to_remove.extend([stream['line1'], stream['line2']])

        lines = [l for l in self._lines if l not in to_remove]

        return '\n'.join(lines)

class DisableXmlNamespaces:
    def __enter__(self):
        self.oldcreate = expat.ParserCreate
        expat.ParserCreate = lambda encoding, sep: self.oldcreate(encoding, None)
            
    def __exit__(self, type, value, traceback):
        expat.ParserCreate = self.oldcreate

class MPD(object):
    def __init__(self, text):
        with DisableXmlNamespaces():
            root = ET.fromstring(text)

        self._streams = []
        for adap_set in root.findall(".//AdaptationSet"):
            for stream in adap_set.findall("./Representation"):
                attrib = adap_set.attrib.copy()
                attrib.update(stream.attrib)
                if 'video' in attrib.get('mimeType', '') and 'bandwidth' in attrib:
                    attrib['bandwidth'] = int(attrib['bandwidth'])
                    self._streams.append(attrib)

        self._streams = sorted(self._streams, key=lambda s: s['bandwidth'], reverse=True)

    def qualities(self):
        qualities  = []
        bandwidths = []

        for stream in self._streams:
            if stream['bandwidth'] in bandwidths:
                continue

            bandwidths.append(stream['bandwidth'])

            resolution = ''
            if 'width' in stream and 'height' in stream:
                resolution = '{}x{}'.format(stream['width'], stream['height'])

            fps = ''
            if 'frameRate' in stream:
                try:
                    if '/' in stream['frameRate']:
                        split = stream['frameRate'].split('/')
                        stream['frameRate'] = float(split[0]) / float(split[1])

                    fps = _(_.QUALITY_FPS, fps=float(stream['frameRate']))
                except:
                    fps = ''
                
            qualities.append([stream['bandwidth'], _(_.QUALITY_BITRATE, bandwidth=float(stream['bandwidth'])/1000000, resolution=resolution, fps=fps)])

        return qualities

    def bandwidth_range(self, quality):
        qualities = []
        for stream in self._streams:
            if stream['bandwidth'] not in qualities:
                qualities.append(stream['bandwidth'])

        if quality == QUALITY_BEST:
            selected = qualities[0]
        elif quality == QUALITY_LOWEST:
            selected = qualities[-1]
        else:
            selected = qualities[-1]

            for bandwidth in qualities:
                if bandwidth <= quality:
                    selected = bandwidth
                    break

        qualities.insert(0, 1)
        qualities.append(0)

        index = qualities.index(selected)

        return qualities[index+1]+1, qualities[index-1]-1