import httplib2
import json
import urllib
import urlparse
import UserDict
import UserList
import UserString

class REST:
    class RESTException(Exception):
        def __init__(self, name, code, msg):
            self.name = name
            self.code = code
            self.msg = msg

        def __str__(self):
            return '%s:%s\nMessage: %s' % (self.name, self.code, self.msg)

        def __repr__(self):
            return '%s:%s\nMessage: %s' % (self.name, self.code, self.msg)

    CONTENT_ENCODE = {
        'text/json' : lambda x: json.dumps(x, encoding='UTF-8'),
        'application/json' : lambda x: json.dumps(x, encoding='UTF-8'),
        'application/x-www-form-urlencoded' : urllib.urlencode,
    }

    CONTENT_DECODE = {
        'text/json' : json.loads,
        'application/json' : json.loads,
        'application/x-www-form-urlencoded' : lambda x : dict( (k, v[0] ) for k, v in [urlparse.parse_qs(x).items()]),
        'text/plain' : lambda x : dict( l.split('=') for l in x.strip().split('\n') ),
    }

    RESULT_WRAPTERS = {
        type({}) : UserDict.UserDict,
        type([]) : UserList.UserList,
        type('') : UserString.UserString,
        type(u'') : UserString.UserString,
    }

    def __init__(self, host, auth=None, http=None):
        if http is None:
            self._conn=httplib2.Http()
        else:
            self._conn = http
        self.auth = auth
        self.host = host

    def rest_call(self, verb, path, data, content_type, headers={}, response_type=None):

        if data is not None:
            data = self.CONTENT_ENCODE[content_type](data)

        headers['Content-Type'] = content_type + '; charset=UTF-8'
        headers['Accept-Charset'] = 'UTF-8'
        if self.auth:
            headers['Authorization'] = self.auth

        uri = self.host+path
        (resp, data) = self._conn.request(uri,
                                          method=verb,
                                          body=data,
                                          headers=headers)
        if response_type:
            content_type = response_type
        else:
            content_type = resp['content-type']
            content_type = content_type.split(';',2)[0]

        if resp.status != 200:
            try:
                error = self.CONTENT_DECODE[content_type](data)
                raise REST.RESTException(error['Name'], error['Code'], error['Message'])
            except (ValueError, KeyError):
                raise REST.RESTException('REST Error', resp.status, data)

        decoded_data = self.CONTENT_DECODE[content_type](data)
        try:
            decoded_data = self.RESULT_WRAPTERS[type(decoded_data)](decoded_data)
        except KeyError:
            pass
        decoded_data.headers = dict(resp)
        return decoded_data

    def get(self, path, content_type='text/json', headers={}, response_type=None):
        return self.rest_call('GET', path, None, content_type, headers, response_type)

    def put(self, path, data, content_type='text/json', headers={}, response_type=None):
        return self.rest_call('PUT', path, data, content_type, headers, response_type)

    def post(self, path, data, content_type='text/json', headers={}, response_type=None):
        return self.rest_call('POST', path, data, content_type, headers, response_type)

    def delete(self, path, data, content_type='text/json', headers={}, response_type=None):
        return self.rest_call('DELETE', path, data, content_type, headers, response_type)


