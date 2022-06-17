import urllib.request
import urllib.parse
import urllib.error
import os


class ProtectedURLopener(urllib.request.FancyURLopener):
    def __init__(self):
        import surbl
        urllib.request.FancyURLopener.__init__(self)
        self.surblchecker = surbl.SurblChecker(
            '/usr/local/share/surbl/two-level-tlds', '/usr/local/etc/surbl.whitelist')

    def open(self, url, data=None):
        # cf https://github.com/w3c/py-http-handler/blob/master/checkremote.py
        from checkremote import check_url_safety, UnsupportedResourceError
        try:
            check_url_safety(url)
        except UnsupportedResourceError:
            raise IOError(403, "Access to url '%s' is not allowed" % url)
        if self.surblchecker.isMarkedAsSpam(url):
            raise IOError(
                403, "Access to url '%s' is not allowed as it is marked as spam in SURBL" % url)
        return urllib.request.FancyURLopener.open(self, url, data)


class ProxyAuthURLopener(ProtectedURLopener):
    error = ""
    version = "W3C HTTP Proxy Auth URL Opener/1.1"

    def http_error_default(self, url, fp, errcode, errmsg, headers):
        self.error = repr(errcode) + " " + errmsg
        return None

    def http_error_304(self, uri, fp, errocode, errmsg, headers):
        print('HTTP/1.1 304 Not Modified')
        return None

    def open_local_file(self, url):
        self.error = "Local file URL not accepted"
        return None

    def _send_auth_challenge(self, scheme, url, realm, data=None):
        if scheme not in ('http', 'https'):
            return
        if os.environ.get('HTTP_AUTHORIZATION'):
            self.addheader('Authorization', os.environ['HTTP_AUTHORIZATION'])
            if data is None:
                return self.open(scheme + ':' + url)
            else:
                return self.open(scheme + ':' + url, data)
        else:
            global Page
            print('Status: 401 Authorization Required')
            print('WWW-Authenticate: Basic realm="%s"' % realm)
            print('Connection: close')
            Page = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>401 Authorization Required</title>
</head>
<body>
<h1>Authorization Required</h1>
<p>You need %s access to %s:%s to use this service.</p>
""" % (realm, scheme, url)
            return None

    def retry_https_basic_auth(self, url, realm, data=None):
        # @@@ need to send challenge through https as needed
        return self._send_auth_challenge("https", url, realm, data)

    def retry_http_basic_auth(self, url, realm, data=None):
        return self._send_auth_challenge("http", url, realm, data)
