#!/usr/bin/python
""" $Id$
Debian packages dependencies: python-dnspython, tidy, libxml2-utils
Other python modules: http://dev.w3.org/2000/tidy-svc/http_auth.py, http://dev.w3.org/2006/surbl.py
Maintainer: dom@w3.org
"""

import cgi
import sys
import os
import urlparse
import urllib
import httplib
import surbl

Page = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en-US">
<head><title>HTML tidy service</title>
<link rel="stylesheet" href="http://www.w3.org/StyleSheets/base" />
</head>
<body>

<p><a href="http://www.w3.org/"><img src="http://www.w3.org/Icons/w3c_home" alt="W3C"/></a></p>

<h1>Tidy your HTML</h1>
"""
Page2 = """
<form method="GET">
<p>Address of document to tidy: <input name="docAddr" value="%s"/></p>
<p><label><input type="checkbox" name="indent" /> indent</label></p>
<p><label><input type="checkbox" name="forceXML" /> enforce XML well-formedness of the results</label> (may lead to loss of parts of the originating document if too ill-formed)</p>
<p><input type="submit" value="get tidy results"/></p>
</form>

<hr />
<h2>Stuff used to build this service</h2>
<ul>
<li><a href="http://tidy.sourceforge.net/">tidy</a></li>
<li><a href="http://xmlsoft.org/xmllint.html">xmllint</a> (for enforcing XML well-formedness)</li>
<li><a href="http://www.python.org/">python</a>, apache, etc.</li>
</ul>
<p>See also the <a href="http://dev.w3.org/cvsweb/2000/tidy-svc/">underlying Python script</a>.</p>
<address>
script $Revision$ of $Date$<br />
by <a href="http://www.w3.org/People/Connolly/">Dan Connolly</a><br />
Further developed and maintained by <a href="http://www.w3.org/People/Dom/">Dominique Hazael-Massieux</a>
</address>
</body>
</html>
"""


from time import strftime, localtime

# def now():
#     return strftime("%H:%M:%S", localtime())

def serveRequest():
    fields = cgi.FieldStorage()

    if not fields.has_key('docAddr'):
        print "Content-Type: text/html;charset=iso-8859-1"
	print
        print Page
	print Page2 % ("")
    else:
        checker = surbl.SurblChecker('/usr/local/share/surbl/two-level-tlds','/afs/w3.org/pub/WWW/Systems/Server/debian/generic/usr/local/etc/surbl.whitelist')
        addr = fields['docAddr'].value
	if "'" in addr:
		print "Status: 403"
		print "Content-Type: text/plain"
		print
		print "sorry, I can't handle addresses with ' in them"
	elif addr[:5] == 'file:' or len(urlparse.urlparse(addr)[0])<2:
		print "Status: 403"
		print "Content-Type: text/plain"
		print
		print "sorry, I decline to handle file: addresses"
        elif checker.isMarkedAsSpam(addr):
                print "Status: 403"
                print "Content-Type: text/plain; charset=utf-8"
                print
                print "sorry, this URL matches a record known in SURBL. See http://www.surbl.org/"
	else:
                tidy_options = ["-n", "-asxml", "-q", "--force-output","yes", "--show-warnings", "no"]
                import http_auth
		url_opener = http_auth.ProxyAuthURLopener()
                if fields.headers.has_key('If-Modified-Since'):
                    url_opener.addheader("If-Modified-Since: %s" % (fields.headers["If-Modified-Since"]))
		if os.environ.has_key('REMOTE_ADDR') and os.environ['REMOTE_ADDR']:
			url_opener.addheader('X_Forward_IP_Addr',os.environ['REMOTE_ADDR'])
		try:
			doc = url_opener.open(addr)
		except IOError, (errno, strerror):
			url_opener.error = "I/O error: %s %s" % (errno,strerror)
			doc = None
                except httplib.InvalidURL:
                        url_opener.error = "Invalid URL submitted"
                        doc = None
		if doc:
			headers = doc.info()
                        if headers.has_key('Last-Modified'):
                            print "Last-Modified: %s" % ( headers["Last-Modified"] )
                        charset = "utf-8"
                        contentType="text/html"
                        outputContentType="text/html"
                        print "Content-Location: %s" % (addr)
                        if headers.has_key('Content-Type'):
                            contentType = cgi.parse_header(headers["Content-Type"])
                            if contentType[1].has_key('charset'):
                                from string import lower
                                charset = lower(contentType[1]['charset'])
                            # @@@ should output charset=utf-8 when forceXML is set
                            outputContentType =  headers["Content-Type"]
                        if headers.has_key("Expires"):
                            print "Expires: %s" % (headers['Expires'] )
			if charset == "iso-8859-1": tidy_options.append('-latin1')
			if charset == "utf-8": tidy_options.append('-utf8')
                        if not cgi.parse_header(outputContentType)[1].has_key('charset') and cgi.parse_header(outputContentType)[0]=="text/html":
                            outputContentType=outputContentType + "; charset=utf-8"
                        print "Content-Type: %s" % outputContentType
			print
			if fields.has_key('indent'): tidy_options.append('-i')
                        forceXML = False
                        if fields.has_key('forceXML'):
                            forceXML = True
                        import re
                        d = doc.read()
                        # searching for XHTML Doctype
                        docpat = re.compile("<!DOCTYPE\s+html\s+PUBLIC\s+\"-//W3C//DTD\s+XHTML\s+")
                        m = docpat.search(d)
                        if fields.has_key('passThroughXHTML') and m:
                            sys.stdout.flush()
                            print d
                        else:
                            from subprocess import Popen, PIPE
                            from tempfile import TemporaryFile, mkstemp
#                            out = open('/tmp/d.txt', 'w')

                            (fd, fname) = mkstemp(prefix='tidy', dir='/tmp')
                            out = os.fdopen(fd, 'w+b')
#                            out = TemporaryFile(prefix='tidy', dir='/tmp')
                            out.write(d)
                            out.flush()


                            remove_feedcarriage_command = ["/usr/bin/tr","\r"," "]
                            escape_lonely_ampersands_command = ["/bin/sed","-e","s/ & / \&amp;/g"]
                            tidy_command = ["/usr/bin/tidy"] + tidy_options
                            force_xml_command = ["/usr/bin/xmllint", "--recover", "--encode", "utf-8", "-"]
                            
                            p1 = Popen(remove_feedcarriage_command, stdin=open(fname, 'r'), stdout=PIPE)
                            p2 = Popen(escape_lonely_ampersands_command, stdin=p1.stdout, stdout=PIPE)
                            p3 = Popen(tidy_command, stdin=p2.stdout, stdout=PIPE)
                            
                            p = p3
                            if forceXML:
                                p = Popen(force_xml_command, stdin=p3.stdout, stdout=PIPE)
                            print p.communicate()[0]
                            sys.stdout.flush()
                            out.close()
		else:
			print "Content-Type: text/html;charset=iso-8859-1"
			print
			print Page
			print "<p style='color:#FF0000'>An error (<code>%s</code>) occured trying to get <a href='%s'>%s</a></p>" % (cgi.escape(url_opener.error), cgi.escape(addr) , cgi.escape(addr))
			print Page2 % cgi.escape(addr)


if __name__ == '__main__':
    if os.environ.has_key('SCRIPT_NAME'):
        serveRequest()
