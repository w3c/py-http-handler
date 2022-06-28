#!/usr/bin/python
"""
$Id: surbl.py,v 1.4 2006/04/24 14:43:34 dom Exp $

SURBL implementation
http://www.surbl.org/

This module implements a SurblChecker class which allows to check whether a given URL matches a domain listed in SURBL.


It relies on DNSPython
http://dnspython.org/

License
-------
Copyright (c) 2006 World Wide Web Consortium, (Massachusetts
Institute of Technology, European Research Consortium for Informatics
and Mathematics, Keio University). All Rights Reserved. This work is
distributed under the W3C Software License [1] in the hope that it
will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

[1] http://www.w3.org/Consortium/Legal/copyright-software

"""


import dns.resolver
import urllib.parse


class SurblChecker:
    """An object that allows to check whether a given URL matches a domain listed ni SURBL. Example:
    S = surbl.SurblChecker()
    if S->isMarkedAsSpam('http://www.w3.org/2006/'):
       print "w3.org has been marked as spam!"

    """

    # Takes the location of the file listing the known TLDs where second level registration is well-known
    # and optionaly the path of a whitelist of domain names (to avoid doing dns resolve on these)
    # An example of such a file can be downloaded from:
    # http://spamcheck.freeapp.net/two-level-tlds
    def __init__(self, twoLevelsTlds, whitelist=None):
        f = open(twoLevelsTlds)
        self._twoLevelsTlds = f.readlines()
        f.close()
        self._whitelist = []
        if whitelist:
            g = open(whitelist)
            self._whitelist = g.readlines()
            g.close()

    def isMarkedAsSpam(self, uri):
        # The domain part of the URI is the 2nd item in the set
        domainData = urllib.parse.urlparse(uri)
        registeredName = self._extractRegisteredDomain(domainData[1])
        if registeredName + "\n" in self._whitelist:
            return 0
        try:
            answers = dns.resolver.query(
                registeredName + '.multi.surbl.org', 'A')
            return 1
        except dns.resolver.NXDOMAIN:
            return 0

    def _extractRegisteredDomain(self, authorityComponent):
        # removing userinfo and port
        hostComponent = authorityComponent
        if hostComponent.count('@')>0:
            hostComponent = hostComponent[hostComponent.find('@'):-1]
        if hostComponent.count(':')>0:
            hostComponent = hostComponent[1:hostComponent.find(':')]
        dnsParts = hostComponent.split('.')
        secondLevelTld = dnsParts[-2] + '.' + dnsParts[-1] + "\n"
        if secondLevelTld in self._twoLevelsTlds and len(dnsParts) > 2:
            registeredName = dnsParts[-3] + '.' + \
                dnsParts[-2] + '.' + dnsParts[-1]
        else:
            registeredName = dnsParts[-2] + '.' + dnsParts[-1]
        return registeredName

import unittest

class Tests(unittest.TestCase):
    def testDomainExtraction(self):
        S = SurblChecker('/home/dom/data/2006/04/two-level-tlds')
        cases = (("www.w3.org", "w3.org"),
                 ('chirurgiens-dentistes.fr', 'chirurgiens-dentistes.fr'),
                 ("myteeth.example.chirurgiens-dentistes.fr",
                  "example.chirurgiens-dentistes.fr"),
                 ("example:example@www.example.org:80", "example.org")
                 )

        for inp, exp in cases:
            self.assertEqual(S._extractRegisteredDomain(inp), exp)

    def testMarkedAsSpam(self):
        S = SurblChecker('/home/dom/data/2006/04/two-level-tlds')
        cases = (("http://www.w3.org/2006/", 0),
                 ("http://www.microsoft.com", 0),
                 ("http://allofall.net/spammer_i_hate_thou", 1)
                 )
        for inp, exp in cases:
            self.assertEqual(S.isMarkedAsSpam(inp), exp)


def _test():
    import doctest
    import surbl
    doctest.testmod(surbl)
    unittest.main()


if __name__ == '__main__':
    _test()
