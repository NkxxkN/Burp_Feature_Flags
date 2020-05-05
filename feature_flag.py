#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from burp import IBurpExtender
from java.io import PrintWriter
from burp import IHttpListener
from burp import IExtensionHelpers
from burp import IProxyListener
import re
import json
LAUNCHDARKLY_CLIENT = 'https://app.launchdarkly.com'

class BurpExtender(IBurpExtender, IProxyListener, IExtensionHelpers):
    def registerExtenderCallbacks(self, callbacks):

        callbacks.setExtensionName("Turn On Feature Flags\r\r")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._helpers = callbacks.getHelpers()
        # register ourselves as a Proxy listener
        callbacks.registerProxyListener(self)

        self._callbacks = callbacks

        self._stdout.println("================================")
        self._stdout.println("         author:nkx             ")
        self._stdout.println("   https://twitter.com/NkkxN    ")
        self._stdout.println("     Turn On Feature Flags      ")
        self._stdout.println("       version:v0.1             ")
        self._stdout.println("================================\r\r")

        return

    #
    # implement IProxyListener
    #
    def processProxyMessage(self, messageIsRequest, message):
        if not messageIsRequest:
            if message.getMessageInfo().getHttpService().toString() == LAUNCHDARKLY_CLIENT:
                response = message.getMessageInfo().getResponse()
                
                if re.match('^HTTP/1.1 304 Not Modified', response.tostring()):
                    self._stdout.println("Proxy response from " + message.getMessageInfo().getHttpService().toString() + " : 304 Not Modified")

                if re.match('^HTTP/1.1 200 OK', response.tostring()):

                    responseInfo = self._helpers.analyzeResponse(response)
                    headers = responseInfo.getHeaders()
                    body = response[responseInfo.getBodyOffset():].tostring()

                    if not body:
                            return

                    self._stdout.println("Proxy response from " + message.getMessageInfo().getHttpService().toString() + " : 200 OK")
                    jbody = json.loads(body)
                    
                    for key in jbody:
                        if jbody[key]['value'] == 0:
                            jbody[key]['value'] = True
                            self._stdout.println("Turning On FF:" + key)

                    body = json.dumps(jbody)
                    httpRequest = bytearray()
                    httpRequest += bytearray('\n'.join(headers).encode("utf8"))
                    httpRequest += bytearray('\n\n')
                    httpRequest += bytearray(body)
                    message.getMessageInfo().setResponse(bytes(httpRequest))


        return
