#!/usr/bin/env python3
from boofuzz import *


class HTTPHeaderAcceptCharset(FuzzableBlock):
    def __init__(self, name=None, request=None, children=None):
        super(HTTPHeaderAcceptCharset, self).__init__(name, request, children)

        if not request:
            request = "utf-8"

        self.push(Static("accept-charset-header", "Accept-Charset"))
        self.push(Delim("header-end", ":"))
        self.push(Delim("space-1", " "))
        self.push(String("header-date", request, max_len=4096))
        self.push(Static("crlf", "\r\n"))


class HTTPHeaderAcceptEncoding(FuzzableBlock):
    def __init__(self, name=None, request=None, children=None):
        super(HTTPHeaderAcceptEncoding, self).__init__(name, request, children)

        if not request:
            request = ["gzip", "deflate"]

        self.push(Static("accept-encoding-header", "Accept-Encoding"))
        self.push(Delim("header-end", ":"))
        self.push(Delim("space-1", " "))
        for e in request[:-1]:
            self.push(String("type-" + e, e, max_len=4096))
            self.push(Delim("comma-" + e, ","))
            self.push(Delim("space-" + e, " "))
        self.push(Static("crlf", "\r\n"))


class HTTPHeaderAcceptLanguage(FuzzableBlock):
    def __init__(self, name=None, request=None, children=None):
        super(HTTPHeaderAcceptLanguage, self).__init__(name, request, children)

        if not request:
            request = "en-US"

        self.push(Static("accept-language-header", "Accept-Language"))
        self.push(Delim("header-end", ":"))
        self.push(Delim("space-1", " "))
        self.push(String("header-date", request, max_len=4096))
        self.push(Static("crlf", "\r\n"))


class HTTPHeaderAcceptDatetime(FuzzableBlock):
    def __init__(self, name=None, request=None, children=None):
        super(HTTPHeaderAcceptDatetime, self).__init__(name, request, children)

        if not request:
            request = "Thu, 31 May 2007 20:35:00 GMT"

        self.push(Static("accept-datetime-header", "Accept-Datetime"))
        self.push(Delim("header-end", ":"))
        self.push(Delim("space-1", " "))
        self.push(String("header-date", request, max_len=4096))
        self.push(Static("crlf", "\r\n"))


class HTTPHeaderConnection(FuzzableBlock):
    def __init__(self, name=None, request=None, children=None):
        super(HTTPHeaderConnection, self).__init__(name, request, children)

        if not request:
            request = "Upgrade"

        self.push(Static("connection-header", "Connection"))
        self.push(Delim("header-end", ":"))
        self.push(Delim("space-1", " "))
        self.push(String("header-date", request, max_len=4096))
        self.push(Static("crlf", "\r\n"))


class HTTPHeaderUpgrade(FuzzableBlock):
    def __init__(self, name=None, request=None, children=None):
        super(HTTPHeaderUpgrade, self).__init__(name, request, children)

        http_upgrades_methods = [
            "websocket",
            "h2c",
            "TLS/1.0",
        ]

        self.push(Static("upgrade-header", "Upgrade"))
        self.push(Delim("header-end", ":"))
        self.push(Delim("space-1", " "))
        self.push(Group("upgrade-methods", values=http_upgrades_methods))
        self.push(Static("crlf", "\r\n"))


class HTTPHeaderHTTP2Settings(FuzzableBlock):
    def __init__(self, name=None, request=None, children=None):
        super(HTTPHeaderHTTP2Settings, self).__init__(name, request, children)

        if not request:
            request = "token64"

        self.push(Static("http2-settings-header", "HTTP2-Settings"))
        self.push(Delim("header-end", ":"))
        self.push(Delim("space-1", " "))
        self.push(String("header-date", request, max_len=4096))
        self.push(Static("crlf", "\r\n"))


class HTTPHeaderHost(FuzzableBlock):
    def __init__(self, name=None, request=None, children=None):
        super(HTTPHeaderHost, self).__init__(name, request, children)

        if not request:
            request = "destination.server.ext"

        self.push(Static("host-header", "Host"))
        self.push(Delim("header-end", ":"))
        self.push(Delim("space-1", " "))
        self.push(String("header-date", request, max_len=4096))
        self.push(Static("crlf", "\r\n"))


class HTTPRequestMethod(FuzzableBlock):
    def __init__(self, name=None, request=None, children=None):
        super(HTTPRequestMethod, self).__init__(name, request, children)

        if not request:
            request = None

        http_methods = [
            "OPTIONS",
            "PRI",
            "GET",
            "HEAD",
            "POST",
            "PUT",
            "DELETE",
            "TRACE",
            "CONNECT",
            "PATCH",
        ]
        requestblock = Block(
            "HTTP Request",
            children=(
                Group("request-methods", values=http_methods),
                Delim("space-1", " "),
                String("request-path", "/"),
                Delim("space-2", " "),
                String("http-version", "HTTP", max_len=4096),
                Delim("version-slash", "/"),
                Word("major-version", 1, output_format="ascii"),
                Delim("dot-1", "."),
                Word("minor-version", 1, output_format="ascii"),
                Static("crlf", "\r\n"),
            ),
        )

        self.push(requestblock)


def main():
    """ """
    session = Session(target=Target(connection=TCPSocketConnection("127.0.0.1", 8000)))

    upgradetls = Request(
        "upgrade-http",
        children=(
            HTTPRequestMethod("Method"),
            HTTPHeaderHost("Host", "destination.server.ext"),
            HTTPHeaderConnection("Connection", "Upgrade"),
            HTTPHeaderUpgrade("Upgrade"),
            HTTPHeaderAcceptDatetime("AcceptDateTime"),
            HTTPHeaderAcceptCharset("AcceptCharset"),
            HTTPHeaderAcceptEncoding("AcceptEncoding"),
            HTTPHeaderAcceptLanguage("AcceptLanguage"),
            Static("CRLF", "\r\n"),
        ),
    )

    session.connect(upgradetls)

    session.fuzz()


if __name__ == "__main__":
    main()
