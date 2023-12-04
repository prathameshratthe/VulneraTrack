from fastapi import FastAPI
from fastapi import Request
from script import Target
app = FastAPI()


@app.post('/{_:path}')
def home(request: Request):
    t=Target(request.url.path[1:])
    print(t.score)
    return {'score':t.score,'http_status':t.http_status,'ssl_certificate':t.ssl_certificate,'security_headers':t.security_headers,'dns_info':t.dns_info,'whois_info':t.whois_info,'google_safebrowsing':t.google_safebrowsing}

@app.get('/{_:path}')
def home(request: Request):
    t=Target(request.url.path[1:])
    print(t.score)
    return {'score':t.score }

