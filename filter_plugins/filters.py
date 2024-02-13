
def sha512_pbkdf2(passwd):
    from hashlib import pbkdf2_hmac
    from base64 import b64encode
    import secrets

    # See https://github.com/eclipse/mosquitto/blob/master/src/password_mosq.h
    iterations = 101

    salt = secrets.token_bytes(12)
    dk = pbkdf2_hmac('sha512', passwd.encode('utf8'), salt, iterations )
    return (
            '$7$' + str(iterations) + '$' +
            b64encode(salt).decode() + '$' +
            b64encode(dk).decode()
            )

def dane_record(pem_certificate, usage=3, selector=1, matchtype=1):
    import hashlib
    import cryptography.x509
    from cryptography.hazmat.primitives import serialization

    cert = cryptography.x509.load_pem_x509_certificates(pem_certificate.encode())
    cert = cert[0]

    if selector == 0: # Full cert
        data = cert.public_bytes(encoding=serialization.Encoding.DER)
    elif selector == 1: # Public key
        pubkey = cert.public_key()
        data = pubkey.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    else:
        raise ValueError('Selector type %d not recognized' % selector)

    if matchtype == 0: # Full
        hexdata = data.hex()
    elif matchtype == 1: # Sha256
        hexdata = hashlib.sha256(data).hexdigest()
    elif matchtype == 2: # Sha512
        hexdata = hashlib.sha512(data).hexdigest()
    else:
        raise ValueError('Matching type %d not recognized' % matchtype)

    return '%d %d %d %s' % (usage, selector, matchtype, hexdata)

class FilterModule(object):
    def filters(self):
        return {
            'sha512_pbkdf2': sha512_pbkdf2,
            'dane_record': dane_record,
        }
