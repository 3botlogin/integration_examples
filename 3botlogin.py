# Example for integrating 3botlogin into python

from flask import Flask, redirect, request, abort
import flask
import nacl
import nacl
import nacl.secret
import nacl.signing
import nacl.utils
import nacl.encoding
from nacl.public import PrivateKey, Box
import random
import string
import base64
import urllib.parse
from urllib.request import urlopen
import json
#pip3 install pynacl flask 
app = Flask(__name__)

# These keys are generated but should be stored on the disc as they should not change everytime the program starts
sk = PrivateKey.generate()
pk = sk.public_key

pkb64 = sk.public_key.encode(
    encoder=nacl.encoding.Base64Encoder).decode("utf-8")


def randomString(stringLength=10):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


@app.route('/')
def hello():
    state = randomString()
    res = flask.make_response(redirect(
        'https://login.threefold.me/?state={}&scope=user:email&appid=pythoniseasy&publickey={}&redirecturl=http://localhost:5000/callback'.format(state, urllib.parse.quote_plus(pkb64))))
    res.set_cookie("state", value=state)
    return res


@app.route('/callback')
def callback():
    signedhash = request.args.get('signedhash')
    username = request.args.get('username')
    userResponse = urlopen(
        "https://login.threefold.me/api/users/{}".format(username))

    username = request.args.get('username')
    data = json.loads(userResponse.read())
    userPk = data['publicKey']

    verify_key = nacl.signing.VerifyKey(userPk,
                                    encoder=nacl.encoding.Base64Encoder)
  

    try:
        verify_key.verify(base64.b64decode(signedhash))
    except:
        print("User signed hash not ok!")
        return abort(400)

    return "user logged in!" #ADD JWT AS COOKIE HERE

if __name__ == '__main__':
    app.run()
