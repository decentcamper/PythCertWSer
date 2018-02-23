from flask import Flask
from flask import jsonify
from AnotherClass  import Person


app = Flask(__name__)


@app.route('/')
def hello_world():
    return 'Hello World!'

@app.route('/gerCert')
def summary():
    # d = make_summary()
    # return jsonify(d)
    person = Person()
    headers = person.prepare_auth_header("/top/Systems","GET",None, None,'/Users/viveksh2/Documents/Work/CDX/dev/PythCertWSer/cdx_is_key.pem',
                                         "59a451338919490001355f85/5a788d806439747238d59b19/5a7957ac6439747238be2b10","qa.starshipcloud.com", "'qa.starshipcloud.com","/api/v1")
    print(headers)
    return jsonify(headers)

if __name__ == '__main__':
    app.run()




