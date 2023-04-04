from flask import Flask, request

app = Flask(__name__)


@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def catch_all(path):
    if request.form:
        print('Form:' + str(request.form))
    if request.data:
        print('Data:' + str(request.data))

    return ''


app.run(host="192.168.43.56", port=5000)
