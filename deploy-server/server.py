# coding: utf-8

import flask
import pathlib
import base64
import subprocess
import json
import hashlib

APP = flask.Flask(__name__)
DRIVER_PATH = pathlib.Path("C:/Users/Cyril/Desktop/hypervisor.sys")
SLEEP_TIME = 10

def exec_command(command: str)->tuple[int, str]:
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
    output, _ = process.communicate()
    process.wait()

    return process.returncode, output.decode("utf-8")



@APP.route("/deploy", methods=["POST"])
def deploy() -> str:
    c,m = exec_command("sc stop my-hypervisor")
    if c and c != 1062:
        return json.dumps({'result': False, "msg": "Failed to stop driver", "reason": m})

    data = base64.b64decode(flask.request.values["data"])
    try:
        DRIVER_PATH.write_bytes(data)
        print(hashlib.sha256(data).hexdigest())
    except Exception as e:
        return json.dumps({'result': False, "msg": "Failed to write driver", "reason": str(e)})


    c,m = exec_command("sc start my-hypervisor")
    if c:
        return json.dumps({'result': False, "msg": "Failed to start driver", "reason": m})

    return json.dumps({"result": True, "msg":"Successfully deployed driver", "reason":None}) 


def main() -> None:
    APP.run(host="0.0.0.0", port=3000)
    pass


if __name__ == "__main__":
    main()
