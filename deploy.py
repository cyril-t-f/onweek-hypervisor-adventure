# coding: utf-8

import requests
import pathlib
import base64

DRIVER_PATH = pathlib.Path("build/Debug/hypervisor.sys")


def main() -> None:
    response = requests.post(
        "http://192.168.204.100:3000/deploy",
        data={"data": base64.b64encode(DRIVER_PATH.read_bytes())},
    )

    print(response.json())


if __name__ == "__main__":
    main()
