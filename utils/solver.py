from requests import post
from time     import sleep
from json     import load


class Funcaptcha:
    key = load(open("./data/config.json"))['captcha_key']

    def getKey() -> str:
        req = post("https://api.anycaptcha.com/createTask", json = {
                "clientKey": Funcaptcha.key,
                "task": {
                    "type"            : "FunCaptchaTaskProxyless",
                    "websitePublicKey": "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA",
                    "websiteURL"      : "https://iframe.arkoselabs.com",
                },
        })

        while True:
            sleep(0.3)
            task = post("https://api.anycaptcha.com/getTaskResult", json = {
                "clientKey" : Funcaptcha.key,
                "taskId"    : req.json()["taskId"]
            })

            if task.json()["status"] == "ready":
                return task.json()["solution"]["token"]