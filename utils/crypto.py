from execjs import compile


class Crypto:
    script = compile(open("utils/enc.js").read())

    def encrypt(password: str, randomNum: str, Key: str) -> str:

        return Crypto.script.call(
            "encrypt", password, randomNum, Key)