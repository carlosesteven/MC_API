import base64
import hashlib
import time
import json
import asyncio
from urllib import parse
import re
import aiohttp

from typing import Awaitable, Callable, Iterable, TypeVar, overload, Literal
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from enum import StrEnum, IntEnum

T = TypeVar("T")


class ResolverFlags(IntEnum):
    FALLBACK = 1
    REVERSE = 1 << 1
    FROMCHARCODE = 1 << 2
    SLICE = 1 << 3
    SPLIT = 1 << 4
    ABC = 1 << 5


class Patterns(StrEnum):
    _FUNC = r"[\w$]{3}\.[\w$]{2}"
    _FUNC2 = r"[\w$]\.[\w$]{2}"
    _FUNC3 = r"[\w$]{3}\.[\w$]{3}"

    SOURCE_ID = r"embed-2/v2/e-1/([A-z0-9]+)\?"

    IDX = r'"(\d+)"'
    VAR = r'[ ;]{name}=(?:\+?"?(\d+)"?;|[\w$][\w$][\w$]\.[\w$][\w$]\(((?:"?\d+"?,?)+)\))'
    DICT = r"[\w$]{2}=\{\}"

    XOR_KEY = r"\)\('(.+)'\)};"
    STRING = r"function [\w$]{2}\(\){return \"(.+?)\";}"
    DELIMITER = r"[\w$]{3}=\w\.[\w$]{2}\([\w$]{3},'(.)'\);"

    BITWISE_SWITCHCASE = r"\w\[\d+\]=\(function\([\w$]+\)[{\d\w$:\(\),= ]+;switch\([\w$]+\){([^}]+)}"
    BITWISE_OPERATION = r"case (\d+):([\w\[\]\-+|><^* =$\(\)]+);break;"
    BITWISE_DEF_FLAG_FUNC = r"\w\[\d+\]=\(function\([\w$]+\).+?;switch\([\w$]+\){[^,]+,([\w$]+)"
    SET_DEF_FLAG = rf"{_FUNC}\((\d+)\)"

    SLICES = rf"case\s(\d{{1,2}}):{_FUNC2}\({_FUNC2}\(\),[\w$]{{3}},{_FUNC2}\({_FUNC2}\([\w$]{{3}},([\d\-]+),[\d\-]+\),[\d\-]+,([\d\-]+)\)\)"

    _GET1_INDEX = r'+?"?([\w$]+)"?( [|\-\+*><^]+ "?[\w$]+"?)?'
    GET1 = rf"{_FUNC}\(\{_GET1_INDEX}\)"
    GET2 = rf'{_FUNC}\({_FUNC}\("?(\w+)"?,"?(\w+)"?\)\)'
    GET3 = rf'{_FUNC}\({_FUNC}\("?(\w+)"?,"?(\w+)"?,{SET_DEF_FLAG}\)\)'
    GET = f"({GET1}|{GET2}|{GET3})"

    INDEX_ARRAY_CONTENT = r'\w=\[((?!arguments)[\w\d.$\(\)",+]+)\];'
    INDEX_ARRAY_ITEM = rf'({_FUNC}\([\w",\(\)]+\))|({_FUNC}\("?\d+"?,"?\d+"?,{_FUNC}\(\d+\)\))|(\d+)'

    KEY_ARRAY_CONTENT = rf'\w=\[((?!arguments)[\w\d.$\(\)",+]+)\];'
    KEY_VAR = r"var (?:[\w$]{1,2},){28,}.+?[\w$\.]+=([^;]+?);"

    MAP = r"\((\w)=>{(.+?return.+?;)"

    PARSE_INT = r'[\w$]+\({},\+?"?16"?'
    BITWISE2 = rf"{_FUNC}\((\w),(\w)\)"
    BITWISE3 = rf'{_FUNC}\("?(\d+)"?,"?(\d+)"?,{_FUNC}\((\d)\)\)'

    GET_KEY = r"var (?:[\w$]{1,2},?){28,};(.+?)try"
    GET_KEY_FUNC = r"(\w)=\(\)=>{(.+?)};"
    GET_KEY_FUNC_RETURN = r"return(.+?);[\}\)]"

    DICT_SET1 = rf"[\w$]{{2}}\[(?:{GET})\]=({GET})"
    DICT_SET2 = rf"[\w$]{{2}}\[(?:{GET})\]=\(\)=>({{.+?return {GET})"
    DICT_SET = f"{DICT_SET1}|{DICT_SET2}"

    def fmt(self, *args, **kwargs) -> "Patterns":
        self._fmted = self.value.format(*args, **kwargs)
        return self

    @property
    def formatted(self) -> str:
        return getattr(self, "_fmted", self.value)


class Resolvers:
    @staticmethod
    def _get_key(s: "Megacloud") -> str:
        fcall = _re(Patterns.KEY_VAR, s.script).group(1)
        args = _re(Patterns.GET, fcall).groups()

        return s._get(args[1:], fcall).replace("-", "")

    @staticmethod
    def _get_keys(s: "Megacloud") -> list[str]:
        array_items = _re(Patterns.KEY_ARRAY_CONTENT, s.script, all=True)[0]
        array_items = re.split(r"(?<=\)),(?=\w)", array_items)
        keys = []

        if any(i.isdigit() for i in array_items) or len(array_items) % 16 != 0:
            return keys

        for fcall in array_items:
            args = _re(Patterns.GET, fcall).groups()
            keys.append(s._get(args[1:], ""))

        return keys

    @staticmethod
    def _get_indexes(s: "Megacloud") -> list[int]:
        array_items = _re(Patterns.INDEX_ARRAY_CONTENT, s.script, all=True)[-1]
        array_items = _re(Patterns.INDEX_ARRAY_ITEM, array_items, all=True)
        indexes = []

        if not any(any(ii.isdigit() for ii in i) for i in array_items) or len(array_items) % 16 != 0:
            return indexes

        for m in array_items:
            idx = m[0] or m[1] or m[2]

            if not idx.isdigit():
                idx = _re(Patterns.IDX, idx).group(1)

            indexes.append(int(idx))

        return indexes

    @classmethod
    def slice(cls, s: "Megacloud") -> tuple[list, list]:
        key = cls._get_key(s)
        if key.endswith("="):
            key = base64.b64decode(key).decode()

        return list(key), list(range(0, len(key)))

    @classmethod
    def abc(cls, s: "Megacloud") -> tuple[list, list]:
        values = {}
        c = _re(Patterns.GET_KEY, s.script).group(1)

        for f in _re(Patterns.DICT_SET, c, all=True):
            i = 0 if f[0] else 17
            key_idxs = list(filter(None, f[i + 1 : i + 8]))

            context = f[i + 8]
            value_idxs = list(filter(None, f[i + 10 : i + 17]))

            k = s._get(key_idxs, c)
            v = s._get(value_idxs, context)

            values[k] = v

        get_key_func = _re(Patterns.GET_KEY_FUNC, c).group(2)

        order = get_key_func.split("return")[-1].split(";")[0]
        order = order.replace("()", "")
        order = re.sub(rf"\w\[(.+?)\]", r"\1", order)

        for f in _re(Patterns.GET, order, all=True):
            indexes = list(filter(None, f[1:]))

            v = s._get(indexes, get_key_func)
            order = order.replace(f[0], f'"{values[v]}"')

        key = eval(order)
        return list(key), list(range(0, len(key)))

    @classmethod
    def add_funcs(cls, s: "Megacloud") -> tuple[list, list]:
        get_key = _re(Patterns.GET_KEY, s.script).group(1)
        funcs = _re(Patterns.GET_KEY_FUNC, get_key, all=True)

        if len(funcs) < 3:
            return [], []

        key = ""

        for f in funcs[:-1]:
            ret = _re(Patterns.GET_KEY_FUNC_RETURN, f[1]).group(1)
            args = _re(Patterns.GET, ret).groups()

            key += s._get(args[1:], f[1])

        return list(key), list(range(0, len(key)))

    @classmethod
    def map(cls, s: "Megacloud") -> tuple[list, list]:
        try:
            keys = cls._get_keys(s)
        except ValueError:
            keys = []

        try:
            indexes = cls._get_indexes(s)
        except ValueError:
            indexes = []

        return keys, indexes

    @classmethod
    def from_charcode(cls, s: "Megacloud", keys: list = [], indexes: list = []) -> tuple[list, list]:
        raw_values = []

        if indexes:
            map_ = _re(Patterns.MAP, s.script)
            map_arg = map_.group(1)
            map_body = map_.group(2)

            if m := _re(Patterns.BITWISE2, map_body, default=None):
                flag = _re(Patterns.SET_DEF_FLAG, map_body).group(1)
                func = s.bitwise[int(flag)]

                var_name = m.group(1) if m.group(1) != map_arg else m.group(2)
                var_value = s._var_to_num(var_name, s.script)

                raw_values = [func(int(var_value), int(i)) for i in indexes]

        elif keys:
            map_ = _re(Patterns.MAP, s.script)
            map_arg = map_.group(1)
            map_body = map_.group(2)

            if _re(Patterns.PARSE_INT.fmt(map_arg), map_body, default=None):
                raw_values = [int(k, 16) for k in keys]

        else:
            indexes = cls._get_indexes(s)
            raw_values = [int(i) for i in indexes]

        return [chr(v) for v in raw_values], list(range(0, len(raw_values)))

    @classmethod
    def fallback(cls, s: "Megacloud", keys: list, indexes: list) -> tuple[list, list]:
        def _map(_) -> tuple[list, list]:
            if keys and indexes:
                key = "".join(keys[i] for i in indexes)
                if len(key) == 64:
                    return keys, indexes

            return [], []

        to_try = [_map, cls.slice, cls.add_funcs, cls.from_charcode]

        for func in to_try:
            try:
                res = func(s)
                if res[0]:
                    return res
                continue

            except ValueError:
                continue

        return [], []

    @classmethod
    def resolve(cls, flags: int, s: "Megacloud") -> bytes:
        key = ""
        keys, indexes = cls.map(s)

        if flags & (ResolverFlags.SLICE | ResolverFlags.SPLIT):
            keys, indexes = cls.slice(s)

        if flags & ResolverFlags.FROMCHARCODE:
            keys, indexes = cls.from_charcode(s, keys, indexes)

        if flags & ResolverFlags.ABC:
            keys, indexes = cls.abc(s)

        if flags & ResolverFlags.FALLBACK:
            keys, indexes = cls.fallback(s, keys, indexes)

        key = [keys[i] for i in indexes]

        if flags & ResolverFlags.REVERSE:
            key = reversed(key)

        return "".join(key).encode()


async def make_request(url: str, headers: dict, params: dict, func: Callable[[aiohttp.ClientResponse], Awaitable[T]]) -> T:
    async with aiohttp.ClientSession() as client:
        async with client.get(url, headers=headers, params=params) as resp:
            return await func(resp)


@overload
def _re(pattern: Patterns, string: str) -> re.Match: ...
@overload
def _re(pattern: Patterns, string: str, *, default: T) -> re.Match | T: ...
@overload
def _re(pattern: Patterns, string: str, *, all: Literal[True]) -> list: ...
@overload
def _re(pattern: Patterns, string: str, *, all: Literal[True], default: T) -> list | T: ...


def _re(pattern: Patterns, string: str, *, all: bool = False, default: T = None) -> re.Match | list | T:
    v = re.findall(pattern.formatted, string) if all else re.search(pattern.formatted, string)

    if not v and default:
        return default

    elif not v:
        msg = f"{pattern.name} not found"
        raise ValueError(msg)

    return v


def derive_key_and_iv(password: bytes) -> tuple[bytes, bytes]:
    hashes = []
    digest = password

    for _ in range(3):
        hash = hashlib.md5(digest).digest()
        hashes.append(hash)
        digest = hash + password

    return hashes[0] + hashes[1], hashes[2]


def decrypt_sources(key: bytes, value: str) -> str:
    bs = AES.block_size
    encrypted = base64.b64decode(value)

    salt = encrypted[8:bs]
    data = encrypted[bs:]

    key, iv = derive_key_and_iv(key + salt)

    obj = AES.new(key, AES.MODE_CBC, iv)
    result = obj.decrypt(data)

    return unpad(result, AES.block_size).decode()


def generate_sequence(n: int) -> list[int]:
    res = [5, 8, 14, 11]
    if n <= 4:
        return res

    for i in range(2, n - 2):
        res.append(res[i] + i + 3 - (i % 2))

    return res


class Megacloud:
    base_url = "https://megacloud.blog"
    headers = {
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64; rv:139.0) Gecko/20100101 Firefox/139.0",
        "origin": base_url,
        "referer": base_url + "/",
    }

    def __init__(self, embed_url: str) -> None:
        self.embed_url = embed_url

        self.script: str
        self.string_array: list[str]
        self.bitwise: dict[int, Callable]

    def _generate_bitwise_func(self, operation: str) -> Callable:
        operation = re.sub(r"[\w$]{2}", "args", operation)
        if any(i in operation for i in (">", "<")):
            v = operation.split()
            v[-1] = f"({v[-1]} & 31)"
            operation = " ".join(v)

        return lambda *args: eval(operation)

    def _get_bitwise_operations(self) -> dict[int, Callable]:
        functions = {}

        switchcase_section = _re(Patterns.BITWISE_SWITCHCASE, self.script).group(1)
        for num, operation in _re(Patterns.BITWISE_OPERATION, switchcase_section, all=True):
            functions[int(num)] = self._generate_bitwise_func(operation.split("=")[1])

        return functions

    def _get_array_slices(self) -> list[tuple[int, ...]]:
        pairs = tuple(map(lambda t: tuple(map(int, t)), _re(Patterns.SLICES, self.script, all=True)))
        order_map = {v: i for i, v in enumerate(generate_sequence(len(pairs)))}

        pairs = list(sorted(pairs, key=lambda t: order_map[t[0]]))
        return pairs

    def _shuffle_array(self, array: list[str]) -> list[str]:
        slices = self._get_array_slices()
        for _, array_idx, tail_idx in slices:
            array, tail = array[:array_idx], array[array_idx:]
            array = tail[:tail_idx] + array

        return array

    def _get_flags(self, ctx: str) -> list[int]:
        try:
            flags = _re(Patterns.SET_DEF_FLAG, ctx, all=True)
            flag = list(filter(lambda i: i <= 15, map(int, flags)))

        except ValueError:
            flag = [0]

        return flag

    def _calc_bitwise(self, args: Iterable, ctx: str) -> int:
        args = map(int, args)

        for f in self._get_flags(ctx):
            try:
                v = self.bitwise[f](*args)

            except IndexError:
                continue

            if v in range(0, len(self.string_array)):
                return v

        raise ValueError(f"wrong bitwise args")

    def _var_to_num(self, var: str, ctx: str) -> str:
        if not var.isdigit():
            var = var.replace("$", r"\$")

            var_value = _re(Patterns.VAR.fmt(name=var), self.script)
            var_value = var_value.group(1) or var_value.group(2)
            var_value = re.findall(r"(\d+)", var_value)

            if len(var_value) == 1:
                return str(var_value[0])

            return str(self._calc_bitwise(var_value, ctx))

        return var

    def _get(self, values, ctx: str) -> str:
        values = list(filter(None, values))

        if len(values) == 1 or not values[1].isdigit():
            if len(values) == 2:
                expression = values[-1].split()

                operator = expression[0]
                operand = self._var_to_num(expression[-1], ctx)

                if any(i in operator for i in (">", "<")):
                    operand = f"({operand} & 31)"

                values[-1] = f"{operator} {operand}"
                i = eval("".join(values))

            else:
                i = int(self._var_to_num(values[0], ctx))

            v = self.string_array[i]

        elif len(values) > 1:
            i1 = int(self._var_to_num(values[0], ctx))
            i2 = int(self._var_to_num(values[1], ctx))

            if len(values) == 3:
                flag = int(self._var_to_num(values[2], ctx))
                i = self.bitwise[flag](i1, i2)

            else:
                i = self._calc_bitwise((i1, i2), ctx)

            v = self.string_array[i]

        else:
            raise ValueError(f"can't get {values}")

        return v

    def _resolve_key(self) -> bytes:
        get_key = _re(Patterns.GET_KEY, self.script).group(1)
        get_key_body = _re(Patterns.GET_KEY_FUNC, get_key).group(2)

        functions: list[str] = []

        for i in _re(Patterns.GET, get_key_body, all=True, default=[]):
            string = self._get(i[1:], get_key_body)
            functions.append(string)

        flags = 0

        for f in functions:
            if f.upper() in ResolverFlags._member_names_:
                flags |= ResolverFlags[f.upper()]

            elif len(f) == 1 and ord(f) in range(97, 123):
                flags |= ResolverFlags.ABC

        if not flags:
            flags = ResolverFlags.FALLBACK

        return Resolvers.resolve(flags, self)

    async def _get_secret_key(self) -> bytes:
        strings = ""

        script_url = f"{self.base_url}/js/player/a/v2/pro/embed-1.min.js"
        script_version = int(time.time())
        self.script = await make_request(script_url, {}, {"v": script_version}, lambda i: i.text())

        xor_key = _re(Patterns.XOR_KEY, self.script).group(1)
        char_sequence = parse.unquote(_re(Patterns.STRING, self.script).group(1))
        delim = _re(Patterns.DELIMITER, self.script).group(1)

        for i in range(len(char_sequence)):
            a = ord(char_sequence[i])
            b = ord(xor_key[i % len(xor_key)])

            idx = a ^ b
            strings += chr(idx)

        string_array = strings.split(delim)
        self.string_array = self._shuffle_array(string_array)
        self.bitwise = self._get_bitwise_operations()

        return self._resolve_key()

    async def extract(self) -> dict:
        id = _re(Patterns.SOURCE_ID, self.embed_url).group(1)
        get_src_url = f"{self.base_url}/embed-2/v2/e-1/getSources"

        resp = await make_request(get_src_url, self.headers, {"id": id}, lambda i: i.json())

        if not resp["sources"]:
            raise ValueError("no sources found")

        key = await self._get_secret_key()
        assert key
        sources = json.loads(decrypt_sources(key, resp["sources"]))

        resp["sources"] = sources

        resp["intro"] = resp["intro"]["start"], resp["intro"]["end"]
        resp["outro"] = resp["outro"]["start"], resp["outro"]["end"]

        return resp


async def main():
    url = "https://megacloud.blog/embed-2/v2/e-1/4HkPRxypS1AS?k=1&autoPlay=1&oa=0&asi=1"
    a = Megacloud(url)
    print(json.dumps(await a.extract(), indent=4))


asyncio.run(main())
