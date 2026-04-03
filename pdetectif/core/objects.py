"""
PDF object type representations.

Provides Python classes for all PDF object types as defined in the
PDF specification (ISO 32000). These are used by the parser to build
an in-memory representation of the PDF document.
"""


class PDFBoolean:
    """PDF Boolean object (true/false)."""

    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "true" if self.value else "false"

    def __bool__(self):
        return self.value


class PDFInteger:
    """PDF Integer object."""

    __slots__ = ("value",)

    def __init__(self, value):
        self.value = int(value)

    def __repr__(self):
        return str(self.value)

    def __int__(self):
        return self.value

    def __eq__(self, other):
        if isinstance(other, PDFInteger):
            return self.value == other.value
        if isinstance(other, int):
            return self.value == other
        return NotImplemented

    def __hash__(self):
        return hash(self.value)


class PDFReal:
    """PDF Real (floating-point) object."""

    __slots__ = ("value",)

    def __init__(self, value):
        self.value = float(value)

    def __repr__(self):
        return str(self.value)

    def __float__(self):
        return self.value


class PDFString:
    """PDF literal string object (parenthesized)."""

    __slots__ = ("value", "raw")

    def __init__(self, value, raw=None):
        self.value = value
        self.raw = raw or value

    def __repr__(self):
        return f"({self.value})"

    def __str__(self):
        return self.value


class PDFHexString:
    """PDF hexadecimal string object."""

    __slots__ = ("hex_value", "value")

    def __init__(self, hex_value):
        self.hex_value = hex_value
        try:
            padded = hex_value if len(hex_value) % 2 == 0 else hex_value + "0"
            self.value = bytes.fromhex(padded)
        except ValueError:
            self.value = b""

    def __repr__(self):
        return f"<{self.hex_value}>"

    def __str__(self):
        return self.value.decode("latin-1", errors="replace")


class PDFName:
    """PDF name object (e.g. /Type, /Pages)."""

    __slots__ = ("name", "raw_name")

    def __init__(self, name, raw_name=None):
        self.name = name
        self.raw_name = raw_name or name

    def __repr__(self):
        return f"/{self.name}"

    def __str__(self):
        return self.name

    def __eq__(self, other):
        if isinstance(other, PDFName):
            return self.name == other.name
        if isinstance(other, str):
            return self.name == other
        return NotImplemented

    def __hash__(self):
        return hash(self.name)

    @property
    def is_obfuscated(self):
        """Check if this name uses hex-encoded characters (#XX)."""
        return self.raw_name != self.name


class PDFArray:
    """PDF array object."""

    __slots__ = ("items",)

    def __init__(self, items=None):
        self.items = items or []

    def __repr__(self):
        return f"[{' '.join(repr(i) for i in self.items)}]"

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        return iter(self.items)

    def __getitem__(self, index):
        return self.items[index]


class PDFDictionary:
    """PDF dictionary object."""

    __slots__ = ("entries",)

    def __init__(self, entries=None):
        self.entries = entries or {}

    def __repr__(self):
        pairs = " ".join(f"/{k} {repr(v)}" for k, v in self.entries.items())
        return f"<< {pairs} >>"

    def get(self, key, default=None):
        return self.entries.get(key, default)

    def __contains__(self, key):
        return key in self.entries

    def __getitem__(self, key):
        return self.entries[key]

    def __iter__(self):
        return iter(self.entries)

    def keys(self):
        return self.entries.keys()

    def values(self):
        return self.entries.values()

    def items(self):
        return self.entries.items()


class PDFStream:
    """PDF stream object (dictionary + binary data)."""

    __slots__ = ("dictionary", "raw_data", "_decoded_data")

    def __init__(self, dictionary, raw_data):
        self.dictionary = dictionary
        self.raw_data = raw_data
        self._decoded_data = None

    def __repr__(self):
        length = len(self.raw_data) if self.raw_data else 0
        return f"stream({repr(self.dictionary)}, {length} bytes)"

    @property
    def decoded_data(self):
        return self._decoded_data

    @decoded_data.setter
    def decoded_data(self, value):
        self._decoded_data = value

    @property
    def data(self):
        """Return decoded data if available, otherwise raw data."""
        return self._decoded_data if self._decoded_data is not None else self.raw_data


class PDFReference:
    """PDF indirect object reference (e.g. 1 0 R)."""

    __slots__ = ("obj_num", "gen_num")

    def __init__(self, obj_num, gen_num=0):
        self.obj_num = obj_num
        self.gen_num = gen_num

    def __repr__(self):
        return f"{self.obj_num} {self.gen_num} R"

    def __eq__(self, other):
        if isinstance(other, PDFReference):
            return self.obj_num == other.obj_num and self.gen_num == other.gen_num
        return NotImplemented

    def __hash__(self):
        return hash((self.obj_num, self.gen_num))


class PDFNull:
    """PDF null object."""

    def __repr__(self):
        return "null"

    def __bool__(self):
        return False


class PDFIndirectObject:
    """A PDF indirect object definition (N G obj ... endobj)."""

    __slots__ = ("obj_num", "gen_num", "value", "offset", "raw_data")

    def __init__(self, obj_num, gen_num, value, offset=None, raw_data=None):
        self.obj_num = obj_num
        self.gen_num = gen_num
        self.value = value
        self.offset = offset
        self.raw_data = raw_data

    def __repr__(self):
        return f"{self.obj_num} {self.gen_num} obj {repr(self.value)} endobj"

    @property
    def is_stream(self):
        return isinstance(self.value, PDFStream)

    @property
    def dictionary(self):
        if isinstance(self.value, PDFStream):
            return self.value.dictionary
        if isinstance(self.value, PDFDictionary):
            return self.value
        return None

    @property
    def type_name(self):
        """Get the /Type value if this object has a dictionary."""
        d = self.dictionary
        if d and "Type" in d:
            val = d.get("Type")
            if isinstance(val, PDFName):
                return val.name
        return None


class PDFXRefEntry:
    """A single cross-reference table entry."""

    __slots__ = ("offset", "gen_num", "in_use")

    def __init__(self, offset, gen_num, in_use=True):
        self.offset = offset
        self.gen_num = gen_num
        self.in_use = in_use

    def __repr__(self):
        status = "n" if self.in_use else "f"
        return f"{self.offset:010d} {self.gen_num:05d} {status}"


class PDFDocument:
    """Represents a parsed PDF document."""

    def __init__(self):
        self.header = ""
        self.version = ""
        self.raw_data = b""
        self.objects = {}
        self.xref_tables = []
        self.trailers = []
        self.startxref_offsets = []
        self.xref_streams = []
        self.linearized = False
        self.encrypted = False
        self.encryption_dict = None
        self.incremental_updates = 0
        self.eof_count = 0
        self.file_size = 0
        self.file_path = ""

    def get_object(self, obj_num, gen_num=0):
        """Retrieve an indirect object by number and generation."""
        return self.objects.get((obj_num, gen_num))

    def get_objects_by_type(self, type_name):
        """Get all objects with a specific /Type value."""
        result = []
        for obj in self.objects.values():
            if obj.type_name == type_name:
                result.append(obj)
        return result

    @property
    def page_count(self):
        """Get the number of pages in the document."""
        pages = self.get_objects_by_type("Pages")
        for p in pages:
            d = p.dictionary
            if d and "Count" in d:
                val = d.get("Count")
                if isinstance(val, PDFInteger):
                    return val.value
                if isinstance(val, int):
                    return val
        return 0

    @property
    def catalog(self):
        """Get the document catalog (root object)."""
        cats = self.get_objects_by_type("Catalog")
        return cats[0] if cats else None
