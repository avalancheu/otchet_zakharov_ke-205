#!/usr/bin/env python3
"""
Потоковое обезличивание CIM/RDF XML.
Запуск: python anonymize_cim.py input.xml.zip anonymized_model.xml.zip
Зависимость: lxml (pip install lxml)
"""
import sys, zipfile, hashlib, hmac, re, os
from lxml import etree

SECRET = b"cim-demo-anonymization-key-v1"
RDF = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}"

# Значения, которые не являются именами конкретных энергообъектов.
SAFE_NAMES = {"CIM16", "Equivalent of Global Objects", "Local Objects"}

def digest(value):
    return hmac.new(SECRET, value.encode("utf-8", "ignore"), hashlib.sha256).hexdigest()

def token(value, prefix="Синтетический"):
    return f"{prefix}_{digest(value)[:12].upper()}"

def fake_digits(value):
    d = digest(value)
    return "".join(str(int(d[i:i+2], 16) % 10) for i in range(len(value)))

def anonymize_text(tag, value, object_type="Объект"):
    if value is None or not value.strip():
        return value
    s = value.strip()
    low = tag.lower()

    # Персональные данные
    if any(x in low for x in ("firstname", "lastname", "middlename", "fullname",
                              "inchargefullname", "person.name")):
        return "Иванов Иван Иванович"
    if any(x in low for x in ("phone", "mobile", "telephone", "fax")):
        return "+7" + fake_digits(re.sub(r"\D", "", s)[-10:].rjust(10, "0"))
    if "email" in low or "mailaddress" in low:
        return "user_" + digest(s)[:10] + "@example.invalid"
    if any(x in low for x in ("passport", "inn", "kpp", "snils", "account",
                              "contract", "personnel", "employee", "meteringpointcode",
                              "mridstr", "mrid")):
        return fake_digits(s) if s.isdigit() else token(s, "ID")
    if "serialnumber" in low or "inventory" in low:
        return fake_digits(s) if s.isdigit() else token(s, "INV")

    # Адреса, географические идентификаторы, IP и координаты
    if any(x in low for x in ("address", "street", "town", "city", "buildingname",
                              "fiasid", "fiasstreetid", "ipconnectionpoint")):
        return token(s, "Адрес")
    if low in ("position.x", "position.y", "position.z", "location.x", "location.y",
               "location.z", "coordinate.x", "coordinate.y", "coordinate.z"):
        return "0"
    if re.fullmatch(r"[-+]?\d{1,3}(?:\.\d{1,10})?", s) and ("latitude" in low or "longitude" in low):
        return "0"

    # Наименования, диспетчерские обозначения и свободные текстовые поля
    if low.endswith(".name") or low in ("name.name", "blobstorage.name", "foldernode.foldername"):
        if s in SAFE_NAMES:
            return s
        return token(s, object_type)
    if any(x in low for x in ("description", "comment", "annotation", "remark", "log",
                              "attachment", "filename", "documentname")):
        return "[ОБЕЗЛИЧЕНО]"

    return value

def process(input_zip, output_zip):
    with zipfile.ZipFile(input_zip, "r") as zin:
        xml_names = [n for n in zin.namelist() if n.lower().endswith(".xml") and not n.startswith("__MACOSX/")]
        if not xml_names:
            raise RuntimeError("В архиве не найден XML")
        source_name = xml_names[0]
        with zin.open(source_name) as src, zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zout:
            with zout.open("anonymized_model.xml", "w") as raw_out:
                # Получаем корень и записываем XML по одному непосредственному потомку.
                context = etree.iterparse(src, events=("start", "end"), huge_tree=True, recover=False)
                event, root = next(context)
                with etree.xmlfile(raw_out, encoding="utf-8") as xf:
                    xf.write_declaration()
                    with xf.element(root.tag, root.attrib, nsmap=root.nsmap):
                        for event, elem in context:
                            if event != "end":
                                continue
                            parent = elem.getparent()
                            if parent is root:
                                cls = next((etree.QName(c).localname for c in elem
                                            if isinstance(c.tag, str) and not etree.QName(c).localname.startswith("IdentifiedObject.")),
                                           "Объект")
                                for node in elem.iter():
                                    if not isinstance(node.tag, str):
                                        continue
                                    local = etree.QName(node).localname
                                    if node.text and node.text.strip():
                                        node.text = anonymize_text(local, node.text, cls)
                                    # Сохраняем RDF-ссылки и UUID-модельные идентификаторы,
                                    # поскольку они обеспечивают связность графа.
                                xf.write(elem)
                                elem.clear()
                                while elem.getprevious() is not None:
                                    del root[0]
            print(f"Обработан файл: {source_name}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Использование: python anonymize_cim.py input.xml.zip output.xml.zip")
        raise SystemExit(2)
    process(sys.argv[1], sys.argv[2])