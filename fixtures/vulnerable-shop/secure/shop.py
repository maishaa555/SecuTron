import ast
import hashlib
import secrets
from hashlib import sha256
import subprocess
from pathlib import Path


def search_products(request, db):
    db.execute("SELECT * FROM products WHERE id = ?", (request.args.get("id"),))


def run_catalog_search(request):
    subprocess.run(["catalog-search", request.args.get("term", "")], shell=False, check=True)


def load_catalog():
    with Path("catalog.json").open("rb") as catalog:
        return catalog.read()


def parse_discount(request):
    return ast.literal_eval(request.args.get("discount", "0"))


def secure_primitives(value):
    return sha256(value).hexdigest(), hashlib.sha256(value).hexdigest(), secrets.token_urlsafe(32)
