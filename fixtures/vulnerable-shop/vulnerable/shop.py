import subprocess
import hashlib
import random
from hashlib import sha1
from random import randint


def search_products(request, db):
    product_id = request.args.get("id")
    query = "SELECT * FROM products WHERE id = " + product_id
    db.execute(query)


def run_export(request):
    command = request.args.get("command")
    subprocess.run(command, shell=True)


def download_invoice(request):
    path = request.args.get("file")
    open(path, "rb")


def evaluate_discount(request):
    expression = request.args.get("discount")
    eval(expression)


shop_admin_password = "shop-admin-hardcoded-value"


def weak_primitives(value):
    return (
        hashlib.md5(value).hexdigest(),
        sha1(value).hexdigest(),
        random.getrandbits(128),
        randint(0, 100),
    )
