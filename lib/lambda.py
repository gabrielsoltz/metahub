from sys import argv
from os import environ
import lib.main

def lambda_handler(event, context):
    # print (event)
    # print (context)
    # for key in environ:
    #     print(key, '=>', environ[key])
    exec = lib.main.main(["--output-modes", "lambda", "--no-banners"])
    return exec