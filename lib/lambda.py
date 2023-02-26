from sys import argv
from os import environ
import lib.main

def lambda_handler(event, context):

    # This could be improved:
    # - Reading from the event that could be a finding
    # - Dynamic options from environment or event

    LAMBDA_OPTIONS = ["--output-modes", "lambda", "--no-banners"]
    CUSTOM_OPTIONS = []
    # CUSTOM_OPTIONS = ["--sh-filters", "Id=010101010101"]

    OPTIONS = LAMBDA_OPTIONS + CUSTOM_OPTIONS

    exec = lib.main.main(OPTIONS)
    return exec