"""
UI Routes — serves HTML pages
"""
from flask import Blueprint, render_template

ui = Blueprint("ui", __name__)

@ui.route("/")
def index():
    return render_template("index.html")

@ui.route("/scan")
def scan():
    return render_template("scan.html")

@ui.route("/devices")
def devices():
    return render_template("devices.html")

@ui.route("/alerts")
def alerts():
    return render_template("alerts.html")

@ui.route("/baseline")
def baseline():
    return render_template("baseline.html")

@ui.route("/monitored")
def monitored():
    return render_template("monitored.html")
