import os
import webapp2
import jinja2

import time

import re

import logging

from google.appengine.api import memcache
from google.appengine.ext import db

import json

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

global cache_time
cache_time = 0

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def get_front_entries(self, update = False):
        key = "top"
        entries = memcache.get(key)
        if entries is None or update:
            logging.error("DB QUERY")
            entries = db.GqlQuery("SELECT * FROM Entry "
                                   "ORDER BY created "
                                    "DESC LIMIT 10")
            entries = list(entries)
            memcache.set(key, entries)
        time_since_query = 0
        if cache_time != 0:
            time_since_query = int(time.time() - cache_time)
        self.render("front.html", entries=entries, time=time_since_query)

class Entry(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now_add = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PASS_RE.match(password)

def valid_verify(password, verify):
    if password == verify:
        return True

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    if email == "":
        return True
    return EMAIL_RE.match(email)

import random
import string
import hashlib

def make_salt():
    salt = ''
    for x in range(5):
        salt += random.choice(string.letters)
    return salt

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s_%s' % (h, salt)

#makes list of dictionary objects with key, value pairs of Entry class properties
#takes list, outputs list
def make_list(entries):
    list_of_dicts = []
    for entry in entries:
        object_dict = {}
        object_dict["content"] = entry.content
        object_dict["subject"] = entry.subject
        list_of_dicts.append(object_dict)
    return list_of_dicts

class User(db.Model):
    username = db.StringProperty(required = True)
    hashed_password = db.StringProperty(required = True)
    email = db.EmailProperty
    
class Front(Handler):
    def render_front(self):
        self.get_front_entries()    
    def get(self):
        self.render_front()

class Json(Handler):
    def render_front(self):
        self.response.headers.add_header('Content-Type', 'application/json')
        entries = db.GqlQuery("SELECT * FROM Entry "
                           "ORDER BY created DESC LIMIT 10")
        entries = list(entries)
        path = self.request.path
        entries_list = make_list(entries)
        entries_list = str(json.dumps(entries_list))
        self.response.out.write(entries_list)
    
    def get(self):
        self.render_front()

class JsonEntry(Handler):
    def render_front(self):
        self.response.headers.add_header('Content-Type', 'application/json')
        path = self.request.path
        path = path[1:-5]
        path = int(path)
        entry = Entry.get_by_id(path)
        if entry:
            entry_list = [entry]
            entry = str(json.dumps(make_list(entry_list)))
            self.response.out.write(entry)
        else:
            self.response.out.write("Entry not found")

    def get(self):
        self.render_front()

class Signup(Handler):

    def get(self):
        self.render('signup.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        val_username = valid_username(username)
        val_password = valid_password(password)
        val_verify = valid_verify(verify, password)
        val_email = valid_email(email)

        params = dict(username = username, email = email)

        if not val_username:
            params['error_username'] = "Not a valid username"

        if not val_password:
            params['error_password'] = "Not a valid password"

        if not val_verify:
            params['error_verify'] = "Passwords don't match"

        if not val_email:
            params['error_email'] = "Not a valid email"

        if val_username and val_password and val_verify and val_email:
            user_hash = make_pw_hash(username, password)
            u = User(username = username, hashed_password = user_hash, email = email)
            u.put()
            user_id = u.key().id()
            cookie_hash = "%s_%s" % (user_id, user_hash)
##            self.redirect("/welcome?username=" + username)
            self.response.headers.add_header('Set-Cookie', 'user_id=%s' % cookie_hash)
            self.redirect("/welcome")
        else:
            self.render("signup.html", **params)

class WelcomeHandler(Handler):
    
    def get(self):
        cookie_str = self.request.cookies.get("user_id")
        user = False
        try:
            user_id = int(cookie_str.split('_')[0])
            user = User.get_by_id(user_id)
        except:
            self.redirect("/")
        if user:
            username = user.username
            self.render("welcome.html", username=username)
        else:
            self.redirect("/")

class NewEntryForm(Handler):
    def render_form(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)

    def get(self):
        self.render_form()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            e = Entry(subject=subject, content=content)
            e.put()

            link = str(e.key().id())

            global cache_time
            cache_time = time.time()

            self.get_front_entries(update = True)
            
##            self.redirect("/entry?link=" + link)
            self.redirect("/%s" % link)
        else:
            error = "We need both a title and a body of text for the entry."
            self.render_form(subject, content, error)

class PermaEntry(Handler):
    def render_entry(self):
        link = self.request.path
        link = link[1:]
        if link[-1] == "/":
            link = link[:-1]
##        self.response.get("link")
        link = int(link)
        entry = Entry.get_by_id(link)
        if entry:
            subject = entry.subject
            content = entry.content
            created = entry.created
        else:
            subject = "Entry not found"
            content = ""
            created = None
        self.render("entry.html", subject=subject, content=content, created=created)

    def get(self):
        self.render_entry()

class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        q = User.all()
        q.filter("username =", username)
        user = q.get()

        params = dict(username = username)

        if user and password:
            user_id = user.key().id()
            stored_hash = str(user.hashed_password)
            salt = stored_hash.split('_')[1]
            new_hash = make_pw_hash(username, password, salt)
            if new_hash == stored_hash:
                cookie_hash = "%s_%s" % (user_id, stored_hash)
                self.response.headers.add_header('Set-Cookie', 'user_id=%s' % cookie_hash)
                self.render("welcome.html", username=username)
            else:
                params['error'] = "Incorrect password"
                self.render("login.html", **params)
        else:
            params['error'] = "Incorrect username or a field is blank"
            self.render("login.html", **params)

class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/signup")

app = webapp2.WSGIApplication([('/', Front),
                               ('/signup/?', Signup),
                               ('/login/?', Login),
                               ('/logout/?', Logout),
                               ('/welcome/?', WelcomeHandler),
                               ('/newpost/?', NewEntryForm),
                               ('/.json', Json),
                               ('/\d+.json', JsonEntry),
                               ('/\d+/?', PermaEntry)],
                              debug=True)
