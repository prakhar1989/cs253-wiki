import os 
import sys
import webapp2
import markupsafe
import jinja2
import datetime
from google.appengine.ext import db
from google.appengine.api import memcache
from webapp2 import uri_for

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
sys.path.append(os.path.join(os.path.dirname(__file__), 'lib'))

import markdown2
import auth_helpers
import valid_helpers

### BASE HANDLER CLASS ###
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, logged_in = self.user, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = auth_helpers.make_secure_val(val)
        self.response.headers.add_header(
                'Set-Cookie', "%s=%s; Path=/" % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and auth_helpers.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def users_key(group = "default"):
    return db.Key.from_path('users', group)

### AUTH STUFF ###
class User(db.Model):
    username = db.StringProperty(required = True)
    email = db.StringProperty()
    pw_hash = db.StringProperty(required = True)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('username =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = auth_helpers.make_pw_hash(name, pw)
        return User(parent = users_key(),
                    username = name,
                    pw_hash = pw_hash,
                    email = email)
    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and auth_helpers.valid_pw(name, pw, u.pw_hash):
            return u

class SignupHandler(Handler):
    def get(self):
        self.render("signup_form.html")

    def post(self):
        have_error = False
        self.user_username = self.request.get('username')
        self.user_password = self.request.get('password')
        self.user_verify = self.request.get('verify')
        self.user_email = self.request.get('email')
        
        check_username = valid_helpers.valid_username(self.user_username)
        check_password = valid_helpers.valid_password(self.user_password)
        check_verify = valid_helpers.valid_verify(self.user_verify, self.user_password)
        check_email = valid_helpers.valid_email(self.user_email)

        params = dict(user_username = self.user_username, user_email = self.user_email)

        if not(check_username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        if not(check_password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        if not(check_verify):
            params['error_verify'] = "Your passwords didn't match."
            have_error = True
        if not(check_email):
            params['error_email'] = "That's not a valid email."
            have_error = True
        if not have_error:
            existing_user = User.by_name(self.user_username)
            if existing_user:
                params['error_username'] = "This user already exists"
                have_error = True

        if have_error:
            self.render("signup_form.html", **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class RegisterHandler(SignupHandler):
    def done(self):
        u = User.register(self.user_username, self.user_password, self.user_email)
        u.put()
        self.login(u)
        self.redirect('/')

class LoginHandler(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        params = dict(username = user_username)
        u = User.login(user_username, user_password)
        if u: 
            self.login(u)
            self.redirect('/')
        else:
            params["error_username"] = "Invalid login"
            params["error_password"] = " "
            self.render("login.html", **params)

class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect(uri_for("main"))

### MODEL FOR WIKI
class Wiki(db.Model):
    content = db.TextProperty(required = True)
    parent_page = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now_add = True)

class MainPage(Handler):
    def get(self):
        try:
            w = Wiki.all().filter("parent_page =", "home").fetch(1)[0]
            content = w.content
        except IndexError:
            content = ""
        self.render("main.html", content = content, wiki_url = "/")

class EditPageHandler(Handler):
    def get(self, wiki_url):
        if not self.user:
            self.redirect('/login')
        if wiki_url == "/": #this construct looks horrific ; change
            wiki_url = "/home"
        try:
            w = Wiki.all().filter("parent_page =", wiki_url[1:]).fetch(1)[0]
            content = w.content
        except IndexError:
            content = ""
        self.render("edit_page.html", wiki_url = wiki_url, content = content)
    
    def post(self, wiki_url):
        if self.user:
            content = self.request.get("content")
            home_redirect = False
            if content:
                if wiki_url == "/": #this construct looks horrific ; change
                    home_redirect = True
                    wiki_url = "/home"
                try:
                    w = Wiki.all().filter("parent_page =", wiki_url[1:]).fetch(1)[0]
                    w.content = content
                except IndexError:
                    w = Wiki(content = content, parent_page = wiki_url[1:])
                w.put()
                if home_redirect:
                    self.redirect('/')
                else:
                    self.redirect('%s' % wiki_url)
            else:
                self.redirect('/_edit' + wiki_url)

class ShowWikiHandler(Handler):
    def get(self, wiki_url):
        try:
            if wiki_url == "/": 
                self.redirect(uri_for('main'))
            w = Wiki.all().filter("parent_page =", wiki_url[1:]).fetch(1)[0]
            self.render("show_page.html", content = w.content, wiki_url = wiki_url)
        except IndexError:
            self.redirect('/_edit' + wiki_url)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
                           webapp2.Route('/', MainPage, name="main"),
                           webapp2.Route('/signup', RegisterHandler, name="signup"),
                           webapp2.Route('/login', LoginHandler, name="signup"),
                           webapp2.Route('/logout', LogoutHandler, name="logout"),
                           ('/_edit' + PAGE_RE, EditPageHandler), # fix this to webapp2.Route
                           (PAGE_RE, ShowWikiHandler),
], debug = True)
