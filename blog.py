import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = "du.uyX9fE~Tb6.pp&U3D-0smY0,Gqi$^jS34tzu9"

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
   return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
        return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
        name = name,
        pw_hash = pw_hash,
        email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.StringProperty(required = True)
    parent_blog = db.StringProperty()
    likes = db.StringListProperty()

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class BlogFront(BlogHandler):
    def get(self):
        #posts = db.GqlQuery("select * from Post order by created desc limit 10")
        posts = Post.all().filter('parent_blog =', None).order('-created')
        uid = self.read_secure_cookie('user_id')
        self.render('front.html', posts = posts, uid = uid)

        if not posts:
            error = "That post does not exist!"
            self.render("error-page.html", error)
            return

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        uid = self.read_secure_cookie('user_id')

        if post.likes and uid in post.likes:
            likeText = 'unlike'
        else:
            likeText = 'like'

        totalLikes = len(post.likes)

        comments = Post.all().filter('parent_blog =', post_id)

        for comment in comments:
            print(comments)

        if not post:
            error = "That post does not exist!"
            self.render("error-page.html", error)
            return

        self.render("permalink.html", post = post, likeText = likeText, totalLikes = totalLikes, uid = uid, comments = comments)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        uid = self.read_secure_cookie('user_id')

        if subject and content:
            post = Post(parent = blog_key(), subject = subject, content = content, user_id = uid, parent_blog = post_id)
            post.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render("permalink.html", subject=subject, content=content, error=error)

class EditPost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            error = "That post does not exist!"
            self.render("edit.html", error=error)
            return

        uid = self.read_secure_cookie('user_id')

        if (int(post.user_id)!= int(uid)):
            error = 'You don\'t have permission to edit this post'
        else:
            error = ''

        self.render("edit.html", post = post, error = error, uid=uid)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post is not None:
            uid = self.read_secure_cookie('user_id')

            subject = self.request.get('subject')
            content = self.request.get('content')

            if subject and content and post.user_id == uid:
                post.subject = subject
                post.content = content
                post.put()
                if post.parent_blog:
                    redirect_id = post.parent_blog
                else:
                    redirect_id = post.key().id()
                    self.write(redirect_id)
                    error = "Sorry! that blog post does not exist"
                    self.render("edit.html", error=error)

                self.redirect('/blog/%s' % str(redirect_id))
            else:
                error = "subject and content, please!"
                self.render("edit.html", post = post, error=error)


class NewPost(BlogHandler):
    def get(self):
        uid = self.read_secure_cookie('user_id')
        if self.user:
            self.render("newpost.html", uid=uid)
        else:
            self.redirect("/login")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        uid = self.read_secure_cookie('user_id')

        if subject and content and uid:
            p = Post(parent = blog_key(), subject = subject, content = content, user_id = uid)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        uid = self.read_secure_cookie('user_id')

        if (int(post.user_id) != int(uid)):
            error = 'Sorry, you cannot delete this post'
        else:
            error = ''
            db.delete(key)

        self.render("delete.html")

class LikePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            error = "That post does not exist!"
            self.render("error-page.html", error=error)
            return

        uid = self.read_secure_cookie('user_id')
        if post.user_id != uid:

            if post.likes and uid in post.likes:
                post.likes.remove(uid)
            else:
                post.likes.append(uid)

            post.put()
            print(post.likes)

            self.redirect('/blog/%s' % str(post.key().id()))

        else:
            error = 'sorry! you can\'t like your own post!'
            self.render("error-page.html", error = error)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            #self.redirect('/unit2/welcome?username=' + self.username)
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' +self.username)


class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/unit3/welcome')


class Login(BlogHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/unit3/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/login')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')


class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/edit/([0-9]+)', EditPost),
                               ('/delete/([0-9]+)', DeletePost),
                               ('/like/([0-9]+)', LikePost),
                               ('/login', Login),
                               ('/logout', Logout)
                               ],
                              debug=True)

def main():
    from paste import httpserver
    httpserver.serve(app, host='127.0.0.1', port='8080')

if __name__ == '__main__':
    main()