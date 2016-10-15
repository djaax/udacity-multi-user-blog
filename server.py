#!/usr/bin/env python

# [START imports]
import os

import jinja2
import webapp2

import re

import hashlib
import string
import random
import hmac

from google.appengine.ext import db

import time

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
# [END imports]

secret = 'nevergonnaletyoudown'


def render_str_global(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Return a salt with a default length of 6 from
# all ascii usercase letters and all digits
# Inspired by
# https://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits-in-python


def make_salt(size=6, chars=string.letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def make_pw_hash(username, pw, salt=None):
    if not salt:
        salt = make_salt()

    h = hashlib.sha256(username + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)


def valid_pw(username, pw, h):
    salt = h.split('|')[1]
    return h == make_pw_hash(username, pw, salt)


class User(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_username(cls, username):
        u = User.all().filter('username = ', username).get()
        return u

    @classmethod
    def register(cls, username, pw, email=None):
        pw_hash = make_pw_hash(username, pw)
        return User(username=username,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, username, pw):
        u = cls.by_username(username)
        if u and valid_pw(username, pw, u.pw_hash):
            return u


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str_global(template, **params)

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
        self.set_secure_cookie('user', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user')
        self.user = uid and User.by_id(int(uid))


class MainPage(Handler):

    def get(self):
        self.render('base.html')


class Signup(Handler):

    def validate(self, value, regex):
        if (value == ''):
            return False

        rx = re.compile(regex)
        check = rx.match(value)

        if (check is None):
            return False
        else:
            return True

    def get(self):
        self.render('signup.html')

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        # Validate username
        valid_username = self.validate(self.username, r"^[a-zA-Z0-9_-]{3,20}$")
        # Validate password
        valid_password = self.validate(self.password, r"^.{3,20}$")
        # Validate email
        if self.request.get('email'):
            valid_email = self.validate(self.email, r"^[\S]+@[\S]+.[\S]+$")
        else:
            valid_email = True

        # Validate verify
        if self.password == self.verify:
            valid_verify = True
        else:
            valid_verify = False

        if (valid_username is False or
            valid_password is False or
            valid_verify is False or
            valid_email is False
            ):

            self.render('signup.html',
                        username=self.username,
                        valid_username=valid_username,
                        valid_password=valid_password,
                        valid_verify=valid_verify,
                        email=self.email,
                        valid_email=valid_email
                        )
        else:
            self.done()

        def done(self, *a, **kw):
            raise NotImplementedError


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_username(self.username)

        if u:
            msg = 'That user already exists.'
            self.render('signup.html', username_dublicate=True)
        else:
            # Create user
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            return self.redirect('/welcome')


class Welcome(Handler):

    def get(self):
        # If user is not logged in
        # To Do: Make this logged-in-check global somehow, like include it in a
        # parent handler
        if self.user:
            self.render('welcome.html', username=self.user.username)
        else:
            return self.redirect('/signup')


class Login(Handler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            return self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(Handler):

    def get(self):
        self.logout()
        return self.redirect('/signup')


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# START Post #
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.ListProperty(str)

    def render(self, template, username, comments):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str_global("post-%s.html" % template,
                                 p=self,
                                 username=username,
                                 comments=comments)

class BlogFront(Handler):

    def get(self):
        if not self.user:
            return self.redirect("/login")

        # Get all posts
        posts = Post.all().order('-created')

        # To Do: How do I assign a value to an exiting object in a collection?
        # This does not seem to work :(
        """
        for idx, post in enumerate(posts):
            if post.author == self.user.username:
        posts[idx].is_owner = True
            else:
        posts[idx].is_owner = False
        """

        self.render('front.html', posts=posts, username=self.user.username)


class PostPage(Handler):

    def get(self, post_id):
        if not self.user:
            return self.redirect("/login")

        # Get post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        post.likes_count = len(post.likes)

        if not post:
            self.error(404)
            return

        # Check if logged in user has already liked this post
        idx = -1
        for liker in post.likes:
            if liker == self.user.username:
                # if so, set check value and break
                idx = post.likes.index(liker)
                break

        if (idx >= 0):
            # User has already liked this post
            post.like = True
        else:
            # User has not yet liked this post
            post.like = False

        # Get comments
        comments = Comment.all().filter('post_id =', post_id).order('-created')
        self.render(
            "permalink.html",
            p=post,
            comments=comments,
            username=self.user.username
            )

class NewPost(Handler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            return self.redirect("login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')

        # Get values
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user.username

        # If values are valid, put in db
        if subject and content:
            p = Post(
                parent=blog_key(),
                subject=subject,
                content=content,
                author=author)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html", subject=subject, content=content, error=error)


class EditPost(Handler):

    def get(self, post_id):
        if not self.user:
            return self.redirect("/login")

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user and (post.author == self.user.username):
            self.render("edit-post.html",
                        content=post.content,
                        subject=post.subject,
                        author=post.author,
                        id=post.key().id())
        else:
            self.redirect("/blog")

    def post(self, post_id):
        if not self.user:
            return self.redirect("/login")

        if not self.user and not (post.author == self.user.username):
            return self.redirect("/blog")

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            # Update post object and update db
            post.subject = subject
            post.content = content
            post.put()

            return self.redirect('/blog/%s' % str(post_id))
        else:
            error = "subject and content, please!"
            self.render(
                "edit-post.html",
                subject=subject,
                content=content,
                error=error)

            
class LikePost(Handler):

    def get(self, post_id):
        if not self.user:
            return self.redirect("/login")

        # Get blog post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        likes = post.likes

        if post.author == self.user.username:
            return self.redirect('/blog/%s' % post.key().id())

        # Check if logged in user has already liked this post
        idx = -1
        for i, liker in enumerate(likes):
            if liker == self.user.username:
                # if so, set check value and break
                idx = i
                break

        if (idx >= 0):
            # Remove from list
            post.likes = likes[:idx] + likes[idx+1:]
        else:
            # Add to list
            post.likes.append(self.user.username)

        # Update
        post.put()

        # Redirect
        return self.redirect('/blog/%s' % post.key().id())


class DeletePost(Handler):

    def get(self, post_id):
        if not self.user:
            return self.redirect("/login")

        # Get blog post
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        likes = post.likes

        if post and post.author == self.user.username:
            # Actual delete
            post.delete()

        # Redirect
        return self.redirect('/blog')
# END Posts #

# START Comments #
class Comment(db.Model):
    content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self, username):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str_global("comment.html", c=self, username=username)


class NewComment(Handler):

    def post(self, post_id):
        if not self.user:
            return self.redirect('/blog')

        # Get values
        content = self.request.get('comment_content')
        author = self.user.username

        if content:
            c = Comment(content=content, author=author, post_id=post_id)
            c.put()
            return self.redirect('/blog/%s' % post_id)
            # See explanation at class DeleteComment ll341
            time.sleep(1)
        else:
            error = "content, please!"
            # To Do: Display error
            return self.redirect('/blog/%s' % post_id)


class DeleteComment(Handler):

    def get(self, comment_id):
        if not self.user:
            return self.redirect("/login")

        # Get blog post comment
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        # If comment does not exist
        if not comment:
            return self.redirect('/blog')

        post_id = comment.post_id

        if comment and comment.author == self.user.username:
            # Actual delete
            comment.delete()

        # After deleting of a comment and subsequent
        # redirection to the blog post, the comment
        # still gets fetched and rendered on the first load.
        # Upon reload the comments list is rendered correctly.
        # Can't find any mistake here, though.
        #
        # Same for NewComment
        #
        # Workaround: Works with an ugly timeout
        time.sleep(1)

        # Redirect
        return self.redirect('/blog/%s' % post_id)


class EditComment(Handler):

    def get(self, comment_id):
        if not self.user:
            return self.reidrect("/login")

        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)

        if self.user and (comment.author == self.user.username):
            self.render("edit-comment.html", c=comment)
        else:
            return self.redirect("/blog")

    def post(self, comment_id):
        if not self.user:
            return self.redirect("/login")

        if not self.user and not (comment.author == self.user.username):
            return self.redirect("/blog")

        # Get content
        content = self.request.get('comment_content')

        if content:
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            # Update post object and update db
            comment.content = content
            comment.put()
            time.sleep(1)

            return self.redirect('/blog/%s' % str(comment.post_id))
        else:
            error = "content, please!"
            self.render("edit-comment.html", c=comment, error=error)
# END Comments #


# [START app]
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/welcome', Welcome),
    ('/blog/?', BlogFront),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost),
    ('/blog/([0-9]+)/edit', EditPost),
    ('/blog/([0-9]+)/like', LikePost),
    ('/blog/([0-9]+)/delete', DeletePost),
    ('/blog/([0-9]+)/comment/create', NewComment),
    ('/blog/comment/([0-9]+)/delete', DeleteComment),
    ('/blog/comment/([0-9]+)/edit', EditComment),
], debug=True)
# [END app]
