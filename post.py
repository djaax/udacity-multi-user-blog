#!/usr/bin/env python

# [START imports]
from server import *
# [END imports]

"""

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
        "" "
        for idx, post in enumerate(posts):
            if post.author == self.user.username:
        posts[idx].is_owner = True
            else:
        posts[idx].is_owner = False
        "" "

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
# END Posts #
"""