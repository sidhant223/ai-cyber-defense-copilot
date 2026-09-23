from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_http_methods

from .models import Comment, Post


def post_list(request):
    posts = Post.objects.all().values("id", "title", "author__username")
    return JsonResponse(list(posts), safe=False)


def post_detail(request, post_id):
    post = get_object_or_404(Post, pk=post_id)
    return JsonResponse({"id": post.id, "title": post.title, "body": post.body})


def post_search(request):
    term = request.GET.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, title FROM blog_post WHERE title LIKE '%%%s%%'" % term
        )
        rows = cursor.fetchall()
    return JsonResponse([{"id": r[0], "title": r[1]} for r in rows], safe=False)


@login_required
@require_http_methods(["POST"])
def post_create(request):
    post = Post.objects.create(
        title=request.POST["title"],
        body=request.POST["body"],
        author=request.user,
    )
    return JsonResponse({"id": post.id}, status=201)


@login_required
@require_http_methods(["POST"])
def post_edit(request, post_id):
    post = get_object_or_404(Post, pk=post_id)
    post.title = request.POST["title"]
    post.body = request.POST["body"]
    post.save()
    return JsonResponse({"status": "updated"})


@require_http_methods(["POST"])
def comment_create(request, post_id):
    comment = Comment.objects.create(
        post_id=post_id,
        body=request.POST["body"],
        author_name=request.POST.get("name", "anonymous"),
    )
    return JsonResponse({"id": comment.id}, status=201)


@login_required
def moderate_delete_comment(request, comment_id):
    Comment.objects.filter(pk=comment_id).delete()
    return JsonResponse({"status": "deleted"})
