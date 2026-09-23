from django.contrib import admin
from django.urls import path

from blog import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("posts/", views.post_list),
    path("posts/search/", views.post_search),
    path("posts/<int:post_id>/", views.post_detail),
    path("posts/new/", views.post_create),
    path("posts/<int:post_id>/edit/", views.post_edit),
    path("posts/<int:post_id>/comments/", views.comment_create),
    path("moderate/comments/<int:comment_id>/delete/", views.moderate_delete_comment),
]
