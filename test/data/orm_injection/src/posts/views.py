from django.db.models import QuerySet
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from .models import Post


def post_list(request: HttpRequest) -> HttpResponse:
    filters = {}
    for key, values in request.GET.items():
        if values:
            if isinstance(values, list):
                filters[key] = values[0]
            else:
                filters[key] = values

        if "year" in key and key in filters:
            filters[key] = int(filters[key])

    posts: QuerySet[Post] = Post.objects.filter(**filters)

    return render(
        request,
        "posts.html",
        {
            "posts": posts,
        },
    )
