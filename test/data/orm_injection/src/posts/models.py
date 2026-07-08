from django.db import models


class Author(models.Model):
    name = models.CharField(max_length=100)  # type: ignore[var-annotated]
    email = models.EmailField()  # type: ignore[var-annotated]


class Category(models.Model):
    name = models.CharField(max_length=100)  # type: ignore[var-annotated]


class Post(models.Model):
    title = models.CharField(max_length=200)  # type: ignore[var-annotated]
    content = models.TextField()  # type: ignore[var-annotated]
    creation_date = models.DateTimeField()  # type: ignore[var-annotated]
    author = models.ForeignKey(Author, on_delete=models.CASCADE)  # type: ignore[var-annotated]
    category = models.ForeignKey(Category, on_delete=models.CASCADE)  # type: ignore[var-annotated]
