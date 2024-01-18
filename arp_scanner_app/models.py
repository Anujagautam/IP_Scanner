from django.db import models


class ScanResult(models.Model):
    ip = models.CharField(max_length=15)
