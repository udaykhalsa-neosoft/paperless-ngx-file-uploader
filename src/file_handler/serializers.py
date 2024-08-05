from rest_framework import serializers


class FileUploadPathSerializer(serializers.Serializer):
    file_path = serializers.CharField()
    tags = serializers.ListField(required=False)

class FileUploadSerializer(serializers.Serializer):
    file = serializers.FileField()
    # upload_path = serializers.CharField(null=True, blank=True)
