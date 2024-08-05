import io
import base64
import logging
import requests
import mimetypes

from io import BytesIO
from ftplib import FTP, error_perm

from django.conf import settings
from django.http import JsonResponse, FileResponse, Http404

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from .serializers import FileUploadPathSerializer, FileUploadSerializer

logger = logging.getLogger(__name__)


class ProcessFromFTPPath(APIView):
    def post(self, request):
        serializer = FileUploadPathSerializer(data=request.data)

        if serializer.is_valid():
            file_path = serializer.validated_data['file_path']
            tags = serializer.validated_data.get('tags', [])

            get_tags_url = f'{settings.BASE_REQUEST_URL}api/tags/'
            post_document_url = f'{settings.BASE_REQUEST_URL}api/documents/post_document/'

            encoded_credentials = base64.b64encode(
                settings.REQUEST_CREDENTIALS.encode('utf-8')).decode('utf-8')

            headers = {'Authorization': f'Basic {encoded_credentials}'}

            try:
                tag_ids = []
                if tags:
                    response = requests.get(get_tags_url, headers=headers)
                    
                    if response.status_code == status.HTTP_200_OK:
                        tag_response = response.json()['results']
                        
                        for tag in tag_response:
                            if tag['name'] in tags:
                                tag_ids.append(tag['id'])
                    else:
                        return Response({'error': 'Failed to fetch tags'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                if tags and not tag_ids:
                    return Response({'error': 'No tags found with given name.'}, status=status.HTTP_404_NOT_FOUND)
                
                ftp = FTP(settings.FTP_SERVER)
                ftp.login(settings.FTP_USER, settings.FTP_PASSWORD)

                ftp.cwd(file_path)
                files = ftp.nlst()
                results = []

                for file_name in files:
                    file_buffer = io.BytesIO()
                    ftp.retrbinary(f"RETR {file_name}", file_buffer.write)
                    file_buffer.seek(0)

                    files_payload = {
                        'document': (file_name, file_buffer, 'application/octet-stream')
                    }

                    payload = {'tags': tag_ids}
                    response = requests.post(post_document_url, 
                                             files=files_payload, 
                                             data=payload, 
                                             headers=headers)

                    if response.status_code == status.HTTP_200_OK:
                        results.append(response.json())
                    else:
                        results.append({'error': response.json()})

                ftp.quit()

                return Response({'results': results})
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProcessSingleFileFromFTP(APIView):
    def post(self, request):
        serializer = FileUploadPathSerializer(data=request.data)

        if serializer.is_valid():
            file_path = serializer.validated_data['file_path']
            tags = serializer.validated_data.get('tags', [])

            get_tags_url = f'{settings.BASE_REQUEST_URL}api/tags/'
            post_document_url = f'{settings.BASE_REQUEST_URL}api/documents/post_document/'

            encoded_credentials = base64.b64encode(
                settings.REQUEST_CREDENTIALS.encode('utf-8')).decode('utf-8')
            headers = {'Authorization': f'Basic {encoded_credentials}'}

            try:
                tag_ids = []
                if tags:
                    response = requests.get(get_tags_url, headers=headers)
                    if response.status_code == status.HTTP_200_OK:
                        tag_response = response.json()['results']
                        
                        for tag in tag_response:
                            if tag['name'] in tags:
                                tag_ids.append(tag['id'])
                    else:
                        return Response({'error': 'Failed to fetch tags'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                if tags and not tag_ids:
                    return Response({'error': 'No tags found with given name.'}, status=status.HTTP_404_NOT_FOUND)
                
                ftp = FTP(settings.FTP_SERVER)
                ftp.login(settings.FTP_USER, settings.FTP_PASSWORD)

                path_parts = file_path.split('/')

                file_name = path_parts[-1]
                directory_path = '/'.join(path_parts[:-1])

                if directory_path:
                    ftp.cwd(directory_path)

                file_buffer = io.BytesIO()
                ftp.retrbinary(f"RETR {file_name}", file_buffer.write)
                file_buffer.seek(0)

                files_payload = {
                    'document': (file_name, file_buffer, 'application/octet-stream')
                }

                payload = {
                    'tags': tag_ids
                }

                response = requests.post(post_document_url, 
                                         files=files_payload, 
                                         data=payload, 
                                         headers=headers)

                ftp.quit()

                if response.status_code == status.HTTP_200_OK:
                    return Response(response.json())
                else:
                    return Response({'error': response.json()}, status=response.status_code)

            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FileUploadFTPView(APIView):
    def post(self, request):
        serializer = FileUploadSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            user_file = serializer.validated_data['file']
            file_name = user_file.name

            try:
                ftp = FTP(settings.FTP_SERVER)
                ftp.login(settings.FTP_USER, settings.FTP_PASSWORD)

                ftp.storbinary(f'STOR {file_name}', user_file.file)

                full_path = f"/home/vsftpd/myuser/{file_name}"
                ftp.quit()

                return Response({'message': 'File uploaded successfully', 'full_path': full_path}, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f'FTP error: {str(e)}')
                return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ListFilesOnFTP(APIView):
    def get(self, request):
        try:
            ftp = FTP(settings.FTP_SERVER)
            ftp.login(settings.FTP_USER, settings.FTP_PASSWORD)
            files = ftp.nlst()
            ftp.quit()
            return JsonResponse({'files': files})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)


class RetrieveFileFromFTP(APIView):
    def get(self, request, file_path):
        try:
            ftp = FTP()
            ftp.connect(settings.FTP_HOST, settings.FTP_PORT)
            ftp.login(settings.FTP_USERNAME, settings.FTP_PASSWORD)
            # Change directory to desired location
            ftp.cwd(settings.FTP_UPLOAD_DIR)

            # Prepare a BytesIO buffer to hold the file data
            buffer = BytesIO()
            ftp.retrbinary(f'RETR {file_path}', buffer.write)
            buffer.seek(0)  # Move to the beginning of the buffer

            ftp.quit()

            return FileResponse(buffer, as_attachment=True, filename=file_path)
        except Exception as e:
            raise Http404(f"File not found: {e}")


class RetrieveAndOpenFileFromFTP(APIView):
    def get(self, request, file_name):
        base_path = '/home/vsftpd/myuser/'
        full_path = f"{base_path}{file_name}"

        if '..' in file_name or file_name.startswith('/'):
            raise Http404("Invalid file name.")

        try:
            ftp = FTP()
            ftp.connect(settings.FTP_SERVER, settings.FTP_PORT)
            ftp.login(settings.FTP_USER, settings.FTP_PASSWORD)

            buffer = BytesIO()
            try:
                ftp.retrbinary(f'RETR {file_name}', buffer.write)
                buffer.seek(0)  # Move to the beginning of the buffer

                mime_type, _ = mimetypes.guess_type(file_name)
                if mime_type is None:
                    mime_type = 'application/octet-stream'

                response = FileResponse(
                    buffer, as_attachment=True, filename=file_name, content_type=mime_type
                )

                logger.info(f"Successfully retrieved file: {full_path}")
                return response
            except error_perm as e:
                logger.error(f"FTP permission error: {e}")
                raise Http404("File not found or access denied.")
            except Exception as e:
                logger.error(f"Error retrieving file from FTP: {e}")
                raise Http404("Error retrieving file.")
            finally:
                ftp.quit()
        except Exception as e:
            logger.error(f"Error connecting to FTP server: {e}")
            raise Http404(f"File not found: {e}")
