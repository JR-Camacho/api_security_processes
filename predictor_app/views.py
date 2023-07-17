from rest_framework import viewsets
from rest_framework import status
from rest_framework.response import Response

from .services.make_prediction import make_email_prediction, make_url_phishing_prediction, make_url_malware_prediction, make_url_spam_prediction
from .utils.process_url import extract_url_info

# Create your views here.


class SpamDetectorViewSet(viewsets.ViewSet):

    def create(self, request):
        email_text = request.data.get("email_text")
        email_file = request.FILES.get("email_file")

        if email_file:
            email_content = email_file.read()
            is_file = True
        else:
            email_content = email_text
            is_file = False

        try:
            prediction = make_email_prediction(email_content, is_file=is_file)
            return Response({"prediction": prediction[0]})
        except Exception as e:
            error_message = str(e)
            return Response({"error": error_message}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class MaliciousUrlDetectorViewSet(viewsets.ViewSet):

    def create(self, request):
        url = request.data.get("url")

        try:
            phishing_prediction = make_url_phishing_prediction(url)
            malware_prediction = make_url_malware_prediction(url)
            spam_prediction = make_url_spam_prediction(url)
            return Response({
                "is_phishing": phishing_prediction[0],
                "is_malware": malware_prediction[0],
                "is_spam": spam_prediction[0],
                "url_info": extract_url_info(url),
            })
        except Exception as e:
            error_message = str(e)
            return Response({"error": error_message}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
