import requests
from django.conf import settings
import logging
import time

logger = logging.getLogger(__name__)


class HttpTimeoutError(Exception):
    pass

class HttpError(Exception):
    def __init__(self, target_url, response_code, response_body, response_headers):
        self.target_url = target_url
        self.response_code = response_code
        self.response_body = response_body
        self.response_headers = response_headers

    def __str__(self):
        return u"{0} error accessing {1}".format(self.response_code, self.target_url)


class VSCommunicator(object):
    """
    simple class to handle communication with VS
    """
    def __init__(self):
        self.retry_wait = 5 #in seconds
        self.max_retries = 10

    def do_get(self, urlpath):
        """
        perform a GET request to VS, with retries. Raises on error, for details see `do_generic`
        :param urlpath:
        :return:
        """
        return self.do_generic(urlpath, lambda full_url:
                               requests.get(full_url,auth=(settings.VIDISPINE_ADMIN_USER,settings.VIDISPINE_ADMIN_PASSWORD),
                                                      headers={
                                                          "Accept": "application/json"
                                                      }))

    def do_post(self, urlpath, body_content):
        """
        perform a POST request, with retries. Raises on error, for details see `do_generic`
        :param urlpath:
        :param body_content:
        :return:
        """
        return self.do_generic(urlpath, lambda full_url:
                               requests.post(full_url, json=body_content,
                                             auth=(settings.VIDISPINE_ADMIN_USER, settings.VIDISPINE_ADMIN_PASSWORD),
                                             headers={"Accept":"application/json"}))

    def do_generic(self, urlpath, requestlambda, attempt=0):
        """
        error-catching wrapper for an http request. Recursively retries if a timeout is received
        :param urlpath: API path to hit, with a leading /. /API is not necessary, it's added automatically if it does not exist.
        :param requestlambda: lambda function that performs the actual request. This is passed the full_url as a parameter
                            and is expected to return a Requests response object
        :param attempt: attempt counter, don't set this when calling externally
        :return: the json content returned as a dictionary.
            If the request errors then an HttpError is raised, if it succeeds but the content won't parse as json then
            a ParseException is raised
        """
        if urlpath.startswith("/API"):
            api_url_path = urlpath
        else:
            api_url_path = "/API" + urlpath

        full_url = settings.VIDISPINE_BASE_URL + api_url_path

        result = requestlambda(full_url)
        if result.status_code==503 or result.status_code==502 or result.status_code==501:
            if attempt>=self.max_retries:
                logger.error("Vidispine is still not available, giving up")
                raise HttpTimeoutError("Timed out accessing {0}".format(full_url))
            logger.warning("Vidispine not available on attempt {0}, received {1}".format(attempt, result.status_code))
            time.sleep(self.retry_wait)
            return self.do_generic(urlpath, requestlambda, attempt+1)
        elif result.status_code!=200 and result.status_code!=201:
            raise HttpError(full_url, result.status_code, result.text, result.headers)
        else:
            return result.json()
