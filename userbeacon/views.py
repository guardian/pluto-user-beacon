from django.views.generic import View
from rest_framework.views import APIView
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .jwt_auth_backend import JwtRestAuth
from django.contrib.auth.models import User
from django.conf import settings
import logging
import json
logger = logging.getLogger(__name__)


class HealthCheckView(APIView):
    """
    very simple healthcheck that responds with a 200 if the app is up and running
    """
    renderer_classes = (JSONRenderer, )

    def get(self, request):
        return Response({"status":"ok"})


class BeaconView(APIView):
    """
    this view responds to an incoming request from the frontend to say a user has just logged in
    it includes the bearer token used for the login
    we validate the bearer token and if it's valid check whether the given user exists in VS
    if not, we create it
    """
    renderer_classes = (JSONRenderer, )
    authentication_classes = (JwtRestAuth, )
    permission_classes = (IsAuthenticated, )

    def create_vs_user(self, user_record, comm):
        """
        ask VS to create a user for the given login
        :param user_record: User object
        :param comm: VSCommunicator instance to perform the request
        :return: a Django response to return directly to the client
        """
        from .vscommunicator import VSCommunicator, HttpError, HttpTimeoutError

        if user_record.is_superuser:
            raw_group_list = settings.ADMIN_USER_VSGROUPS
        else:
            raw_group_list = settings.REGULAR_USER_VSGROUPS

        user_group_list = [{"groupName": groupname, "role": False} for groupname in raw_group_list]

        request_data = {
            "userName": user_record.username,
            "realName": user_record.first_name + " " + user_record.last_name,
            "groupList": {
                "group": user_group_list,
            },
        }
        comm.do_post("/API/user", request_data)

    def set_import_acl(self, user_name, comm):
        """
        ensure that media imported by this user is read-write to other users in the group
        :param comm: VSCommunicator instance to perform the request
        :return:
        """
        for group_name in settings.REGULAR_USER_VSGROUPS:
            writeurl = "/API/import/access/group/{0}?permission=WRITE".format(group_name)
            comm.do_put(writeurl, run_as=user_name)

    def put(self, request):
        """
        the main endpoint. Expects an empty PUT request with valid bearer-token authentication
        If we get this far, then the authentication class has already validated the token and
        populated the request.user object
        :return: either a 200 django response or a 500 indicating a VS error. No client feedback is given if the user
        is actually created or not, for that see the logs
        """
        from .vscommunicator import VSCommunicator, HttpError, HttpTimeoutError

        if request is None:
            logger.error("No request data? Something is badly wrong.")
            return Response({"status":"server_error","detail":"no request data"}, status=500)

        logger.info("Received beacon for login of {0}".format(request.user))
        if not isinstance(request.user, User):
            logger.warning("the provided user is not a User object, something weird is going on")
            return Response({"status":"ok"})

        comm = VSCommunicator()
        user_create_required = True
        try:
            comm.do_get("/API/user/{0}".format(self.request.user.username))
            logger.info("User {0} already exists in Vidispine".format(self.request.user.username))
            #if we get here, then we got a 200 response and the user exists, happy times.
            user_create_required = False
        except HttpTimeoutError as e:
            logger.error("Vidispine seems down! Timed out checking user: {0}".format(e))
            return Response({"status":"error","detail":"Could not communicate with Vidispine"},status=500)
        except HttpError as e:
            if e.response_code==404:
                #user does not exist, so we should create it
                logger.info("User {0} does not exist in Vidispine, creating".format(self.request.user.username))
                user_create_required = True
            else:
                logger.error("Could not communicate with Vidispine: {0}".format(e))
                logger.error("Error response was {0}".format(e.response_body))
                return Response({"status":"error","detail":"Could not communicate with Vidispine"},status=500)

        if user_create_required:
            try:
                self.create_vs_user(self.request.user, comm)
            except HttpTimeoutError as e:
                logger.error("Vidispine seems down! Timed out checking user: {0}".format(e))
                return Response({"status":"error","detail":"Could not communicate with Vidispine"},status=500)
            except HttpError as e:
                logger.error("Could not communicate with Vidispine: {0}".format(e))
                logger.error("Error response was {0}".format(e.response_body))
                return Response({"status":"error","detail":"Could not communicate with Vidispine"},status=500)
            except json.decoder.JSONDecodeError:    #does not matter if the body fails to parse, we are not interested (spec says it is empty)
                pass

        try:
            self.set_import_acl(self.request.user.username, comm)
        except HttpTimeoutError as e:
            logger.error("Vidispine seems down! Timed out checking user: {0}".format(e))
            return Response({"status":"error","detail":"Could not communicate with Vidispine"},status=500)
        except HttpError as e:
            logger.error("Could not communicate with Vidispine: {0}".format(e))
            logger.error("Error response was {0}".format(e.response_body))
            return Response({"status":"error","detail":"Could not communicate with Vidispine"},status=500)
        except json.decoder.JSONDecodeError:    #does not matter if the body fails to parse, we are not interested (spec says it is empty)
            pass
        return Response({"status":"ok"})