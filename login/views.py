from django.http import HttpResponse
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
import logging
import requests
import json
import datetime
import pytz
from datetime import datetime as dt
import ldap3

# from django_auth_ldap3.backends import LDAPBackend
from django_python3_ldap.auth import LDAPBackend
from django.conf import settings
from django.contrib import messages
from django.http import FileResponse
import os
import mimetypes
import csv
from django.core.exceptions import ValidationError


# Create your views here.


def Login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password1 = request.POST["password"]

        try:
            # Try to authenticate against LDAP server
            server = ldap3.Server("")  # url to ldap server with port number
            conn = ldap3.Connection(
                server,
                user=settings.AUTH_LDAP_BIND_DN,
                password=settings.AUTH_LDAP_BIND_PASSWORD,
                auto_bind=True,
            )
            conn.search(
                search_base=settings.AUTH_LDAP_USER_SEARCH_BASE,
                search_filter="(&(objectClass=user)(sAMAccountName={0}))".format(
                    username
                ),
                attributes=ldap3.ALL_ATTRIBUTES,  # Retrieve all attributes
            )

            if len(conn.response) == 0:
                messages.error(request, "User not found in LDAP")
            else:
                user_dn = conn.response[0]["dn"]
                backend = LDAPBackend()
                user = backend.authenticate(
                    request, username=username, password=password1
                )
                print(user)
                if user is not None:
                    login(request, user)
                    return render(request, "Dashboard.html")
                else:
                    messages.error(request, "Invalid username or password.")

            conn.unbind()

        except ldap3.core.exceptions.LDAPBindError as e:
            messages.error(request, "LDAP bind failed: %s" % e)
        except (
            ldap3.core.exceptions.LDAPSocketOpenError,
            ldap3.core.exceptions.LDAPSocketReceiveError,
        ) as e:
            messages.error(request, "LDAP connection failed: %s" % e)

    return render(request, "login.html")


def authentication_token():
    ZABBIX_API_URL = "http://172.29.57.33/zabbix/api_jsonrpc.php"
    obj = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {"username": "", "password": ""},
        "id": 1,
    }
    r = requests.post(ZABBIX_API_URL, json=obj, timeout=10)
    AUTHTOKEN = r.json()["result"]
    return ZABBIX_API_URL, AUTHTOKEN


def get_user_id_from_username(username):
    values = authentication_token()
    token = values[1]
    url = values[0]
    payload = {
        "jsonrpc": "2.0",
        "method": "user.get",
        "params": {
            "filter": {
                "roleid": "1",
                "username": username,
            },
            "output": ["userid"],
        },
        "auth": token,
        "id": 1,
    }
    response = requests.post(url, json=payload, timeout=10)
    if response.status_code == 200:
        json_response = response.json()
        if len(json_response["result"]) > 0:
            print(json.dumps(json_response, indent=4))
            userid = response.json()["result"][0]["userid"]
            print(userid)
        else:
            return
    else:
        print(f"Error: {response.status_code}")
    return userid


def host_name_to_id(host_name):
    values = authentication_token()
    token = values[1]
    url = values[0]
    payload = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {"filter": {"host": [host_name]}},
        "auth": token,
        "id": 1,
    }
    response = requests.post(url, json=payload, timeout=10)
    if response.status_code == 200:
        json_response = response.json()
        if len(json_response["result"]) > 0:
            print(json.dumps(json_response, indent=4))
            host_id = response.json()["result"][0]["hostid"]
        else:
            return
    else:
        print(f"Error: {response.status_code}")
    return host_id


def get_maintenance_id_from_host_id(host_id):
    values = authentication_token()
    token = values[1]
    url = values[0]
    payload = payload = {
        "jsonrpc": "2.0",
        "method": "maintenance.get",
        "params": {
            "output": "maintenanceid",
            "hostids": host_id,
        },
        "auth": token,
        "id": 1,
    }
    response = requests.post(url, json=payload, timeout=10)
    if response.status_code == 200:
        json_response = response.json()
        if len(json_response["result"]) > 0:
            print(json.dumps(json_response, indent=4))
            maintenance_id = response.json()["result"][0]["maintenanceid"]
        else:
            return
        print(json.dumps(json_response, indent=4))
        maintenance_id = response.json()["result"][0]["maintenanceid"]
    else:
        print(f"Error: {response.status_code}")
    return maintenance_id


def localtime_to_timestamp_converter(t):
    # datetime string to be converted
    datetime_str = t

    # convert datetime string to datetime object
    datetime_obj = datetime.datetime.strptime(datetime_str, "%Y-%m-%dT%H:%M")

    # convert datetime object to Unix timestamp
    unix_timestamp = datetime_obj.timestamp()
    time_stamp = int(unix_timestamp)

    return time_stamp


def period_calculater(dt2_str, dt1_str):
    # define the format for datetime objects
    fmt = "%Y-%m-%dT%H:%M"

    # convert datetime strings to datetime objects
    dt1 = dt.strptime(dt1_str, fmt)
    dt2 = dt.strptime(dt2_str, fmt)

    # calculate time difference in seconds
    diff_seconds = (dt1 - dt2).total_seconds()

    return diff_seconds


def current_date_time():
    # datetime object containing current date and time
    now = dt.now()

    print("now =", now)

    # dd/mm/YY H:M:S
    dt_string = now.strftime("%d/%m/%YT%H:%M:%S")
    return dt_string


def Login(request):
    return render(request, "login.html")


def dashboard(request):
    return render(request, "Dashboard.html")


def add_host_to_monitoring(request):
    return render(request, "Add_host_to_monitoring.html")


def remove_host_from_monitoring(request):
    return render(request, "Remove_host_from_monitoring.html")


def add_host_to_maintenance(request):
    return render(request, "Add_host_to_maintenance.html")


def remove_host_from_maintenance(request):
    return render(request, "Remove_host_from_maintenance.html")


def add_user_to_console(request):
    return render(request, "Add_user_to_console.html")


def remove_user_from_console(request):
    return render(request, "Remove_user_from_console.html")


def host_bulk_import(request):
    return render(request, "Bulk_import.html")


def add_host_to_monitoring_form(request):
    if request.method == "POST":
        host_name = request.POST.get("host_name")
        host_ip = request.POST.get("host_ip")
        host_group = request.POST.get("host_group")
        template = request.POST.get("template")
        type_monitoring = request.POST.get("type_monitoring")
        description = request.POST.get("description")
        values = authentication_token()
        token = values[1]
        url = values[0]
        if (
            (type_monitoring == "1")
            or (type_monitoring == "3")
            or (type_monitoring == "4")
        ):
            payload = {
                "jsonrpc": "2.0",
                "method": "host.create",
                "params": {
                    "host": host_name,
                    "interfaces": [
                        {
                            "type": type_monitoring,
                            "main": 1,
                            "useip": 1,
                            "ip": host_ip,
                            "dns": "",
                            "port": "10050",
                        }
                    ],
                    "groups": [{"groupid": host_group}],
                    "templates": [{"templateid": template}],
                    "description": description,
                },
                "auth": token,
                "id": 1,
            }

            # for SNMP
        else:
            payload = {
                "jsonrpc": "2.0",
                "method": "host.create",
                "params": {
                    "host": host_name,
                    "interfaces": [
                        {
                            "type": 2,
                            "main": 1,
                            "useip": 1,
                            "ip": host_ip,
                            "dns": "",
                            "port": "161",
                            "details": {
                                "version": 2,
                                "bulk": 0,
                                "community": "$SNMP_COMMUNIT",
                            },
                        }
                    ],
                    "groups": [{"groupid": host_group}],
                    "templates": [{"templateid": template}],
                    "description": description,
                },
                "auth": token,
                "id": 1,
            }
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            json_response = response.json()
            if "error" in json_response:
                print("Error code: {}".format(json_response["error"]["code"]))
                messages.error(
                    request, ("Error : {}".format(json_response["error"]["data"]))
                )
                val = combine(request)
                return val
            host_id = response.json()["result"]["hostids"]

        else:
            messages.success(request, f"Error: {response.status_code}")
        messages.success(request, f"host added with host id {host_id}")
        val = combine(request)
        return val
    else:
        return HttpResponse("Error")


def remove_host_from_monitoring_form(request):
    if request.method == "POST":
        host_name = request.POST.get("host_name")
        # Retrive Host_id from host name
        host_id = host_name_to_id(host_name)
        # if host not found
        if host_id is None:
            messages.error(request, "Error : Host not found")
            return render(request, "remove_host_from_monitoring.html")
        ticket_number = request.POST.get("ticket_number")
        requested_by = request.POST.get("requested_by")
        description = "TN : " + ticket_number + "\n" + "Requested by : " + requested_by
        values = authentication_token()
        token = values[1]
        url = values[0]
        payload = {
            "jsonrpc": "2.0",
            "method": "host.update",
            "params": {"hostid": host_id, "status": 1, "description": description},
            "auth": token,
            "id": 1,
        }
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            json_response = response.json()
            print(json.dumps(json_response, indent=4))
        else:
            print(f"Error: {response.status_code}")
        messages.success(request, "Host removed from monitoring successfully")
        return render(request, "remove_host_from_monitoring.html")
    else:
        return HttpResponse("Error")


def add_host_to_maintenance_form(request):
    if request.method == "POST":
        maintenance_name = request.POST.get("maintenance_name")
        # Appending Timestamp in Maintenance name
        maintenance_name = maintenance_name + " " + current_date_time()
        # Retriving host id from host name
        hostid = host_name_to_id(request.POST.get("host_name"))
        # in case host not found, response from host_name_to_id() will be none
        if hostid is None:
            messages.error(request, "Error : Host not found")
            return render(request, "add_host_to_maintenance.html")
        active_since_0 = request.POST.get("active_since")
        # Changing active_since format to payload supported format which is unix timestamp
        active_since = localtime_to_timestamp_converter(active_since_0)
        active_till_0 = request.POST.get("active_till")
        # Changing active_till format to payload supported format which is unix timestamp
        active_till = localtime_to_timestamp_converter(active_till_0)
        # period is deffernce between active_since and active_till
        period = period_calculater(active_since_0, active_till_0)
        ticket_number = request.POST.get("ticket_number")
        requested_by = request.POST.get("requested_by")
        description = "TN : " + ticket_number + "\n" + "Requested by : " + requested_by
        values = authentication_token()
        token = values[1]
        url = values[0]
        payload = {
            "jsonrpc": "2.0",
            "method": "maintenance.create",
            "params": {
                "name": maintenance_name,
                "active_since": active_since,
                "active_till": active_till,
                "tags_evaltype": 0,
                "hostids": [hostid],
                "timeperiods": [
                    {
                        "period": period,
                        "timeperiod_type": 0,
                        "start_time": active_since,
                    }
                ],
                "description": description,
                "tags": [
                    {"tag": "service", "operator": "0", "value": "mysqld"},
                    {"tag": "error", "operator": "2", "value": ""},
                ],
            },
            "auth": token,
            "id": 1,
        }
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            json_response = response.json()
            if "error" in json_response:
                print("Error code: {}".format(json_response["error"]["code"]))
                messages.error(
                    request, ("Error : {}".format(json_response["error"]["data"]))
                )
                return render(request, "add_host_to_maintenance.html")
            print(json.dumps(json_response, indent=4))
        else:
            print(f"Error: {response.status_code}")
        messages.success(request, "Maintenance created successfully")
        return render(request, "add_host_to_maintenance.html")
    else:
        return HttpResponse("Error")


def remove_host_from_maintenance_form(request):
    if request.method == "POST":
        host_id = host_name_to_id(request.POST.get("host_name"))
        if host_id is None:
            messages.error(request, "Error : Host not found")
            return render(request, "remove_host_from_maintenance.html")
        maintenance_id = get_maintenance_id_from_host_id(host_id)
        if maintenance_id is None:
            messages.error(request, "Error : Maintenance not found")
            return render(request, "remove_host_from_maintenance.html")

        # ticket_number = request.POST.get("ticket_number")
        # requested_by = request.POST.get("requested_by")
        # description = request.POST.get("description")
        values = authentication_token()
        token = values[1]
        url = values[0]
        payload = {
            "jsonrpc": "2.0",
            "method": "maintenance.delete",
            "params": [maintenance_id],
            "auth": token,
            "id": 1,
        }
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            json_response = response.json()

            print(json.dumps(json_response, indent=4))
        else:
            print(f"Error: {response.status_code}")
        messages.success(request, "Host removed from maintenance")
        return render(request, "remove_host_from_maintenance.html")
    else:
        return HttpResponse("Error")


def add_user_to_console_form(request):
    if request.method == "POST":
        user_name = request.POST.get("user_name")
        name = request.POST.get("name")
        surname = request.POST.get("surname")
        password = request.POST.get("password")
        values = authentication_token()
        token = values[1]
        url = values[0]
        payload = {
            "jsonrpc": "2.0",
            "method": "user.create",
            "params": {
                "username": user_name,
                "name": name,
                "surname": surname,
                "passwd": password,
                "roleid": "1",
                "usrgrps": [{"usrgrpid": "15"}],
            },
            "auth": token,
            "id": 1,
        }
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            json_response = response.json()
            print(json.dumps(json_response, indent=4))
        else:
            print(f"Error: {response.status_code}")
        messages.success(
            request, (f"Welcome on zabbix monitoring, have fun ! {name}  {surname}")
        )
        return render(request, "add_user_to_console.html")
    else:
        return HttpResponse("Error")


def remove_user_from_console_form(request):
    if request.method == "POST":
        username = request.POST.get("user_name")
        userid = get_user_id_from_username(username)
        if userid is None:
            messages.error(request, "Error : User not found")
            return render(request, "remove_user_from_console.html")
        values = authentication_token()
        token = values[1]
        url = values[0]
        payload = {
            "jsonrpc": "2.0",
            "method": "user.update",
            "params": {
                "userid": userid,
                "usrgrps": [{"usrgrpid": "9"}],  # differ for every zabbix server
                # "usrgrps_clear": 1
            },
            "auth": token,
            "id": 1,
        }

        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            json_response = response.json()
            print(json.dumps(json_response, indent=4))
        else:
            print(f"Error: {response.status_code}")
        messages.success(request, "User successfully deleted")
        return render(request, "remove_user_from_console.html")
    else:
        return HttpResponse("Error")


def Host_group_Dict():  # as the name suggest Host_group_Dict aquire and return all Host_group list
    values = authentication_token()
    token = values[1]
    url = values[0]
    payload1 = {
        "jsonrpc": "2.0",
        "method": "hostgroup.get",
        "params": {"output": ["groupid", "name"]},
        "auth": token,
        "id": 2,
    }
    rpc_response = requests.post(url, json=payload1, timeout=10)

    hosts = json.loads(rpc_response.content)["result"]

    # Create a list of choices for the HTML select field
    chs = [(host["groupid"], host["name"]) for host in hosts]

    # Pass the choices to the template using a context variable
    context1 = {"chs": chs}
    return context1


def Template_dict():  # as the name suggest template dict aquire and return all template list
    values = authentication_token()
    token = values[1]
    url = values[0]
    payload2 = {
        "jsonrpc": "2.0",
        "method": "template.get",
        "params": {"output": ["templateid", "host"]},
        "auth": token,
        "id": 2,
    }

    rpc_response = requests.post(url, json=payload2, timeout=10)

    hosts = json.loads(rpc_response.content)["result"]

    # Create a list of choices for the HTML select field
    choices = [(host["templateid"], host["host"]) for host in hosts]

    # Pass the choices to the template using a context variable
    context2 = {"choices": choices}
    return context2


def combine(
    request,
):  # for fetching conetext and rendering add host to monitoring page seletion fields
    context1 = Host_group_Dict()
    context2 = Template_dict()

    context = {**context1, **context2}  # combining two dictionaries into one
    return render(request, "Add_host_to_monitoring.html", context)


def download_static_file(request, file_path):
    # Construct the absolute path to the static file
    absolute_path = os.path.join(settings.STATIC_ROOT, file_path)

    # Open the file and create a FileResponse object
    file = open(absolute_path, "rb")
    response = FileResponse(file)

    # Set the appropriate content type for the file
    content_type, _ = mimetypes.guess_type(absolute_path)
    response["Content-Type"] = content_type

    # Set the Content-Disposition header to force download
    response["Content-Disposition"] = 'attachment; filename="{0}"'.format(
        os.path.basename(file_path)
    )

    return response


def bulk_import_host_form(request):
    if request.method == "POST":
        values = authentication_token()  # for Authentication Token
        token = values[1]
        url = values[0]

        file = request.FILES["file"]
        # for converting uploaded file into a readable format
        reader = csv.reader(file.read().decode("utf-8").splitlines())
        next(reader)

        # aquire Host groups and split dictionary from json format
        host_groups = Host_group_Dict()
        host_group_dict = host_groups.items()
        host_group_dict = dict(host_group_dict)["chs"]

        templates = (
            Template_dict()
        )  # aquire template and split dictionary from json format
        template_dict = templates.items()
        template_dict = dict(template_dict)["choices"]

        for row in reader:  # iterating over each rows next to header
            for (
                host_group_id,
                host_group,
            ) in host_group_dict:  # for finding host group id via name
                if host_group == row[2]:
                    host_group = host_group_id
                    break

            host_name = row[0]
            host_ip = row[1]

            for (
                template_id,
                template_name,
            ) in template_dict:  # for finding template id via name
                if template_name == row[3]:
                    template = template_id
                    break

            if (row[4] == "Agent") or (row[4] == "IPMI") or (row[4] == "JMX"):
                type_monitoring = 1
            if row[4] == "SNMP":
                type_monitoring = 2
            if type_monitoring == 1:
                payload = {
                    "jsonrpc": "2.0",
                    "method": "host.create",
                    "params": {
                        "host": host_name,
                        "interfaces": [
                            {
                                "type": type_monitoring,
                                "main": 1,
                                "useip": 1,
                                "ip": host_ip,
                                "dns": "",
                                "port": "10050",
                            }
                        ],
                        "groups": [{"groupid": host_group}],
                        "templates": [{"templateid": template}],
                    },
                    "auth": token,
                    "id": 1,
                }

                # for SNMP
            else:
                payload = {
                    "jsonrpc": "2.0",
                    "method": "host.create",
                    "params": {
                        "host": host_name,
                        "interfaces": [
                            {
                                "type": 2,
                                "main": 1,
                                "useip": 1,
                                "ip": host_ip,
                                "dns": "",
                                "port": "161",
                                "details": {
                                    "version": 2,
                                    "bulk": 0,
                                    "community": "$SNMP_COMMUNIT",
                                },
                            }
                        ],
                        "groups": [{"groupid": host_group}],
                        "templates": [{"templateid": template}],
                    },
                    "auth": token,
                    "id": 1,
                }
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                json_response = response.json()
                if "error" in json_response:
                    print("Error code: {}".format(json_response["error"]["code"]))
                    messages.error(
                        request, ("Error : {}".format(json_response["error"]["data"]))
                    )

        if response.status_code == 200 and "error" not in json_response:
            messages.success(request, "host added")
    return render(request, "Bulk_import.html")
