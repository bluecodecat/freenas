# Copyright 2013 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################
import json
import logging
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.translation import ugettext as _

from freenasUI.freeadmin.views import JsonResp
from freenasUI.jails import forms, models
from freenasUI.jails.utils import get_jails_index
from freenasUI.common.sipcalc import sipcalc_type
from freenasUI.common.warden import Warden
from freenasUI.middleware.client import client
from freenasUI.middleware.exceptions import MiddlewareError
from freenasUI.middleware.notifier import notifier

log = logging.getLogger("jails.views")


def jails_home(request):
    default_iface = notifier().get_default_interface()

    try:
        jailsconf = models.JailsConfiguration.objects.order_by("-id")[0]

    except IndexError:
        jailsconf = models.JailsConfiguration.objects.create()

    if not jailsconf.jc_collectionurl:
        jailsconf.jc_collectionurl = get_jails_index()
        jailsconf.save()

    return render(request, 'jails/index.html', {
        'focus_form': request.GET.get('tab', 'jails.View'),
        'jailsconf': jailsconf,
        'default_iface': default_iface
    })


def jailsconfiguration(request):

    try:
        jc = models.JailsConfiguration.objects.order_by("-id")[0]

    except IndexError:
        jc = models.JailsConfiguration.objects.create()

    if request.method == "POST":
        form = forms.JailsConfigurationForm(request.POST, instance=jc)
        if form.is_valid():
            form.save()
            return JsonResp(
                request,
                message="Jails Configuration successfully updated."
            )
        else:
            return JsonResp(request, form=form)
    else:
        form = forms.JailsConfigurationForm(instance=jc)

    return render(request, 'jails/jailsconfiguration.html', {
        'form': form,
        'inline': True
    })


def jail_edit(request, id):

    jail = models.Jails.objects.get(id=id)

    if request.method == 'POST':
        form = forms.JailsEditForm(request.POST, instance=jail)
        if form.is_valid():
            form.save()
            return JsonResp(
                request,
                message=_("Jail successfully edited.")
            )
    else:
        form = forms.JailsEditForm(instance=jail)

    return render(request, 'jails/edit.html', {
        'form': form
    })


def jail_storage_add(request, jail_id):

    jail = models.Jails.objects.get(id=jail_id)

    if request.method == 'POST':
        form = forms.JailMountPointForm(request.POST, jail=jail)
        if form.is_valid():
            form.save()
            return JsonResp(
                request,
                message=_("Storage successfully added.")
            )
    else:
        form = forms.JailMountPointForm(jail=jail)

    return render(request, 'jails/storage.html', {
        'form': form,
    })


def jail_start(request, id):

    jail = models.Jails.objects.get(id=id)

    if request.method == 'POST':
        try:
            notifier().reload("http")  # Jail IP reflects nginx plugins.conf
            with client as c:
                c.call('notifier.warden', 'start', None, {'jail': jail.jail_host})
            return JsonResp(
                request,
                message=_("Jail successfully started.")
            )

        except Exception as e:
            return JsonResp(request, error=True, message=repr(e))

    else:
        return render(request, "jails/start.html", {
            'name': jail.jail_host
        })


def jail_stop(request, id):

    jail = models.Jails.objects.get(id=id)

    if request.method == 'POST':
        try:
            Warden().stop(jail=jail.jail_host)
            return JsonResp(
                request,
                message=_("Jail successfully stopped.")
            )

        except Exception as e:
            return JsonResp(request, error=True, message=repr(e))

    else:
        return render(request, "jails/stop.html", {
            'name': jail.jail_host
        })


def jail_restart(request, id):

    jail = models.Jails.objects.get(id=id)

    if request.method == 'POST':
        try:
            with client as c:
                c.call('notifier.warden', 'stop', None, {'jail': jail.jail_host})
                c.call('notifier.warden', 'start', None, {'jail': jail.jail_host})
            return JsonResp(
                request,
                message=_("Jail successfully restarted.")
            )

        except Exception as e:
            return JsonResp(request, error=True, message=repr(e))

    else:
        return render(request, "jails/restart.html", {
            'name': jail.jail_host
        })


def jail_delete(request, id):

    jail = models.Jails.objects.get(id=id)

    if request.method == 'POST':
        try:
            jail.delete()
            return JsonResp(
                request,
                message=_("Jail successfully deleted.")
            )
        except MiddlewareError:
            raise
        except Exception as e:
            return JsonResp(request, error=True, message=repr(e))

    else:
        return render(request, "jails/delete.html", {
            'name': jail.jail_host
        })


def jail_info(request, id):
    data = {}

    for f in models.Jails._meta.get_fields():
        if f.many_to_one or f.related_model:
            continue
        data[f.name] = None

    try:
        jail = models.Jails.objects.get(pk=id)
        for k in list(data.keys()):
            data[k] = getattr(jail, k)

    except:
        pass

    content = json.dumps(data)
    return HttpResponse(content, content_type='application/json')


def jail_template_info(request, name):
    data = {}

    for f in models.JailTemplate._meta.get_fields():
        if f.many_to_one or f.related_model:
            continue
        data[f.name] = None

    if name:
        jt = models.JailTemplate.objects.filter(jt_name=name)
        if jt.exists():
            jt = jt[0]
            for k in list(data.keys()):
                data[k] = getattr(jt, k)
            data['jt_instances'] = jt.jt_instances

    content = json.dumps(data)
    return HttpResponse(content, content_type='application/json')


def jail_template_create(request):
    if request.method == "POST":
        form = forms.JailTemplateCreateForm(request.POST)
        if form.is_valid():
            form.save()
            return JsonResp(
                request,
                message=_("Jail Template successfully created.")
            )

    else:
        form = forms.JailTemplateCreateForm()

    return render(request, "jails/jail_template_create.html", {
        'form': form
    })


def jail_template_edit(request, id):
    jt = models.JailTemplate.objects.get(pk=id)

    if request.method == "POST":
        form = forms.JailTemplateEditForm(request.POST, instance=jt)
        if form.is_valid():
            form.save()
            return JsonResp(
                request,
                message=_("Jail Template successfully edited.")
            )

    else:
        form = forms.JailTemplateEditForm(instance=jt)

    return render(request, "jails/jail_template_edit.html", {
        'form': form
    })


def jail_template_delete(request, id):
    jt = models.JailTemplate.objects.get(pk=id)

    if request.method == 'POST':
        try:
            jt.delete()
            return JsonResp(
                request,
                message=_("Jail template successfully deleted.")
            )
        except MiddlewareError:
            raise
        except Exception as e:
            return JsonResp(request, error=True, message=repr(e))

    else:
        return render(request, "jails/delete.html", {
            'name': jt.jt_name
        })


def jailsconfiguration_info(request):
    data = {}

    for f in models.JailsConfiguration._meta.get_fields():
        if f.many_to_one or f.related_model:
            continue
        data[f.name] = None

    try:
        jc = models.JailsConfiguration.objects.all()[0]

    except:
        pass

    for k in list(data.keys()):
        data[k] = getattr(jc, k)

    content = json.dumps(data)
    return HttpResponse(content, content_type='application/json')


def jailsconfiguration_network_info(request):
    data = {
        'jc_ipv4_network': None,
        'jc_ipv4_network_start': None,
        'jc_ipv4_network_end': None,
        'jc_ipv6_network': None,
        'jc_ipv6_network_start': None,
        'jc_ipv6_network_end': None,
    }

    ipv4_iface = notifier().get_default_ipv4_interface()
    if ipv4_iface:
        ipv4_st = sipcalc_type(iface=ipv4_iface)
        if ipv4_st.is_ipv4():
            data['jc_ipv4_network'] = "%s/%d" % (
                ipv4_st.network_address,
                ipv4_st.network_mask_bits
            )
            data['jc_ipv4_network_start'] = str(
                ipv4_st.usable_range[0]).split('/')[0]
            data['jc_ipv4_network_end'] = str(
                ipv4_st.usable_range[1]).split('/')[0]

    ipv6_iface = notifier().get_default_ipv6_interface()
    try:
        iface_info = notifier().get_interface_info(ipv6_iface)
        if iface_info['ipv6'] is None:
            raise Exception

        ipv6_addr = iface_info['ipv6'][0]['inet6']
        if ipv6_addr is None:
            raise Exception

        ipv6_prefix = iface_info['ipv6'][0]['prefixlen']
        if ipv6_prefix is None:
            raise Exception

        ipv6_st = sipcalc_type("%s/%s" % (ipv6_addr, ipv6_prefix))
        if not ipv6_st:
            raise Exception

        if not ipv6_st.is_ipv6():
            raise Exception

        ipv6_st2 = sipcalc_type(ipv6_st.subnet_prefix_masked)
        if not ipv6_st:
            raise Exception

        if not ipv6_st.is_ipv6():
            raise Exception

        data['jc_ipv6_network'] = "%s/%d" % (
            ipv6_st2.compressed_address,
            ipv6_st.prefix_length
        )

        ipv6_st2 = sipcalc_type(ipv6_st.network_range[0])
        data['jc_ipv6_network_start'] = str(
            ipv6_st2.compressed_address).split('/')[0]

        ipv6_st2 = sipcalc_type(ipv6_st.network_range[1])
        data['jc_ipv6_network_end'] = str(
            ipv6_st2.compressed_address).split('/')[0]

    except:
        pass

    content = json.dumps(data)
    return HttpResponse(content, content_type='application/json')
