# See https://apereo.github.io/cas/4.2.x/protocol/CAS-Protocol-Specification.html
import logging
from xml.etree import ElementTree

import requests

from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.httpexceptions import HTTPFound, HTTPNoContent, HTTPForbidden
from pyramid.security import remember, authenticated_userid, forget

from c2cgeoportal_geoportal.resources import defaultgroupsfinder

log = logging.getLogger(__name__)


def includeme(config):
    config.add_route('login', '/login')
    config.add_view(login, route_name='login')

    config.add_route('cas_login', '/cas/login')
    config.add_view(cas_login, route_name='cas_login')

    config.add_route('cas_logout', '/cas/logout')
    config.add_view(cas_logout, route_name='cas_logout')


def create_authentication(settings):
    timeout = settings.get('authtkt_timeout')
    timeout = None if timeout is None else int(timeout)
    reissue_time = settings.get('reissue_time')
    reissue_time = None if reissue_time is None else int(reissue_time)
    return CASAuthenticationPolicy(
        settings.get('authtkt_secret'),
        callback=defaultgroupsfinder,
        cookie_name=settings.get('authtkt_cookie_name'),
        timeout=timeout, max_age=timeout, reissue_time=reissue_time,
        hashalg='sha512'
    )


class CASAuthenticationPolicy(AuthTktAuthenticationPolicy):
    def authenticated_userid(self, request):
        userid = self.unauthenticated_userid(request)
        log.debug('authenticated_userid: %s' % userid)
        if userid is not None:
            return userid
        else:
            # back from CAS, validate ticket
            ticket = request.params.get('ticket')
            if ticket is not None:
                return _verify_ticket(request, ticket)


def login(request):
    user = request.authenticated_userid
    log.debug('remember %s' % user)
    headers = remember(request, user)
    came_from = request.params.get('came_from', request.referer)
    return HTTPFound(came_from, headers=headers)


def cas_login(request):
    # redirect to CAS login page
    server = request.registry.settings.get('cas').get('server')
    service = request.route_url('login')
    url = requests.compat.urljoin(server, 'login?service=%s' % service)
    return HTTPFound(url)


def cas_logout(request):
    server = request.registry.settings.get('cas').get('server')
    service = request.route_url('login')
    url = requests.compat.urljoin(server, 'logout?service=%s' % service)
    r = requests.get(url)
    log.debug('logged out from CAS server and forget user: %s' % r.ok)
    headers = forget(request)
    came_from = request.params.get('came_from', request.referer)
    return HTTPFound(came_from, headers=headers)


def _verify_ticket(request, ticket):
    server = request.registry.settings.get('cas').get('server')
    params = {
        'ticket': ticket,
        'service': request.route_url('login'),
    }
    url = requests.compat.urljoin(server, 'serviceValidate')
    r = requests.get(url, params=params)
    if r.ok:
        root = ElementTree.fromstring(r.text)
        user = root.find('{http://www.yale.edu/tp/cas}authenticationSuccess/{http://www.yale.edu/tp/cas}user')
        return user.text if user is not None else None
