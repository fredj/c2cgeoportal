# -*- coding: utf-8 -*-

# Copyright (c) 2013-2014, Camptocamp SA
# All rights reserved.

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:

# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.

# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of the FreeBSD Project.


from unittest import TestCase
from nose.plugins.attrib import attr

import transaction
import os
import json
from geoalchemy import WKTSpatialElement
from pyramid import testing
from owslib.wms import WebMapService

from c2cgeoportal.tests.functional import (  # noqa
    tear_down_common as tearDownModule,
    set_up_common as setUpModule,
    mapserv_url, host, create_dummy_request)

import logging
log = logging.getLogger(__name__)


@attr(functional=True)
class TestEntryView(TestCase):

    def setUp(self):  # noqa
        from c2cgeoportal.models import DBSession, User, Role, LayerV1, \
            RestrictionArea, Theme, LayerGroup, Functionality, Interface

        role1 = Role(name=u'__test_role1')
        user1 = User(username=u'__test_user1', password=u'__test_user1', role=role1)

        role2 = Role(name=u'__test_role2', extent=WKTSpatialElement(
            "POLYGON((1 2, 1 4, 3 4, 3 2, 1 2))", srid=21781
        ))
        user2 = User(username=u'__test_user2', password=u'__test_user2', role=role2)

        main = Interface(name=u'main')
        mobile = Interface(name=u'mobile')

        public_layer = LayerV1(name=u'__test_public_layer', order=40, public=True)
        public_layer.is_checked = False
        public_layer.interfaces = [main, mobile]

        private_layer = LayerV1(name=u'__test_private_layer', order=40, public=False)
        private_layer.geo_table = 'a_schema.a_geo_table'
        private_layer.interfaces = [main, mobile]

        layer_in_group = LayerV1(name=u'__test_layer_in_group')
        layer_in_group.interfaces = [main, mobile]
        layer_group = LayerGroup(name=u'__test_layer_group')
        layer_group.children = [layer_in_group]

        layer_wmsgroup = LayerV1(name=u'test_wmsfeaturesgroup')
        layer_wmsgroup.is_checked = False
        layer_wmsgroup.interfaces = [main, mobile]

        theme = Theme(name=u'__test_theme')
        theme.children = [
            public_layer, private_layer, layer_group, layer_wmsgroup
        ]
        theme.interfaces = [main]

        functionality1 = Functionality(name=u'test_name', value=u'test_value_1')
        functionality2 = Functionality(name=u'test_name', value=u'test_value_2')
        theme.functionalities = [functionality1, functionality2]

        poly = "POLYGON((-100 0, -100 20, 100 20, 100 0, -100 0))"

        area = WKTSpatialElement(poly, srid=21781)
        RestrictionArea(
            name=u'__test_ra1', description=u'', layers=[private_layer],
            roles=[role1], area=area
        )

        area = WKTSpatialElement(poly, srid=21781)
        RestrictionArea(
            name=u'__test_ra2', description=u'', layers=[private_layer],
            roles=[role2], area=area, readwrite=True
        )

        DBSession.add_all([user1, user2, public_layer, private_layer])

        transaction.commit()

    def tearDown(self):  # noqa
        testing.tearDown()

        from c2cgeoportal.models import DBSession, User, Role, LayerV1, \
            RestrictionArea, Theme, LayerGroup, Interface

        DBSession.query(User).filter(User.username == '__test_user1').delete()
        DBSession.query(User).filter(User.username == '__test_user2').delete()

        ra = DBSession.query(RestrictionArea).filter(
            RestrictionArea.name == '__test_ra1'
        ).one()
        ra.roles = []
        DBSession.delete(ra)
        ra = DBSession.query(RestrictionArea).filter(
            RestrictionArea.name == '__test_ra2'
        ).one()
        ra.roles = []
        DBSession.delete(ra)

        DBSession.query(Role).filter(Role.name == '__test_role1').delete()
        DBSession.query(Role).filter(Role.name == '__test_role2').delete()

        for t in DBSession.query(Theme).filter(Theme.name == '__test_theme').all():
            DBSession.delete(t)
        for layergroup in DBSession.query(LayerGroup).all():
            DBSession.delete(layergroup)  # pragma: nocover
        for layer in DBSession.query(LayerV1).all():
            DBSession.delete(layer)  # pragma: nocover
        DBSession.query(Interface).filter(
            Interface.name == 'main'
        ).delete()

        transaction.commit()

    #
    # login/logout tests
    #

    @attr(login=True)
    def test_login(self):
        from c2cgeoportal.views.entry import Entry

        request = self._create_request_obj(params={
            'login': u'__test_user1',
            'password': u'__test_user1',
            'came_from': "/came_from",
        })
        response = Entry(request).login()
        self.assertEquals(response.status_int, 302)
        self.assertEquals(response.headers['Location'], "/came_from")

        request = self._create_request_obj(params={
            'login': u'__test_user1',
            'password': u'__test_user1',
        })
        response = Entry(request).login()
        self.assertEquals(response.status_int, 200)
        self.assertEquals(response.body, 'true')

        request = self._create_request_obj(params={
            'login': u'__test_user1',
            'password': u'bad password',
        })
        response = Entry(request).login()
        self.assertEquals(response.status_int, 401)

    @attr(logout_no_auth=True)
    def test_logout_no_auth(self):
        from c2cgeoportal.views.entry import Entry

        request = self._create_request_obj(path='/', params={
            'came_from': '/came_from'
        })
        entry = Entry(request)
        response = entry.logout()
        self.assertEquals(response.status_int, 404)

    @attr(logout=True)
    def test_logout(self):
        from c2cgeoportal.models import DBSession, User
        from c2cgeoportal.views.entry import Entry

        request = self._create_request_obj(path='/')
        request.user = DBSession.query(User).filter_by(
            username=u'__test_user1'
        ).one()
        entry = Entry(request)
        response = entry.logout()
        self.assertEquals(response.status_int, 200)
        self.assertEquals(response.body, 'true')

        request = self._create_request_obj(path='/')
        request.route_url = lambda url: '/dummy/route/url'
        request.user = DBSession.query(User).filter_by(
            username=u'__test_user1'
        ).one()
        entry = Entry(request)
        response = entry.logout()
        self.assertEquals(response.status_int, 200)
        self.assertEquals(response.body, 'true')

    #
    # viewer view tests
    #

    def _create_request_obj(self, username=None, params={}, **kwargs):
        from c2cgeoportal.models import DBSession, User

        request = create_dummy_request(**kwargs)
        request.static_url = lambda url: '/dummy/static/url'
        request.route_url = lambda url, **kwargs: \
            request.registry.settings['mapserv_url']
        request.params = params

        if username is not None:
            request.user = DBSession.query(User) \
                .filter_by(username=username).one()

        return request

    def _create_entry_obj(self, **kwargs):
        from c2cgeoportal.views.entry import Entry

        return Entry(self._create_request_obj(**kwargs))

    @attr(index_no_auth=True)
    def test_index_no_auth(self):
        entry = self._create_entry_obj()
        response = entry.get_cgxp_viewer_vars()
        assert '__test_public_layer' in response['themes']
        assert '__test_private_layer' not in response['themes']

    @attr(index_auth_no_edit_permission=True)
    def test_index_auth_no_edit_permission(self):
        import json

        entry = self._create_entry_obj(username=u'__test_user1')
        response = entry.get_cgxp_viewer_vars()

        themes = json.loads(response['themes'])
        self.assertEqual(len(themes), 1)

        layers = themes[0]['children']
        self.assertEqual(len(layers), 4)

        self.assertEqual([
            'editable' in layer
            for layer in themes[0]['children']
            if layer['name'] == 'test_wmsfeaturesgroup'
        ], [False])

        self.assertEqual([
            'editable' in layer
            for layer in themes[0]['children']
            if layer['name'] == '__test_private_layer'
        ], [False])

        self.assertEqual([
            'editable' in layer
            for layer in themes[0]['children']
            if layer['name'] == '__test_public_layer'
        ], [False])

    @attr(index_auth_edit_permission=True)
    def test_index_auth_edit_permission(self):
        import json

        entry = self._create_entry_obj(username=u'__test_user2')
        response = entry.get_cgxp_viewer_vars()

        self.assertEqual(
            set(json.loads(response['serverError'])),
            set([
                "The layer __test_private_layer is not defined in WMS capabilities",
                "The layer __test_public_layer is not defined in WMS capabilities",
                "The layer __test_layer_in_group is not defined in WMS capabilities"
            ])
        )

        themes = json.loads(response['themes'])
        self.assertEqual(len(themes), 1)

        layers = themes[0]['children']
        self.assertEqual(len(layers), 4)

        self.assertEqual([
            'editable' in layer
            for layer in themes[0]['children']
            if layer['name'] == 'test_wmsfeaturesgroup'
        ], [False])

        self.assertEqual([
            'editable' in layer
            for layer in themes[0]['children']
            if layer['name'] == '__test_private_layer'
        ], [True])

        self.assertEqual([
            'editable' in layer
            for layer in themes[0]['children']
            if layer['name'] == '__test_public_layer'
        ], [False])

    @attr(mobileconfig_no_auth_no_theme=True)
    def test_mobileconfig_no_auth_no_theme(self):
        entry = self._create_entry_obj()
        response = entry.mobileconfig()

        self.assertEqual(response['themes'], [])

    @attr(mobileconfig_no_auth_theme=True)
    def test_mobileconfig_no_auth_theme(self):
        entry = self._create_entry_obj(params={'theme': u'__test_theme'})
        response = entry.mobileconfig()

        self.assertEqual(
            [t['name'] for t in response['themes']],
            ['__test_theme']
        )
        theme = response['themes'][0]
        self.assertEqual(
            [l['name'] for l in theme['allLayers']],
            [u'__test_layer_in_group', u'__test_public_layer', u'test_wmsfeaturesgroup']
        )

        self.assertEqual(theme['layers'], '__test_layer_in_group')

        info = response['info']
        self.assertEqual(
            info,
            {"username": ""}
        )

    @attr(mobileconfig_no_auth_default_theme=True)
    def test_mobileconfig_no_auth_default_theme(self):
        entry = self._create_entry_obj()
        entry.request.registry.settings['functionalities'] = {
            'anonymous': {
                'mobile_default_theme': u'__test_theme'
            }
        }
        response = entry.mobileconfig()

        theme = response['themes'][0]
        layers = theme['allLayers']
        self.assertEqual(len(layers), 3)

    @attr(mobileconfig_wmsgroup=True)
    def test_mobileconfig_wmsgroup(self):
        entry = self._create_entry_obj(params={'theme': u'__test_theme'})
        response = entry.mobileconfig()

        theme = response['themes'][0]
        layers = theme['allLayers']
        self.assertEqual(
            layers,
            [{
                "name": u"__test_layer_in_group"
            }, {
                "name": u"__test_public_layer"
            }, {
                "name": u"test_wmsfeaturesgroup",
                'minResolutionHint': 1.76,
                'maxResolutionHint': 8.82,
                'childLayers': [{
                    'name': 'test_wmsfeatures',
                    'minResolutionHint': 1.76,
                    'maxResolutionHint': 8.82,
                }]
            }]
        )

    @attr(mobileconfig_auth_theme=True)
    def test_mobileconfig_auth_theme(self):
        entry = self._create_entry_obj(
            params={'theme': u'__test_theme'}, username=u'__test_user1')
        response = entry.mobileconfig()

        theme = response['themes'][0]
        layers = theme['allLayers']

        self.assertEqual(set([
            layer['name'] for layer in layers
        ]), set([
            u'__test_layer_in_group', u'__test_public_layer',
            u'__test_private_layer', u'test_wmsfeaturesgroup'
        ]))

        visible_layers = set(theme['layers'].split(','))
        self.assertEqual(
            visible_layers,
            set([u'__test_layer_in_group', u'__test_private_layer'])

        )
        info = response['info']
        self.assertEqual(
            info,
            {"username": "__test_user1"}
        )

    @attr(theme=True)
    def test_theme(self):
        from c2cgeoportal.models import DBSession, User
        from c2cgeoportal.views.entry import Entry
        request = self._create_request_obj()
        entry = Entry(request)

        # unautenticated
        themes = entry.themes()
        self.assertEquals(len(themes), 1)
        layers = [l['name'] for l in themes[0]['children']]
        self.assertTrue('__test_public_layer' in layers)
        self.assertFalse('__test_private_layer' in layers)

        # autenticated on parent
        request.user = DBSession.query(User).filter_by(username=u'__test_user1').one()
        themes = entry.themes()
        self.assertEquals(len(themes), 1)
        layers = [l['name'] for l in themes[0]['children']]
        self.assertTrue('__test_public_layer' in layers)
        self.assertTrue('__test_private_layer' in layers)

        # autenticated
        request.params = {}
        request.user = DBSession.query(User).filter_by(username=u'__test_user1').one()
        themes = entry.themes()
        self.assertEquals(len(themes), 1)
        layers = [l['name'] for l in themes[0]['children']]
        self.assertTrue('__test_public_layer' in layers)
        self.assertTrue('__test_private_layer' in layers)

        # mapfile error
        request.params = {}
        request.registry.settings['mapserv_url'] = mapserv_url + '?map=not_a_mapfile'
        log.info(request.registry.settings['mapserv_url'])
        from c2cgeoportal import caching
        caching.invalidate_region()
        log.info(type(request.registry.settings['mapserv_url']))
        themes, errors = entry._themes(None)
        self.assertEquals(len(themes), 0)
        self.assertEquals(len(errors), 1)

    @attr(wfs_types=True)
    def test_wfs_types(self):
        from c2cgeoportal.views.entry import Entry

        request = self._create_request_obj()
        request.registry.settings.update({
            'external_mapserv_url': request.registry.settings['mapserv_url'],
        })
        entry = Entry(request)

        response = entry.get_cgxp_viewer_vars()
        self.assertEquals(
            set(json.loads(response['serverError'])),
            set([
                "The layer __test_public_layer is not defined in WMS capabilities",
                "The layer __test_layer_in_group is not defined in WMS capabilities"
            ])
        )

        result = '["testpoint_unprotected", "testpoint_protected", ' \
            '"testpoint_protected_query_with_collect", ' \
            '"testpoint_substitution", "testpoint_column_restriction", ' \
            '"test_wmsfeatures", "test_wmstime", "test_wmstime2"]'
        self.assertEquals(response['WFSTypes'], result)
        self.assertEquals(response['externalWFSTypes'], result)

    @attr(permalink_themes=True)
    def test_permalink_themes(self):
        from c2cgeoportal.views.entry import Entry
        request = self._create_request_obj()
        request.registry.settings['external_mapserv_url'] = \
            request.registry.settings['mapserv_url']
        request.params = {
            'permalink_themes': 'my_themes',
        }
        entry = Entry(request)

        response = entry.get_cgxp_viewer_vars()
        self.assertEquals(response['permalink_themes'], '["my_themes"]')

    @attr(mobile_cache_version=True)
    def test_mobile_cache_version(self):
        from c2cgeoportal.views.entry import Entry

        request = self._create_request_obj()
        request.user = None
        entry = Entry(request)
        request.current_route_url = lambda **kwargs: 'http://example.com/current/view'
        result = entry.mobile()
        self.assertRegexpMatches(result['url_params'], 'cache_version=[0-9a-f]*')
        self.assertRegexpMatches(result['extra_params'], 'cache_version=[0-9a-f]*')
        self.assertEquals(result['url_params'], result['extra_params'])

        result2 = entry.mobile()
        self.assertEquals(result2['url_params'], result['url_params'])
        self.assertEquals(result2['extra_params'], result['extra_params'])

    @attr(entry_points=True)
    def test_entry_points(self):
        from c2cgeoportal.views.entry import Entry

        request = self._create_request_obj()
        request.current_route_url = lambda **kwargs: 'http://example.com/current/view'
        mapserv = request.registry.settings['mapserv_url']
        request.registry.settings.update({
            'external_mapserv_url': mapserv,
            'layers_enum': {
                'layer_test': {
                    'attributes': {
                        'label': None
                    }
                }
            }
        })
        entry = Entry(request)
        request.user = None

        result = entry.get_cgxp_index_vars()
        self.assertEquals(
            set(result.keys()),
            set([
                'lang', 'debug', 'extra_params', 'url_params',
                'mobile_url', 'no_redirect'
            ])
        )
        result = entry.get_cgxp_viewer_vars()
        self.assertEquals(set(result.keys()), set([
            'lang', 'tiles_url', 'debug',
            'serverError', 'themes', 'external_themes', 'functionality',
            'WFSTypes', 'externalWFSTypes', 'user', 'queryer_attribute_urls',
            'url_params', 'url_role_params'
        ]))
        self.assertEquals(
            result['queryer_attribute_urls'],
            '{"layer_test": {"label": "%s"}}' % mapserv
        )
        result = entry.mobile()
        self.assertEquals(
            set(result.keys()),
            set(['lang', 'came_from', 'url_params', 'extra_params'])
        )
        result = entry.apijs()
        self.assertEquals(
            set(result.keys()),
            set(['lang', 'debug', 'queryable_layers', 'tiles_url', 'url_params'])
        )
        result = entry.xapijs()
        self.assertEquals(
            set(result.keys()),
            set(['lang', 'debug', 'queryable_layers', 'tiles_url', 'url_params'])
        )
        result = entry.apihelp()
        self.assertEquals(set(result.keys()), set(['lang', 'debug']))
        result = entry.xapihelp()
        self.assertEquals(set(result.keys()), set(['lang', 'debug']))

    @attr(auth_home=True)
    def test_auth_home(self):
        from c2cgeoportal.views.entry import Entry
        from c2cgeoportal.models import User

        request = self._create_request_obj()
        mapserv = request.registry.settings['mapserv_url']
        request.registry.settings.update({
            'external_mapserv_url': mapserv,
            'layers_enum': {
                'layer_test': {
                    'attributes': {
                        'label': None
                    }
                }
            }
        })
        entry = Entry(request)
        request.user = User()
        request.user.username = "a user"

        result = entry.get_cgxp_index_vars()
        self.assertEquals(
            set(result.keys()),
            set([
                'lang', 'debug', 'url_params', 'extra_params', 'mobile_url', 'no_redirect'
            ])
        )
        self.assertEquals(
            set(result['extra_params'].keys()),
            set(['lang', 'user', 'version'])
        )
        self.assertEquals(result['extra_params']['lang'], 'fr')
        self.assertEquals(result['extra_params']['user'], 'a user')
        self.assertRegexpMatches(result['extra_params']['version'], '[0-9a-f]*')

    @attr(entry_points_version=True)
    def test_entry_points_version(self):
        from c2cgeoportal.views.entry import Entry

        mapfile = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'c2cgeoportal_test.map'
        )
        mapserv = "%s?map=%s&" % (mapserv_url, mapfile)

        request = testing.DummyRequest()
        request.user = None
        request.headers['Host'] = host

        request.static_url = lambda url: 'http://example.com/dummy/static/url'
        request.route_url = lambda url, **kwargs: mapserv
        request.registry.settings = {
            'mapserv_url': mapserv,
            'external_mapserv_url': mapserv,
            'default_max_age': 76,
            'layers_enum': {
                'layer_test': {
                    'attributes': {
                        'label': None
                    }
                }
            }
        }
        entry = Entry(request)
        request.user = None

        result = entry.get_cgxp_index_vars()
        self.assertEquals(
            set(result.keys()),
            set([
                'lang', 'debug', 'extra_params', 'url_params',
                'mobile_url', 'no_redirect'
            ])
        )
        self.assertRegexpMatches(result['url_params']['version'], '[0-9a-f]*')
        self.assertRegexpMatches(result['extra_params']['version'], '[0-9a-f]*')

    @attr(entry_points_wfs=True)
    def test_entry_points_wfs(self):
        from c2cgeoportal.views.entry import Entry
        from c2cgeoportal.models import User

        request = self._create_request_obj()
        mapserv = request.registry.settings['mapserv_url']
        request.registry.settings.update({
            'external_mapserv_url': mapserv,
            'layers_enum': {
                'layer_test': {
                    'attributes': {
                        'label': None
                    }
                }
            }
        })
        entry = Entry(request)
        request.user = User()
        request.user.username = "a user"

        result = entry.get_cgxp_index_vars()
        self.assertEquals(
            set(result.keys()),
            set([
                'lang', 'debug', 'extra_params', 'url_params', 'mobile_url', 'no_redirect'
            ])
        )
        self.assertEquals(
            set(result['extra_params'].keys()),
            set(['lang', 'user', 'version']),
        )
        self.assertEquals(result['extra_params']['lang'], 'fr')
        self.assertEquals(result['extra_params']['user'], 'a user')

    @attr(entry_points_wfs_url=True)
    def test_entry_points_wfs_url(self):
        from c2cgeoportal.views.entry import Entry

        request = self._create_request_obj()
        mapserv = request.registry.settings['mapserv_url']
        request.registry.settings.update({
            'external_mapserv_url': mapserv,
            'mapserv_wfs_url': mapserv,
            'external_mapserv_wfs_url': mapserv,
            'layers_enum': {
                'layer_test': {
                    'attributes': {
                        'label': None
                    }
                }
            }
        })

        entry = Entry(request)

        result = entry.get_cgxp_index_vars()
        self.assertEquals(
            set(result.keys()),
            set(
                [
                    'lang', 'debug', 'extra_params', 'url_params',
                    'mobile_url', 'no_redirect'
                ]
            )
        )
        result = entry.get_cgxp_viewer_vars()

    @attr(entry_points_noexternal=True)
    def test_entry_points_noexternal(self):
        from c2cgeoportal.views.entry import Entry

        request = self._create_request_obj()
        request.registry.settings.update({
            'layers_enum': {
                'layer_test': {
                    'attributes': {
                        'label': None
                    }
                }
            }
        })

        entry = Entry(request)

        result = entry.get_cgxp_index_vars()
        self.assertEquals(
            set(result.keys()),
            set(
                [
                    'lang', 'debug', 'extra_params', 'url_params',
                    'mobile_url', 'no_redirect'
                ]
            )
        )
        result = entry.get_cgxp_viewer_vars()

    @attr(permalink_theme=True)
    def test_permalink_theme(self):
        from c2cgeoportal.views.entry import Entry
        request = self._create_request_obj()
        entry = Entry(request)

        request.matchdict = {
            'themes': ['theme'],
        }
        result = entry.get_cgxp_permalinktheme_vars()
        self.assertEquals(
            set(result.keys()),
            set([
                'lang', 'url_params', 'mobile_url', 'permalink_themes',
                'no_redirect', 'extra_params', 'debug'
            ])
        )
        self.assertEquals(
            set(result['extra_params'].keys()),
            set(['lang', 'permalink_themes', 'version'])
        )
        self.assertEquals(result['extra_params']['lang'], 'fr')
        self.assertEquals(result['extra_params']['permalink_themes'], 'theme')
        self.assertRegexpMatches(result['extra_params']['version'], '[0-9a-f]*')
        self.assertEquals(result['permalink_themes'], 'theme')

        request.matchdict = {
            'themes': ['theme1', 'theme2'],
        }
        result = entry.get_cgxp_permalinktheme_vars()
        self.assertEquals(
            set(result.keys()),
            set([
                'lang', 'url_params', 'mobile_url', 'permalink_themes',
                'no_redirect', 'extra_params', 'debug'
            ])
        )
        self.assertEquals(
            set(result['extra_params'].keys()),
            set(['lang', 'permalink_themes', 'version'])
        )
        self.assertEquals(result['extra_params']['lang'], 'fr')
        self.assertEquals(result['extra_params']['permalink_themes'], 'theme1,theme2')
        self.assertRegexpMatches(result['extra_params']['version'], '[0-9a-f]*')
        self.assertEquals(result['permalink_themes'], 'theme1,theme2')

    @attr(layer=True)
    def test_layer(self):
        import httplib2
        from c2cgeoportal.views.entry import Entry
        from c2cgeoportal.models import LayerV1, LayerGroup
        from c2cgeoportal.lib.wmstparsing import TimeInformation

        request = self._create_request_obj()
        request.static_url = lambda name: '/dummy/static/' + name
        request.route_url = lambda name: '/dummy/route/' + name
        request.registry.settings['project'] = 'test_layer'
        entry = Entry(request)

        self.assertEqual(entry._group(LayerGroup(), [], [], None, TimeInformation()), (None, [], False))

        layer = LayerV1()
        layer.id = 20
        layer.name = 'test internal WMS'
        layer.metadata_url = "http://example.com/tiwms"
        layer.is_checked = True
        layer.layer_type = "internal WMS"
        layer.image_type = "image/png"
        layer.style = "my-style"
        layer.kml = "tiwms.kml"
        layer.legend = True
        layer.legend_rule = "rule"
        layer.legend_image = "legend:static/tiwms-legend.png"
        layer.is_legend_expanded = False
        layer.min_resolution = 10
        layer.max_resolution = 1000
        layer.disclaimer = "Camptocamp"
        layer.identifier_attribute_field = "name"
        layer.geo_table = "tiwms"
        layer.public = True
        self.assertEqual(entry._layer(layer, [], None, TimeInformation()), ({
            'id': 20,
            'name': 'test internal WMS',
            'metadataURL': 'http://example.com/tiwms',
            'isChecked': True,
            'icon': '/dummy/route/mapserverproxy?SERVICE=WMS&VERSION=1.1.1&'
            'REQUEST=GetLegendGraphic&LAYER=test internal WMS&FORMAT=image/png&TRANSPARENT=TRUE&RULE=rule',
            'type': u'internal WMS',
            'imageType': 'image/png',
            'style': 'my-style',
            'kml': '/dummy/static/test_layer:static/tiwms.kml',
            'legend': True,
            'legendImage': '/dummy/static/legend:static/tiwms-legend.png',
            'isLegendExpanded': False,
            'minResolutionHint': 10,
            'maxResolutionHint': 1000,
            'disclaimer': 'Camptocamp',
            'identifierAttribute': 'name',
            'public': True,
        }, ['The layer test internal WMS is not defined in WMS capabilities']))

        layer = LayerV1()
        layer.id = 20
        layer.name = 'test external WMS'
        layer.is_checked = False
        layer.icon = "tewms.png"
        layer.layer_type = "external WMS"
        layer.url = "http://example.com"
        layer.image_type = "image/jpeg"
        layer.is_single_tile = True
        layer.legend = False
        layer.is_legend_expanded = False
        layer.min_resolution = 10
        layer.max_resolution = 1000
        layer.public = True
        self.assertEqual(entry._layer(layer, [], None, TimeInformation), ({
            'id': 20,
            'name': 'test external WMS',
            'icon': '/dummy/static/test_layer:static/tewms.png',
            'isChecked': False,
            'type': u'external WMS',
            'url': 'http://example.com',
            'imageType': 'image/jpeg',
            'isSingleTile': True,
            'legend': False,
            'isLegendExpanded': False,
            'minResolutionHint': 10,
            'maxResolutionHint': 1000,
            'public': True,
        }, []))

        layer = LayerV1()
        layer.id = 20
        layer.name = 'test WMTS'
        layer.is_checked = False
        layer.layer_type = "WMTS"
        layer.url = "http://example.com/WMTS-Capabilities.xml"
        layer.style = 'wmts-style'
        layer.dimensions = '{"DATE": "1012"}'
        layer.matrix_set = "swissgrid"
        layer.wms_url = 'http://example.com/'
        layer.wms_layers = 'test'
        layer.legend = False
        layer.is_legend_expanded = False
        layer.min_resolution = 10
        layer.max_resolution = 1000
        layer.public = True
        self.assertEqual(entry._layer(layer, [], None, TimeInformation()), ({
            'id': 20,
            'name': 'test WMTS',
            'isChecked': False,
            'type': 'WMTS',
            'url': 'http://example.com/WMTS-Capabilities.xml',
            'style': 'wmts-style',
            'dimensions': {u'DATE': u'1012'},
            'matrixSet': 'swissgrid',
            'wmsUrl': 'http://example.com/',
            'wmsLayers': 'test',
            'legend': False,
            'isLegendExpanded': False,
            'minResolutionHint': 10,
            'maxResolutionHint': 1000,
            'public': True,
        }, []))

        layer = LayerV1()
        layer.id = 20
        layer.name = 'test WMTS'
        layer.is_checked = False
        layer.layer_type = "WMTS"
        layer.url = "http://example.com/WMTS-Capabilities.xml"
        layer.wms_url = 'http://example.com/'
        layer.legend = False
        layer.is_legend_expanded = False
        layer.min_resolution = 10
        layer.max_resolution = 1000
        layer.public = True
        self.assertEqual(entry._layer(layer, [], None, TimeInformation()), ({
            'id': 20,
            'name': 'test WMTS',
            'isChecked': False,
            'type': 'WMTS',
            'url': 'http://example.com/WMTS-Capabilities.xml',
            'wmsUrl': 'http://example.com/',
            'wmsLayers': 'test WMTS',
            'legend': False,
            'isLegendExpanded': False,
            'minResolutionHint': 10,
            'maxResolutionHint': 1000,
            'public': True,
        }, []))

        layer = LayerV1()
        layer.id = 20
        layer.name = 'test WMTS'
        layer.is_checked = False
        layer.layer_type = "WMTS"
        layer.url = "http://example.com/WMTS-Capabilities.xml"
        layer.wms_layers = 'test'
        layer.legend = False
        layer.is_legend_expanded = False
        layer.min_resolution = 10
        layer.max_resolution = 1000
        layer.public = True
        self.assertEqual(entry._layer(layer, [], None, TimeInformation()), ({
            'id': 20,
            'name': 'test WMTS',
            'isChecked': False,
            'type': 'WMTS',
            'url': 'http://example.com/WMTS-Capabilities.xml',
            'wmsUrl': '/dummy/route/mapserverproxy',
            'wmsLayers': 'test',
            'queryLayers': [],
            'legend': False,
            'isLegendExpanded': False,
            'minResolutionHint': 10,
            'maxResolutionHint': 1000,
            'public': True,
        }, []))

        layer = LayerV1()
        layer.id = 20
        layer.name = 'test no 2D'
        layer.is_checked = False
        layer.layer_type = "no 2D"
        layer.legend = False
        layer.is_legend_expanded = False
        layer.metadata_url = 'http://example.com/wmsfeatures.metadata'
        layer.public = True
        self.assertEqual(entry._layer(layer, [], None, TimeInformation()), ({
            'id': 20,
            'name': u'test no 2D',
            'isChecked': False,
            'type': u'no 2D',
            'legend': False,
            'isLegendExpanded': False,
            'metadataURL': u'http://example.com/wmsfeatures.metadata',
            'public': True,
        }, []))

        curdir = os.path.dirname(os.path.abspath(__file__))
        mapfile = os.path.join(curdir, 'c2cgeoportal_test.map')

        mapfile = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'c2cgeoportal_test.map'
        )
        params = (
            ('map', mapfile),
            ('SERVICE', 'WMS'),
            ('VERSION', '1.1.1'),
            ('REQUEST', 'GetCapabilities'),
        )
        mapserv = "%s?map=%s&" % (mapserv_url, mapfile)
        url = mapserv + '&'.join(['='.join(p) for p in params])
        http = httplib2.Http()
        h = {'Host': host}
        resp, xml = http.request(url, method='GET', headers=h)

        wms = WebMapService(None, xml=xml)
        wms_layers = list(wms.contents)

        layer = LayerV1()
        layer.id = 20
        layer.name = 'test_wmsfeaturesgroup'
        layer.layer_type = "internal WMS"
        layer.image_type = "image/png"
        layer.is_checked = False
        layer.legend = False
        layer.is_legend_expanded = False
        layer.public = True
        self.assertEqual(entry._layer(layer, wms_layers, wms, TimeInformation()), ({
            'id': 20,
            'name': u'test_wmsfeaturesgroup',
            'type': u'internal WMS',
            'isChecked': False,
            'legend': False,
            'isLegendExpanded': False,
            'imageType': u'image/png',
            'minResolutionHint': 1.76,
            'maxResolutionHint': 8.8200000000000003,
            'public': True,
            'queryable': 0,
            'metadataUrls': [{
                'url': 'http://example.com/wmsfeatures.metadata',
                'type': 'TC211',
                'format': 'text/plain',
            }],
            'childLayers': [{
                'name': u'test_wmsfeatures',
                'minResolutionHint': 1.76,
                'maxResolutionHint': 8.8200000000000003,
                'queryable': 1,
            }],
        }, []))

        layer_t1 = LayerV1()
        layer_t1.id = 20
        layer_t1.name = 'test_wmstime'
        layer_t1.layer_type = "internal WMS"
        layer_t1.image_type = "image/png"
        layer_t1.is_checked = False
        layer_t1.legend = False
        layer_t1.is_legend_expanded = False
        layer_t1.public = True
        layer_t1.time_mode = 'single'
        time = TimeInformation()
        entry._layer(layer_t1, wms_layers, wms, time)
        self.assertEqual(time.to_dict(), {
            'resolution': 'year',
            'interval': (1, 0, 0, 0),
            'maxValue': '2010-01-01T00:00:00Z',
            'minValue': '2000-01-01T00:00:00Z',
            'mode': 'single',
        })

        layer_t2 = LayerV1()
        layer_t2.id = 30
        layer_t2.name = 'test_wmstime2'
        layer_t2.layer_type = "internal WMS"
        layer_t2.image_type = "image/png"
        layer_t2.is_checked = False
        layer_t2.legend = False
        layer_t2.is_legend_expanded = False
        layer_t2.public = True
        layer_t2.time_mode = 'single'
        time = TimeInformation()
        entry._layer(layer_t2, wms_layers, wms, time)
        self.assertEqual(time.to_dict(), {
            'resolution': 'year',
            'interval': (1, 0, 0, 0),
            'maxValue': '2020-01-01T00:00:00Z',
            'minValue': '2015-01-01T00:00:00Z',
            'mode': 'single',
        })

        group = LayerGroup()
        group.name = 'time'
        group.children = [layer_t1, layer_t2]
        time = TimeInformation()
        entry._group(group, [layer_t1, layer_t2], wms_layers, wms, time)
        self.assertEqual(time.to_dict(), {
            'resolution': 'year',
            'interval': (1, 0, 0, 0),
            'maxValue': '2020-01-01T00:00:00Z',
            'minValue': '2000-01-01T00:00:00Z',
            'mode': 'single',
        })

        layer = LayerV1()
        layer.id = 20
        layer.name = 'test_wmstimegroup'
        layer.layer_type = "internal WMS"
        layer.image_type = "image/png"
        layer.is_checked = False
        layer.legend = False
        layer.is_legend_expanded = False
        layer.public = True
        layer.time_mode = 'single'
        time = TimeInformation()
        entry._layer(layer, wms_layers, wms, time)
        self.assertEqual(time.to_dict(), {
            'resolution': 'year',
            'interval': (1, 0, 0, 0),
            'maxValue': '2020-01-01T00:00:00Z',
            'minValue': '2000-01-01T00:00:00Z',
            'mode': 'single',
        })

        layer = LayerV1()
        layer.id = 20
        layer.name = 'test WMTS'
        layer.is_checked = False
        layer.layer_type = "WMTS"
        layer.url = "http://example.com/WMTS-Capabilities.xml"
        layer.wms_layers = 'test_wmsfeatures'
        layer.legend = False
        layer.is_legend_expanded = False
        layer.public = True
        self.assertEqual(entry._layer(layer, wms_layers, wms, TimeInformation()), ({
            'id': 20,
            'name': 'test WMTS',
            'isChecked': False,
            'type': 'WMTS',
            'url': 'http://example.com/WMTS-Capabilities.xml',
            'wmsUrl': '/dummy/route/mapserverproxy',
            'wmsLayers': 'test_wmsfeatures',
            'queryLayers': [{
                'name': 'test_wmsfeatures',
                'minResolutionHint': 1.76,
                'maxResolutionHint': 8.8200000000000003
            }],
            'legend': False,
            'isLegendExpanded': False,
            'public': True,
        }, []))

        layer = LayerV1()
        layer.id = 20
        layer.name = 'test WMTS'
        layer.is_checked = False
        layer.layer_type = "WMTS"
        layer.url = "http://example.com/WMTS-Capabilities.xml"
        layer.wms_layers = 'foo'
        layer.query_layers = 'test_wmsfeatures'
        layer.legend = False
        layer.is_legend_expanded = False
        layer.public = True
        self.assertEqual(entry._layer(layer, wms_layers, wms, TimeInformation()), ({
            'id': 20,
            'name': 'test WMTS',
            'isChecked': False,
            'type': 'WMTS',
            'url': 'http://example.com/WMTS-Capabilities.xml',
            'wmsUrl': '/dummy/route/mapserverproxy',
            'wmsLayers': 'foo',
            'queryLayers': [{
                'name': 'test_wmsfeatures',
                'minResolutionHint': 1.76,
                'maxResolutionHint': 8.8200000000000003
            }],
            'legend': False,
            'isLegendExpanded': False,
            'public': True,
        }, []))

        group1 = LayerGroup()
        group1.name = 'block'
        group2 = LayerGroup()
        group2.name = 'node'
        group2.metadata_url = 'http://example.com/group.metadata'
        layer = LayerV1()
        layer.id = 20
        layer.name = 'test layer in group'
        layer.is_checked = False
        layer.layer_type = "internal WMS"
        layer.image_type = "image/png"
        layer.legend = False
        layer.is_legend_expanded = False
        layer.public = True
        group1.children = [group2]
        group2.children = [layer]
        self.assertEqual(entry._group(group1, [layer], [], None, TimeInformation()), ({
            'isExpanded': False,
            'isInternalWMS': True,
            'name': u'block',
            'isBaseLayer': False,
            'children': [{
                'isExpanded': False,
                'isInternalWMS': True,
                'name': u'node',
                'isBaseLayer': False,
                'metadataURL': 'http://example.com/group.metadata',
                'children': [{
                    'name': u'test layer in group',
                    'id': 20,
                    'isChecked': False,
                    'type': u'internal WMS',
                    'legend': False,
                    'isLegendExpanded': False,
                    'imageType': u'image/png',
                    'public': True,
                }]
            }]
        }, ['The layer test layer in group is not defined in WMS capabilities'], False))

        group1 = LayerGroup()
        group1.is_internal_wms = True
        group2 = LayerGroup()
        group2.is_internal_wms = False
        group1.children = [group2]
        _, errors, stop = entry._group(group1, [], [], None, TimeInformation())
        self.assertTrue(len(errors) > 0)
        self.assertFalse(stop)

        group1 = LayerGroup()
        group1.is_internal_wms = False
        group2 = LayerGroup()
        group2.is_internal_wms = True
        group1.children = [group2]
        _, errors, stop = entry._group(group1, [], [], None, TimeInformation())
        self.assertTrue(len(errors) > 0)
        self.assertFalse(stop)

        group = LayerGroup()
        group.is_internal_wms = True
        layer = LayerV1()
        layer.layer_type = 'internal WMS'
        group.children = [layer]
        _, errors, stop = entry._group(group, [layer], [], None, TimeInformation())
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0], "The layer  is not defined in WMS capabilities")
        self.assertFalse(stop)

        group = LayerGroup()
        group.is_internal_wms = True
        layer = LayerV1()
        layer.layer_type = 'external WMS'
        group.children = [layer]
        _, errors, stop = entry._group(group, [layer], [], None, TimeInformation())
        self.assertTrue(len(errors) > 0)
        self.assertFalse(stop)

        group = LayerGroup()
        group.is_internal_wms = True
        layer = LayerV1()
        layer.layer_type = 'WMTS'
        group.children = [layer]
        _, errors, stop = entry._group(group, [layer], [], None, TimeInformation())
        self.assertTrue(len(errors) > 0)
        self.assertFalse(stop)

        group = LayerGroup()
        group.is_internal_wms = True
        layer = LayerV1()
        layer.layer_type = 'no 2D'
        group.children = [layer]
        _, errors, stop = entry._group(group, [layer], [], None, TimeInformation())
        self.assertTrue(len(errors) > 0)
        self.assertFalse(stop)

        group = LayerGroup()
        group.is_internal_wms = False
        layer = LayerV1()
        layer.layer_type = 'internal WMS'
        group.children = [layer]
        _, errors, stop = entry._group(group, [layer], [], None, TimeInformation())
        self.assertTrue(len(errors) > 0)
        self.assertFalse(stop)

        group = LayerGroup()
        group.is_internal_wms = False
        layer = LayerV1()
        layer.layer_type = 'external WMS'
        group.children = [layer]
        _, errors, stop = entry._group(group, [layer], [], None, TimeInformation())
        self.assertEqual(len(errors), 0)
        self.assertFalse(stop)

        group = LayerGroup()
        group.is_internal_wms = False
        layer = LayerV1()
        layer.layer_type = 'WMTS'
        group.children = [layer]
        _, errors, stop = entry._group(group, [layer], [], None, TimeInformation())
        self.assertEqual(len(errors), 0)
        self.assertFalse(stop)

        group = LayerGroup()
        group.is_internal_wms = False
        layer = LayerV1()
        layer.layer_type = 'no 2D'
        group.children = [layer]
        _, errors, stop = entry._group(group, [layer], [], None, TimeInformation())
        self.assertEqual(len(errors), 0)
        self.assertFalse(stop)

    @attr(loginchange=True)
    def test_loginchange(self):
        from c2cgeoportal.views.entry import Entry
        from c2cgeoportal.models import User
        from pyramid.httpexceptions import HTTPBadRequest, HTTPUnauthorized
        try:
            from hashlib import sha1
            sha1  # suppress pyflakes warning
        except ImportError:  # pragma: nocover
            from sha import new as sha1  # noqa

        request = self._create_request_obj()
        entry = Entry(request)
        self.assertRaises(HTTPBadRequest, entry.loginchange)

        request = self._create_request_obj(params={
            'lang': 'en',
            'newPassword': '1234',
            'confirmNewPassword': '12345',
        })
        entry = Entry(request)
        self.assertRaises(HTTPUnauthorized, entry.loginchange)

        request.user = User()
        self.assertEquals(request.user.is_password_changed, False)
        self.assertEquals(request.user._password, unicode(sha1('').hexdigest()))
        self.assertRaises(HTTPBadRequest, entry.loginchange)

        request = self._create_request_obj(params={
            'lang': 'en',
            'newPassword': '1234',
            'confirmNewPassword': '1234'
        })
        request.user = User()
        entry = Entry(request)
        self.assertNotEqual(entry.loginchange(), None)
        self.assertEqual(request.user.is_password_changed, True)
        self.assertEqual(request.user._password, unicode(sha1('1234').hexdigest()))

    @attr(json_extent=True)
    def test_json_extent(self):
        from c2cgeoportal.models import DBSession, Role

        role = DBSession.query(Role).filter(Role.name == '__test_role1').one()
        self.assertEqual(role.json_extent, None)

        role = DBSession.query(Role).filter(Role.name == '__test_role2').one()
        self.assertEqual(role.json_extent, '[1, 2, 3, 4]')
