INSTANCE_ID = test

MOBILE = FALSE
TILECLOUD_CHAIN = FALSE

REQUIREMENTS += -e /home/travis/build/camptocamp/c2cgeoportal
PRINT_OUTPUT = /var/lib/tomcat7/webapps

PIP_CMD = /home/travis/build/camptocamp/c2cgeoportal/travis/pip.sh

TOMCAT_SERVICE_COMMAND =
APACHE_CONF_DIR = /etc/apache2/sites-enabled/

# TODO remove it ...
testgeomapfish/static-ngeo/build/locale/%/testgeomapfish.json:
	mkdir -p $(dir $@)
	touch $@

include testgeomapfish.mk
