ifdef VARS_FILE
VARS_FILES += ${VARS_FILE} vars_nondocker.yaml vars.yaml
else
VARS_FILE = vars_nondocker.yaml
VARS_FILES += ${VARS_FILE} vars.yaml
endif

# The hostname use in the browser to open the application
APACHE_VHOST ?= demo_geomapfish
TILECLOUD_CHAIN ?= FALSE

# Deploy branch
DEPLOY_BRANCH_DIR ?= /var/www/vhosts/$(APACHE_VHOST)/private/deploybranch
GIT_REMOTE_URL ?= git@github.com:camptocamp/demo.git
DEPLOY_BRANCH_BASE_URL ?= $(VISIBLE_PROTOCOL)://$(VISIBLE_HOST)
DEPLOY_BRANCH_MAKEFILE ?= demo.mk

include nondocker-override.mk